<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Security\Principal;
use Kongono\Security\PrincipalKind;
use Kongono\Security\SecurityException;
use Kongono\Security\SignedUrl;
use SensitiveParameter;

/**
 * Phishing-resistant, Cross-Device Cryptographic QR Code Login (Discord / WhatsApp style).
 *
 * Security invariants:
 *   - QR payload carries a short-lived, domain-separated HMAC-SHA256 SignedUrl (`kongono:qr-login:v1`)
 *   - Separate 256-bit `poll_secret` stays strictly on the requesting desktop device (NEVER inside the QR)
 *   - 6-digit `verification_code` (`XXX-XXX`) + requester IP/User-Agent defeat remote QRLjacking/phishing
 *   - Atomic one-time claim lock prevents concurrent session-duplication or replay races
 */
final readonly class QrLoginAuth
{
    private SignedUrl $signer;

    public function __construct(
        #[SensitiveParameter]
        string $secretKey,
        private CacheInterface $cache,
        private string $prefix = 'kongono:qr_login:',
    ) {
        $this->signer = new SignedUrl($secretKey, domain: 'kongono:qr-login:v1');
    }

    /**
     * Step 1 (Desktop): Create a short-lived cryptographic QR login challenge and strict-CSP SVG.
     *
     * Store `poll_secret` in the desktop session or HttpOnly cookie — never embed it in the QR code.
     *
     * @return array{
     *     challenge_id: string,
     *     poll_secret: string,
     *     verification_code: string,
     *     qr_payload: string,
     *     qr_svg: string,
     *     expires_at: int
     * }
     */
    public function begin(
        string $approvePath,
        string $requesterIp = '',
        string $requesterUserAgent = '',
        int $ttlSeconds = 180,
        ?int $now = null,
        int $qrSize = 220,
    ): array {
        $ts = $now ?? time();
        $ttl = min(300, max(30, $ttlSeconds));
        $expiresAt = $ts + $ttl;

        $challengeId = bin2hex(random_bytes(16));
        $pollSecret = bin2hex(random_bytes(32));
        $rawCode = str_pad((string) random_int(0, 999_999), 6, '0', STR_PAD_LEFT);
        $verificationCode = substr($rawCode, 0, 3) . '-' . substr($rawCode, 3, 3);

        $qrPayload = $this->signer->temporary($approvePath, $ttl, ['cid' => $challengeId], $ts);
        $qrSvg = QrCodeSvg::render($qrPayload, size: $qrSize, ecLevel: 'M', ariaLabel: 'Sign-in QR code');

        $this->cache->set($this->recordKey($challengeId), [
            'status' => 'pending',
            'poll_secret_hash' => hash('sha256', $pollSecret),
            'verification_code' => $rawCode,
            'requester_ip' => self::cleanMetadata($requesterIp, 64),
            'requester_ua' => self::cleanMetadata($requesterUserAgent, 160),
            'expires_at' => $expiresAt,
            'principal' => null,
        ], $ttl + 10);

        return [
            'challenge_id' => $challengeId,
            'poll_secret' => $pollSecret,
            'verification_code' => $verificationCode,
            'qr_payload' => $qrPayload,
            'qr_svg' => $qrSvg,
            'expires_at' => $expiresAt,
        ];
    }

    /**
     * Step 2 (Authenticated Mobile Device): Verify the scanned QR signature, mark it `scanned`,
     * and return requester metadata + verification code for the user to confirm before approving.
     *
     * @return array{
     *     challenge_id: string,
     *     status: string,
     *     verification_code: string,
     *     requester_ip: string,
     *     requester_user_agent: string,
     *     expires_at: int
     * }
     */
    public function inspect(string $signedQrPayload, ?int $now = null): array
    {
        $ts = $now ?? time();
        $challengeId = $this->verifyAndExtractChallengeId($signedQrPayload, $ts);
        $record = $this->readRecord($challengeId);

        if (null === $record || $ts >= $record['expires_at']) {
            $this->cache->delete($this->recordKey($challengeId));
            throw new SecurityException('QR login challenge is unknown, expired, or already completed.');
        }
        if (!in_array($record['status'], ['pending', 'scanned'], true)) {
            throw new SecurityException('QR login challenge can no longer be scanned.');
        }

        if ('pending' === $record['status']) {
            $record['status'] = 'scanned';
            $this->cache->set($this->recordKey($challengeId), $record, max(5, $record['expires_at'] - $ts + 10));
        }

        $code = $record['verification_code'];
        $formattedCode = strlen($code) === 6 ? substr($code, 0, 3) . '-' . substr($code, 3, 3) : $code;

        return [
            'challenge_id' => $challengeId,
            'status' => $record['status'],
            'verification_code' => $formattedCode,
            'requester_ip' => $record['requester_ip'],
            'requester_user_agent' => $record['requester_ua'],
            'expires_at' => $record['expires_at'],
        ];
    }

    /**
     * Step 3a (Authenticated Mobile Device): Approve the QR sign-in for `$approver`.
     *
     * Pass `$verificationCode` entered/confirmed by the user to enforce QRLjacking phishing resistance.
     */
    public function approve(
        string $signedQrPayload,
        Principal $approver,
        ?string $verificationCode = null,
        ?int $now = null,
    ): void {
        $ts = $now ?? time();
        $challengeId = $this->verifyAndExtractChallengeId($signedQrPayload, $ts);
        $record = $this->readRecord($challengeId);

        if (null === $record || $ts >= $record['expires_at']) {
            $this->cache->delete($this->recordKey($challengeId));
            throw new SecurityException('QR login challenge is unknown, expired, or already completed.');
        }
        if (!in_array($record['status'], ['pending', 'scanned'], true)) {
            throw new SecurityException('QR login challenge has already been resolved.');
        }

        if (null !== $verificationCode) {
            $normalized = preg_replace('/[\s-]+/', '', trim($verificationCode));
            if (!is_string($normalized) || '' === $normalized || !hash_equals($record['verification_code'], $normalized)) {
                throw new SecurityException('QR login verification code mismatch.');
            }
        }

        $claimDeadline = min($record['expires_at'], $ts + 60);
        $record['status'] = 'approved';
        $record['expires_at'] = $claimDeadline;
        $record['principal'] = [
            'id' => $approver->id,
            'kind' => $approver->kind->value,
            'capabilities' => $approver->capabilities,
            'attributes' => $approver->attributes,
        ];

        $this->cache->set($this->recordKey($challengeId), $record, max(5, $claimDeadline - $ts + 10));
    }

    /**
     * Step 3b (Authenticated Mobile Device): Explicitly decline the QR sign-in attempt.
     */
    public function reject(string $signedQrPayload, ?int $now = null): void
    {
        $ts = $now ?? time();
        $challengeId = $this->verifyAndExtractChallengeId($signedQrPayload, $ts);
        $record = $this->readRecord($challengeId);

        if (null === $record || $ts >= $record['expires_at']) {
            $this->cache->delete($this->recordKey($challengeId));

            return;
        }
        if (!in_array($record['status'], ['pending', 'scanned'], true)) {
            return;
        }

        $record['status'] = 'rejected';
        $record['principal'] = null;
        $this->cache->set($this->recordKey($challengeId), $record, max(5, min(60, $record['expires_at'] - $ts + 5)));
    }

    /**
     * Step 4a (Desktop): Check current challenge state using the desktop-only `poll_secret`.
     *
     * Returns `'pending' | 'scanned' | 'approved' | 'rejected' | 'expired'`.
     * Never discloses user identity or confirms unknown challenge IDs.
     */
    public function pollStatus(
        string $challengeId,
        #[SensitiveParameter]
        string $pollSecret,
        ?int $now = null,
    ): string {
        $record = $this->readAuthenticatedRecord($challengeId, $pollSecret, $now ?? time());
        if (null === $record) {
            return 'expired';
        }

        return $record['status'];
    }

    /**
     * Step 4b (Desktop): Atomically claim an approved QR login challenge exactly once.
     *
     * Returns the approved {@see Principal} so the caller can invoke `$sessionAuth->login($session, $principal)`,
     * or `null` if not approved, wrong `poll_secret`, expired, or already claimed.
     */
    public function claim(
        string $challengeId,
        #[SensitiveParameter]
        string $pollSecret,
        ?int $now = null,
    ): ?Principal {
        $ts = $now ?? time();
        $record = $this->readAuthenticatedRecord($challengeId, $pollSecret, $ts);
        if (null === $record || 'approved' !== $record['status'] || null === $record['principal']) {
            return null;
        }

        $principal = self::hydratePrincipal($record['principal']);
        if (null === $principal) {
            $this->cache->delete($this->recordKey($challengeId));

            return null;
        }

        // Atomic one-time claim lock prevents two concurrent desktop polls from claiming the same login
        $remaining = max(10, $record['expires_at'] - $ts + 10);
        $claimKey = $this->prefix . 'claimed:' . hash('sha256', $challengeId);
        if ($this->cache instanceof AtomicCacheInterface) {
            if (!$this->cache->add($claimKey, '1', $remaining)) {
                return null;
            }
        } elseif ($this->cache->has($claimKey)) {
            return null;
        } else {
            $this->cache->set($claimKey, '1', $remaining);
        }

        $this->cache->delete($this->recordKey($challengeId));

        return $principal;
    }

    private function verifyAndExtractChallengeId(string $signedQrPayload, int $now): string
    {
        if (!$this->signer->verify($signedQrPayload, $now)) {
            throw new SecurityException('QR login signature is invalid or expired.');
        }

        $parts = parse_url($signedQrPayload);
        if (false === $parts || !isset($parts['query'])) {
            throw new SecurityException('QR login payload is missing query parameters.');
        }
        $params = SignedUrl::parseStrictQuery($parts['query']);
        $cid = is_array($params) ? ($params['cid'] ?? null) : null;
        if (!is_string($cid) || 1 !== preg_match('/\A[a-f0-9]{32}\z/', $cid)) {
            throw new SecurityException('QR login challenge identifier is invalid.');
        }

        return $cid;
    }

    /**
     * @return array{
     *     status: string,
     *     poll_secret_hash: string,
     *     verification_code: string,
     *     requester_ip: string,
     *     requester_ua: string,
     *     expires_at: int,
     *     principal: ?array<string, mixed>
     * }|null
     */
    private function readAuthenticatedRecord(string $challengeId, string $pollSecret, int $now): ?array
    {
        if (1 !== preg_match('/\A[a-f0-9]{32}\z/', $challengeId) || '' === $pollSecret || strlen($pollSecret) > 256) {
            return null;
        }

        $record = $this->readRecord($challengeId);
        if (null === $record) {
            return null;
        }
        if ($now >= $record['expires_at']) {
            $this->cache->delete($this->recordKey($challengeId));

            return null;
        }
        if (!hash_equals($record['poll_secret_hash'], hash('sha256', $pollSecret))) {
            return null;
        }

        return $record;
    }

    /**
     * @return array{
     *     status: string,
     *     poll_secret_hash: string,
     *     verification_code: string,
     *     requester_ip: string,
     *     requester_ua: string,
     *     expires_at: int,
     *     principal: ?array<string, mixed>
     * }|null
     */
    private function readRecord(string $challengeId): ?array
    {
        $raw = $this->cache->get($this->recordKey($challengeId));
        if (
            !is_array($raw)
            || !is_string($raw['status'] ?? null)
            || !is_string($raw['poll_secret_hash'] ?? null)
            || !is_string($raw['verification_code'] ?? null)
            || !is_string($raw['requester_ip'] ?? null)
            || !is_string($raw['requester_ua'] ?? null)
            || !is_int($raw['expires_at'] ?? null)
        ) {
            return null;
        }

        /** @var array<string, mixed>|null $principal */
        $principal = is_array($raw['principal'] ?? null) ? $raw['principal'] : null;

        return [
            'status' => $raw['status'],
            'poll_secret_hash' => $raw['poll_secret_hash'],
            'verification_code' => $raw['verification_code'],
            'requester_ip' => $raw['requester_ip'],
            'requester_ua' => $raw['requester_ua'],
            'expires_at' => $raw['expires_at'],
            'principal' => $principal,
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function hydratePrincipal(array $data): ?Principal
    {
        if (!is_string($data['id'] ?? null) || '' === $data['id'] || !is_string($data['kind'] ?? null)) {
            return null;
        }
        $kind = PrincipalKind::tryFrom($data['kind']);
        if (null === $kind) {
            return null;
        }
        $capabilities = [];
        if (is_array($data['capabilities'] ?? null)) {
            foreach ($data['capabilities'] as $cap) {
                if (is_string($cap) && '' !== $cap) {
                    $capabilities[] = $cap;
                }
            }
        }
        /** @var array<string, mixed> $attributes */
        $attributes = is_array($data['attributes'] ?? null) ? $data['attributes'] : [];

        return new Principal($data['id'], $kind, $capabilities, $attributes);
    }

    private static function cleanMetadata(string $value, int $maxLen): string
    {
        $clean = preg_replace('/[\x00-\x1f\x7f]+/', ' ', trim($value));
        if (!is_string($clean)) {
            return '';
        }

        return substr($clean, 0, $maxLen);
    }

    private function recordKey(string $challengeId): string
    {
        return $this->prefix . 'cid:' . hash('sha256', $challengeId);
    }
}
