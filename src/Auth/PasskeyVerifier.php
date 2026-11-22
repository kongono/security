<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Core\Cache\CacheInterface;
use Kongono\Security\SecurityException;

/**
 * Pure PHP 8.5 WebAuthn / FIDO2 Passkey challenge issuer and cryptographic assertion verifier.
 *
 * Verifies FaceID / TouchID / YubiKey assertions with zero third-party packages:
 *   - One-time cryptographic challenges stored & consumed via CacheInterface
 *   - Exact origin & `webauthn.get` clientDataJSON validation
 *   - SHA-256 `rpIdHash`, User Present (UP), optional User Verified (UV), and anti-cloning `signCount` checks
 *   - ES256 (ECDSA P-256 via ext-openssl) and EdDSA (Ed25519 via ext-sodium) signature verification
 */
final readonly class PasskeyVerifier
{
    public function __construct(
        private CacheInterface $cache,
        private string $cachePrefix = 'kongono:passkey:challenge:',
    ) {}

    /**
     * Issue a one-time WebAuthn challenge bound to `$rpId` and `$origin`.
     *
     * @return array{challenge: string, rpId: string, origin: string, expiresAt: int}
     */
    public function createChallenge(string $rpId, string $origin, int $ttlSeconds = 300, ?int $now = null): array
    {
        $cleanRpId = strtolower(trim($rpId));
        $cleanOrigin = rtrim(trim($origin), '/');
        if ('' === $cleanRpId || '' === $cleanOrigin) {
            throw new SecurityException('Passkey rpId and origin are required.');
        }

        $ttl = max(30, $ttlSeconds);
        $challenge = self::base64UrlEncode(random_bytes(32));
        $expiresAt = ($now ?? time()) + $ttl;

        $this->cache->set(
            $this->challengeKey($challenge),
            json_encode([
                'rpId' => $cleanRpId,
                'origin' => $cleanOrigin,
                'expiresAt' => $expiresAt,
            ], JSON_THROW_ON_ERROR),
            $ttl + 5,
        );

        return [
            'challenge' => $challenge,
            'rpId' => $cleanRpId,
            'origin' => $cleanOrigin,
            'expiresAt' => $expiresAt,
        ];
    }

    /**
     * Verify a WebAuthn authentication assertion (`navigator.credentials.get()`).
     *
     * @param 'ES256'|'EdDSA' $algorithm
     * @return array{signCount: int, userPresent: bool, userVerified: bool}
     */
    public function verifyAssertion(
        string $expectedChallenge,
        string $clientDataJsonBase64Url,
        string $authenticatorDataBase64Url,
        string $signatureBase64Url,
        string $publicKey,
        string $algorithm = 'ES256',
        int $previousSignCount = 0,
        bool $requireUserVerification = false,
        ?int $now = null,
    ): array {
        $cacheKey = $this->challengeKey($expectedChallenge);
        $rawChallengeMeta = $this->cache->get($cacheKey);
        if (!is_string($rawChallengeMeta) || '' === $rawChallengeMeta) {
            throw new SecurityException('Passkey challenge is unknown, expired, or already consumed.');
        }

        // Single-use challenge consumption (prevents replay even if assertion fails)
        $this->cache->delete($cacheKey);

        $meta = json_decode($rawChallengeMeta, true);
        if (!is_array($meta) || !is_string($meta['rpId'] ?? null) || !is_string($meta['origin'] ?? null) || !is_int($meta['expiresAt'] ?? null)) {
            throw new SecurityException('Stored passkey challenge metadata is invalid.');
        }

        if (($now ?? time()) > $meta['expiresAt']) {
            throw new SecurityException('Passkey challenge has expired.');
        }

        $clientDataRaw = self::base64UrlDecode($clientDataJsonBase64Url);
        $clientData = json_decode($clientDataRaw, true);
        if (!is_array($clientData)) {
            throw new SecurityException('Passkey clientDataJSON is not valid JSON.');
        }

        if (($clientData['type'] ?? null) !== 'webauthn.get') {
            throw new SecurityException('Passkey assertion type must be "webauthn.get".');
        }

        $receivedChallenge = is_string($clientData['challenge'] ?? null) ? $clientData['challenge'] : '';
        if (!hash_equals($expectedChallenge, $receivedChallenge)) {
            throw new SecurityException('Passkey challenge mismatch.');
        }

        $receivedOrigin = is_string($clientData['origin'] ?? null) ? rtrim($clientData['origin'], '/') : '';
        if (!hash_equals($meta['origin'], $receivedOrigin)) {
            throw new SecurityException('Passkey origin mismatch.');
        }

        $authData = self::base64UrlDecode($authenticatorDataBase64Url);
        if (strlen($authData) < 37) {
            throw new SecurityException('Passkey authenticatorData is truncated.');
        }

        $rpIdHash = substr($authData, 0, 32);
        $expectedRpIdHash = hash('sha256', $meta['rpId'], true);
        if (!hash_equals($expectedRpIdHash, $rpIdHash)) {
            throw new SecurityException('Passkey RP ID hash mismatch.');
        }

        $flags = ord($authData[32]);
        $userPresent = 0 !== ($flags & 0x01);
        $userVerified = 0 !== ($flags & 0x04);
        if (!$userPresent) {
            throw new SecurityException('Passkey User Present (UP) flag is not set.');
        }
        if ($requireUserVerification && !$userVerified) {
            throw new SecurityException('Passkey User Verified (UV) flag is required but not set.');
        }

        $unpacked = unpack('Ncount', substr($authData, 33, 4));
        $signCount = is_array($unpacked) && is_int($unpacked['count'] ?? null) ? $unpacked['count'] : 0;
        if ($signCount > 0 && $signCount <= $previousSignCount) {
            throw new SecurityException('Passkey signCount did not advance (possible cloned authenticator).');
        }

        $signature = self::base64UrlDecode($signatureBase64Url);
        $signedPayload = $authData . hash('sha256', $clientDataRaw, true);

        $valid = match ($algorithm) {
            'ES256' => $this->verifyEs256($signedPayload, $signature, $publicKey),
            'EdDSA' => $this->verifyEd25519($signedPayload, $signature, $publicKey),
        };

        if (!$valid) {
            throw new SecurityException('Passkey cryptographic signature verification failed.');
        }

        return [
            'signCount' => $signCount,
            'userPresent' => $userPresent,
            'userVerified' => $userVerified,
        ];
    }

    public static function base64UrlEncode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $encoded): string
    {
        $normalized = strtr($encoded, '-_', '+/');
        $pad = strlen($normalized) % 4;
        if ($pad > 0) {
            $normalized .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($normalized, true);
        if (false === $decoded) {
            throw new SecurityException('Invalid base64url payload.');
        }

        return $decoded;
    }

    private function verifyEs256(string $signedPayload, string $signature, string $publicKeyPem): bool
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if (false === $key) {
            throw new SecurityException('Invalid ES256 PEM public key.');
        }

        return 1 === openssl_verify($signedPayload, $signature, $key, OPENSSL_ALGO_SHA256);
    }

    private function verifyEd25519(string $signedPayload, string $signature, string $publicKeyHexOrRaw): bool
    {
        $rawKey = SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES === strlen($publicKeyHexOrRaw)
            ? $publicKeyHexOrRaw
            : hex2bin($publicKeyHexOrRaw);
        if (!is_string($rawKey) || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen($rawKey)) {
            throw new SecurityException('Invalid Ed25519 public key (expected 32 raw bytes or 64 hex chars).');
        }
        if (SODIUM_CRYPTO_SIGN_BYTES !== strlen($signature)) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $signedPayload, $rawKey);
    }

    private function challengeKey(string $challenge): string
    {
        return $this->cachePrefix . hash('sha256', $challenge);
    }
}
