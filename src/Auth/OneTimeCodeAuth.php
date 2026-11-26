<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Security\SecurityException;
use SensitiveParameter;

/**
 * Single-use Email / SMS One-Time Passcode (OTP) authentication helper.
 *
 * Security properties:
 *   - Cryptographically uniform codes generated via `random_int()` (6–10 digits)
 *   - Domain-separated HKDF-SHA256 + per-issue random nonce HMAC storage (never stores plaintext codes)
 *   - Issuing a new code for an identifier immediately invalidates any prior code
 *   - Strict failed-attempt ceiling (`maxAttempts`, default 5) immediately invalidates the code on exhaustion
 *   - Atomic one-time claim lock prevents concurrent replay races
 */
final readonly class OneTimeCodeAuth
{
    private string $derivedKey;

    public function __construct(
        #[SensitiveParameter]
        string $secretKey,
        private CacheInterface $cache,
        private string $prefix = 'kongono:otp:',
    ) {
        if ('' === $secretKey) {
            throw new SecurityException('OneTimeCodeAuth requires a non-empty secret key.');
        }
        $this->derivedKey = hash_hkdf('sha256', $secretKey, 32, 'kongono:otp:v1');
    }

    /**
     * Issue a fresh single-use numeric OTP for `$identifier` (email address, phone number, or user ID).
     *
     * @param array<string, mixed> $claims Optional metadata persisted server-side until verification
     * @return array{code: string, expires_at: int, max_attempts: int}
     */
    public function issue(
        string $identifier,
        int $digits = 6,
        int $ttlSeconds = 600,
        int $maxAttempts = 5,
        array $claims = [],
        ?int $now = null,
    ): array {
        $normalized = self::normalizeIdentifier($identifier);
        if ($digits < 6 || $digits > 10) {
            throw new SecurityException('One-time code length must be between 6 and 10 digits.');
        }

        $ttl = max(30, $ttlSeconds);
        $attemptsCap = min(10, max(1, $maxAttempts));
        $ts = $now ?? time();
        $expiresAt = $ts + $ttl;

        $code = str_pad((string) random_int(0, (10 ** $digits) - 1), $digits, '0', STR_PAD_LEFT);
        $nonce = bin2hex(random_bytes(16));
        $digest = $this->digestCode($normalized, $code, $nonce);

        $this->cache->set($this->identifierKey($normalized), [
            'nonce' => $nonce,
            'code_hash' => $digest,
            'digits' => $digits,
            'attempts' => 0,
            'max_attempts' => $attemptsCap,
            'expires_at' => $expiresAt,
            'claims' => $claims,
        ], $ttl + 5);

        return [
            'code' => $code,
            'expires_at' => $expiresAt,
            'max_attempts' => $attemptsCap,
        ];
    }

    /**
     * Verify and atomically consume a single-use OTP.
     *
     * Accepts optional spaces or hyphens in user input (e.g. `123 456` or `123-456`).
     * Invalidates the code immediately once `max_attempts` wrong guesses are reached.
     *
     * @return array{identifier: string, claims: array<string, mixed>}|null
     */
    public function verify(
        string $identifier,
        #[SensitiveParameter]
        string $code,
        ?int $now = null,
    ): ?array {
        $normalized = strtolower(trim($identifier));
        if ('' === $normalized) {
            return null;
        }

        $record = $this->readRecord($normalized);
        if (null === $record) {
            return null;
        }

        $ts = $now ?? time();
        if ($ts >= $record['expires_at']) {
            $this->cache->delete($this->identifierKey($normalized));

            return null;
        }

        $cleanCode = preg_replace('/[\s-]+/', '', trim($code));
        $validSyntax = is_string($cleanCode)
            && strlen($cleanCode) === $record['digits']
            && ctype_digit($cleanCode);

        $candidateHash = $validSyntax
            ? $this->digestCode($normalized, $cleanCode, $record['nonce'])
            : $this->digestCode($normalized, str_repeat('0', $record['digits']), $record['nonce']);

        if (!$validSyntax || !hash_equals($record['code_hash'], $candidateHash)) {
            $nextAttempts = $record['attempts'] + 1;
            if ($nextAttempts >= $record['max_attempts']) {
                $this->cache->delete($this->identifierKey($normalized));
            } else {
                $record['attempts'] = $nextAttempts;
                $this->cache->set($this->identifierKey($normalized), $record, max(5, $record['expires_at'] - $ts + 5));
            }

            return null;
        }

        // Atomic one-time claim lock prevents two concurrent verification requests from both succeeding
        $remaining = max(5, $record['expires_at'] - $ts + 5);
        $claimKey = $this->prefix . 'used:' . $record['code_hash'];
        if ($this->cache instanceof AtomicCacheInterface) {
            if (!$this->cache->add($claimKey, '1', $remaining)) {
                return null;
            }
        } elseif ($this->cache->has($claimKey)) {
            return null;
        } else {
            $this->cache->set($claimKey, '1', $remaining);
        }

        $this->cache->delete($this->identifierKey($normalized));

        return [
            'identifier' => $normalized,
            'claims' => $record['claims'],
        ];
    }

    public function invalidate(string $identifier): void
    {
        $normalized = strtolower(trim($identifier));
        if ('' !== $normalized) {
            $this->cache->delete($this->identifierKey($normalized));
        }
    }

    /**
     * @return array{
     *     nonce: string,
     *     code_hash: string,
     *     digits: int,
     *     attempts: int,
     *     max_attempts: int,
     *     expires_at: int,
     *     claims: array<string, mixed>
     * }|null
     */
    private function readRecord(string $normalizedIdentifier): ?array
    {
        $raw = $this->cache->get($this->identifierKey($normalizedIdentifier));
        if (
            !is_array($raw)
            || !is_string($raw['nonce'] ?? null)
            || !is_string($raw['code_hash'] ?? null)
            || !is_int($raw['digits'] ?? null)
            || !is_int($raw['attempts'] ?? null)
            || !is_int($raw['max_attempts'] ?? null)
            || !is_int($raw['expires_at'] ?? null)
        ) {
            return null;
        }

        /** @var array<string, mixed> $claims */
        $claims = is_array($raw['claims'] ?? null) ? $raw['claims'] : [];

        return [
            'nonce' => $raw['nonce'],
            'code_hash' => $raw['code_hash'],
            'digits' => $raw['digits'],
            'attempts' => $raw['attempts'],
            'max_attempts' => $raw['max_attempts'],
            'expires_at' => $raw['expires_at'],
            'claims' => $claims,
        ];
    }

    private function digestCode(string $normalizedIdentifier, string $code, string $nonce): string
    {
        return hash_hmac('sha256', $normalizedIdentifier . "\0" . $code . "\0" . $nonce, $this->derivedKey);
    }

    private static function normalizeIdentifier(string $identifier): string
    {
        $normalized = strtolower(trim($identifier));
        if ('' === $normalized || strlen($normalized) > 320 || 1 === preg_match('/[\x00-\x1f\x7f]/', $normalized)) {
            throw new SecurityException('One-time code requires a valid non-empty identifier.');
        }

        return $normalized;
    }

    private function identifierKey(string $normalizedIdentifier): string
    {
        return $this->prefix . 'id:' . hash('sha256', $normalizedIdentifier);
    }
}
