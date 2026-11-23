<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Security\SecurityException;
use SensitiveParameter;

/**
 * Single-use, SHA-256-hashed password reset token broker.
 *
 * Security properties:
 *   - Stores only SHA-256 token digests server-side (never plaintext reset tokens)
 *   - Issuing a fresh token for an email automatically invalidates any previous token
 *   - Wrong token guesses never invalidate a pending legitimate reset token (no DoS)
 *   - Atomic one-time claim lock prevents concurrent replay races
 */
final readonly class PasswordResetBroker
{
    public function __construct(
        private CacheInterface $cache,
        private string $prefix = 'kongono:pwd_reset:',
    ) {}

    /** Generate a 256-bit reset token for `$email`, replacing any prior active token for that email. */
    public function createToken(string $email, int $ttlSeconds = 3600, ?int $now = null): string
    {
        $normalized = self::normalizeEmail($email);
        $ttl = max(60, $ttlSeconds);
        $ts = $now ?? time();
        $token = bin2hex(random_bytes(32));

        $this->cache->set($this->emailKey($normalized), [
            'token_hash' => hash('sha256', $token),
            'expires_at' => $ts + $ttl,
        ], $ttl + 5);

        return $token;
    }

    /** Non-consuming constant-time verification check (useful for rendering the reset password form). */
    public function verify(string $email, #[SensitiveParameter] string $token, ?int $now = null): bool
    {
        if ('' === $token || strlen($token) > 256) {
            return false;
        }
        $normalized = strtolower(trim($email));
        if ('' === $normalized) {
            return false;
        }

        $record = $this->readRecord($normalized);
        if (null === $record) {
            return false;
        }

        $ts = $now ?? time();
        if ($ts >= $record['expires_at']) {
            return false;
        }

        return hash_equals($record['token_hash'], hash('sha256', $token));
    }

    /**
     * Atomically verify and consume a single-use password reset token.
     * Returns `true` exactly once for a valid non-expired token; `false` otherwise.
     */
    public function consume(string $email, #[SensitiveParameter] string $token, ?int $now = null): bool
    {
        if ('' === $token || strlen($token) > 256) {
            return false;
        }
        $normalized = strtolower(trim($email));
        if ('' === $normalized) {
            return false;
        }

        $record = $this->readRecord($normalized);
        if (null === $record) {
            return false;
        }

        $ts = $now ?? time();
        if ($ts >= $record['expires_at']) {
            $this->cache->delete($this->emailKey($normalized));

            return false;
        }

        $presentedHash = hash('sha256', $token);
        if (!hash_equals($record['token_hash'], $presentedHash)) {
            return false;
        }

        // Atomic one-time claim lock prevents two concurrent requests from both consuming the same valid token
        $remaining = max(5, $record['expires_at'] - $ts + 5);
        $claimKey = $this->prefix . 'used:' . $presentedHash;
        if ($this->cache instanceof AtomicCacheInterface) {
            if (!$this->cache->add($claimKey, '1', $remaining)) {
                return false;
            }
        } elseif ($this->cache->has($claimKey)) {
            return false;
        } else {
            $this->cache->set($claimKey, '1', $remaining);
        }

        $this->cache->delete($this->emailKey($normalized));

        return true;
    }

    public function revoke(string $email): void
    {
        $normalized = strtolower(trim($email));
        if ('' !== $normalized) {
            $this->cache->delete($this->emailKey($normalized));
        }
    }

    /** @return array{token_hash: string, expires_at: int}|null */
    private function readRecord(string $normalizedEmail): ?array
    {
        $raw = $this->cache->get($this->emailKey($normalizedEmail));
        if (!is_array($raw) || !is_string($raw['token_hash'] ?? null) || !is_int($raw['expires_at'] ?? null)) {
            return null;
        }

        return [
            'token_hash' => $raw['token_hash'],
            'expires_at' => $raw['expires_at'],
        ];
    }

    private function emailKey(string $normalizedEmail): string
    {
        return $this->prefix . 'email:' . hash('sha256', $normalizedEmail);
    }

    private static function normalizeEmail(string $email): string
    {
        $clean = strtolower(trim($email));
        if ('' === $clean || false === filter_var($clean, FILTER_VALIDATE_EMAIL)) {
            throw new SecurityException('Password reset requires a valid email address.');
        }

        return $clean;
    }
}
