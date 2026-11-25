<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;

/**
 * Credential-stuffing and brute-force login throttler keyed on normalized `(identifier + clientIp)`
 * plus an optional broader per-account burst cap to stop distributed IP-spraying attacks.
 */
final readonly class LoginThrottler
{
    public function __construct(
        private CacheInterface $cache,
        private int $maxAttempts = 5,
        private int $lockoutSeconds = 900,
        private int $maxAccountAttempts = 20,
        private string $prefix = 'kongono:login_throttle:',
    ) {}

    public function isLockedOut(string $identifier, string $clientIp, ?int $now = null): bool
    {
        return $this->retryAfterSeconds($identifier, $clientIp, $now) > 0;
    }

    /** Seconds remaining until login attempts are allowed again (`0` when not locked out). */
    public function retryAfterSeconds(string $identifier, string $clientIp, ?int $now = null): int
    {
        $ts = $now ?? time();
        $pairWait = $this->bucketRetryAfter($this->pairKey($identifier, $clientIp), max(1, $this->maxAttempts), $ts);
        $acctWait = $this->maxAccountAttempts > 0
            ? $this->bucketRetryAfter($this->accountKey($identifier), $this->maxAccountAttempts, $ts)
            : 0;

        return max($pairWait, $acctWait);
    }

    public function remainingAttempts(string $identifier, string $clientIp, ?int $now = null): int
    {
        $ts = $now ?? time();
        $pairState = $this->readBucket($this->pairKey($identifier, $clientIp), $ts);
        $pairRemaining = max(0, max(1, $this->maxAttempts) - $pairState['count']);

        if ($this->maxAccountAttempts > 0) {
            $acctState = $this->readBucket($this->accountKey($identifier), $ts);
            $acctRemaining = max(0, $this->maxAccountAttempts - $acctState['count']);

            return min($pairRemaining, $acctRemaining);
        }

        return $pairRemaining;
    }

    /** Record a failed login attempt and return the updated failure count for `(identifier + clientIp)`. */
    public function recordFailure(string $identifier, string $clientIp, ?int $now = null): int
    {
        $ts = $now ?? time();
        $pairCount = $this->incrementBucket($this->pairKey($identifier, $clientIp), $ts);
        if ($this->maxAccountAttempts > 0) {
            $this->incrementBucket($this->accountKey($identifier), $ts);
        }

        return $pairCount;
    }

    /** Clear failure counters after a successful authentication. */
    public function clear(string $identifier, string $clientIp): void
    {
        $this->clearBucket($this->pairKey($identifier, $clientIp));
        if ($this->maxAccountAttempts > 0) {
            $this->clearBucket($this->accountKey($identifier));
        }
    }

    private function clearBucket(string $key): void
    {
        $reset = $this->cache->get($key . ':reset');
        if (is_int($reset)) {
            $this->cache->delete($key . ':c:' . $reset);
        }
        $this->cache->delete($key);
        $this->cache->delete($key . ':reset');
    }

    private function bucketRetryAfter(string $key, int $limit, int $now): int
    {
        $bucket = $this->readBucket($key, $now);
        if ($bucket['count'] < $limit) {
            return 0;
        }

        return max(0, $bucket['reset_at'] - $now);
    }

    private function incrementBucket(string $key, int $now): int
    {
        $window = max(1, $this->lockoutSeconds);
        if ($this->cache instanceof AtomicCacheInterface) {
            $resetKey = $key . ':reset';
            $existingReset = $this->cache->get($resetKey);
            if (!is_int($existingReset)) {
                $targetReset = $now + $window;
                if ($this->cache->add($resetKey, $targetReset, $window + 5)) {
                    $resetAt = $targetReset;
                } else {
                    $reread = $this->cache->get($resetKey);
                    $resetAt = is_int($reread) && $reread > $now ? $reread : $targetReset;
                }
            } elseif ($now >= $existingReset) {
                $targetReset = $now + $window;
                // Single-winner rollover switches to a fresh reset-scoped counter key without deleting active counters
                if ($this->cache->add($key . ':roll:' . $existingReset, 1, 10)) {
                    $this->cache->set($resetKey, $targetReset, $window + 5);
                    $resetAt = $targetReset;
                } else {
                    $reread = $this->cache->get($resetKey);
                    $resetAt = is_int($reread) && $reread > $now ? $reread : $targetReset;
                }
            } else {
                $resetAt = $existingReset;
            }

            $ttl = max(1, $resetAt - $now) + 5;

            return $this->cache->increment($key . ':c:' . $resetAt, 1, $ttl);
        }

        $bucket = $this->readBucket($key, $now);
        $nextCount = $bucket['count'] + 1;
        $resetAt = $bucket['count'] > 0 ? $bucket['reset_at'] : ($now + $window);
        $ttl = max(1, $resetAt - $now);

        $this->cache->set($key, [
            'count' => $nextCount,
            'reset_at' => $resetAt,
        ], $ttl);

        return $nextCount;
    }

    /** @return array{count: int, reset_at: int} */
    private function readBucket(string $key, int $now): array
    {
        if ($this->cache instanceof AtomicCacheInterface) {
            $resetRaw = $this->cache->get($key . ':reset');
            if (!is_int($resetRaw) || $now >= $resetRaw) {
                return ['count' => 0, 'reset_at' => $now + max(1, $this->lockoutSeconds)];
            }
            $countRaw = $this->cache->get($key . ':c:' . $resetRaw);
            if (!is_int($countRaw)) {
                return ['count' => 0, 'reset_at' => $resetRaw];
            }

            return ['count' => $countRaw, 'reset_at' => $resetRaw];
        }

        $raw = $this->cache->get($key);
        if (!is_array($raw) || !is_int($raw['count'] ?? null) || !is_int($raw['reset_at'] ?? null)) {
            return ['count' => 0, 'reset_at' => $now + max(1, $this->lockoutSeconds)];
        }
        if ($now >= $raw['reset_at']) {
            return ['count' => 0, 'reset_at' => $now + max(1, $this->lockoutSeconds)];
        }

        return ['count' => $raw['count'], 'reset_at' => $raw['reset_at']];
    }

    private function pairKey(string $identifier, string $clientIp): string
    {
        return $this->prefix . 'pair:' . hash('sha256', strtolower(trim($identifier)) . '|' . self::normalizeIp($clientIp));
    }

    private static function normalizeIp(string $ip): string
    {
        $trimmed = trim($ip);
        if ('' === $trimmed) {
            return '';
        }
        $packed = @inet_pton($trimmed);
        if (false === $packed) {
            return strtolower($trimmed);
        }
        // Unwrap IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) so IPv4 and mapped IPv6 share one bucket
        if (16 === strlen($packed) && str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")) {
            $v4 = @inet_ntop(substr($packed, 12));
            if (false !== $v4) {
                return strtolower($v4);
            }
        }
        $canonical = @inet_ntop($packed);

        return false !== $canonical ? strtolower($canonical) : strtolower($trimmed);
    }

    private function accountKey(string $identifier): string
    {
        return $this->prefix . 'acct:' . hash('sha256', strtolower(trim($identifier)));
    }
}
