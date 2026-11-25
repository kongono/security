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
        $pairKey = $this->pairKey($identifier, $clientIp);
        $this->cache->delete($pairKey);
        $this->cache->delete($pairKey . ':reset');
        if ($this->maxAccountAttempts > 0) {
            $acctKey = $this->accountKey($identifier);
            $this->cache->delete($acctKey);
            $this->cache->delete($acctKey . ':reset');
        }
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
                if ($this->cache->add($resetKey, $now + $window, $window + 5)) {
                    $this->cache->delete($key);
                    $ttl = $window + 5;
                } else {
                    $reread = $this->cache->get($resetKey);
                    $ttl = is_int($reread) ? max(1, $reread - $now) + 5 : ($window + 5);
                }
            } elseif ($now >= $existingReset) {
                // Single-winner reset guard prevents concurrent requests from repeatedly clearing sibling counts
                if ($this->cache->add($key . ':roll:' . $existingReset, 1, 10)) {
                    $this->cache->delete($key);
                    $this->cache->set($resetKey, $now + $window, $window + 5);
                }
                $ttl = $window + 5;
            } else {
                $ttl = max(1, $existingReset - $now) + 5;
            }

            return $this->cache->increment($key, 1, $ttl);
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
            $countRaw = $this->cache->get($key);
            $resetRaw = $this->cache->get($key . ':reset');
            if (!is_int($countRaw) || !is_int($resetRaw) || $now >= $resetRaw) {
                return ['count' => 0, 'reset_at' => $now + max(1, $this->lockoutSeconds)];
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
        return $this->prefix . 'pair:' . hash('sha256', strtolower(trim($identifier)) . '|' . trim($clientIp));
    }

    private function accountKey(string $identifier): string
    {
        return $this->prefix . 'acct:' . hash('sha256', strtolower(trim($identifier)));
    }
}
