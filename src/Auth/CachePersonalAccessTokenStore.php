<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Closure;
use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Security\Principal;
use Kongono\Security\SecurityException;
use SensitiveParameter;

/**
 * Cache-backed Personal Access Token store (works with MemoryCache, FileCache, or shared RedisCache
 * across horizontal FrankenPHP workers).
 */
final readonly class CachePersonalAccessTokenStore implements PersonalAccessTokenStoreInterface
{
    public function __construct(
        private CacheInterface $cache,
        private string $prefix = 'kongono:pat:',
        private int $defaultTtlSeconds = 31_536_000,
    ) {}

    public function issue(
        Principal $principal,
        string $name,
        ?array $capabilities = null,
        ?int $ttlSeconds = null,
        ?int $now = null,
    ): IssuedToken {
        $cleanName = trim($name);
        if ('' === $cleanName) {
            throw new SecurityException('Personal access token name cannot be empty.');
        }

        $ts = $now ?? time();
        $id = bin2hex(random_bytes(8));
        $secret = bin2hex(random_bytes(24));
        $expiresAt = null !== $ttlSeconds ? $ts + max(1, $ttlSeconds) : null;
        $record = new PersonalAccessToken(
            id: $id,
            principalId: $principal->id,
            principalKind: $principal->kind,
            name: $cleanName,
            capabilities: $capabilities ?? $principal->capabilities,
            tokenHash: hash('sha256', $secret),
            createdAt: $ts,
            expiresAt: $expiresAt,
            lastUsedAt: null,
            attributes: $principal->attributes,
        );

        $storeTtl = null !== $ttlSeconds ? max(1, $ttlSeconds) : $this->defaultTtlSeconds;
        $maxTtlKey = $this->maxTtlKey($principal->id);
        $prevMaxTtl = $this->cache->get($maxTtlKey);
        $effectiveMaxTtl = max($this->defaultTtlSeconds, $storeTtl, is_int($prevMaxTtl) ? $prevMaxTtl : 0);
        $metaTtl = $effectiveMaxTtl + 86400;
        if (!is_int($prevMaxTtl) || $effectiveMaxTtl > $prevMaxTtl) {
            $this->cache->set($maxTtlKey, $effectiveMaxTtl, $metaTtl);
        }

        // Always persist a non-zero generation anchor outliving every active token so cache expiry/eviction fails closed
        $revGen = $this->ensureRevocationGen($principal->id, $metaTtl);
        $this->cache->delete($this->revokedKey($id));
        $payload = $record->toArray();
        $payload['_rev_gen'] = $revGen;
        $payload['_store_expires_at'] = $ts + $storeTtl;
        $this->cache->set($this->tokenKey($id), $payload, $storeTtl);

        $ids = $this->readIndex($principal->id);
        if (!in_array($id, $ids, true)) {
            $ids[] = $id;
            $this->writeIndex($principal->id, $ids, $effectiveMaxTtl);
        }

        return new IssuedToken('kgn_pat_' . $id . '.' . $secret, $record);
    }

    public function authenticate(#[SensitiveParameter] string $plainTextToken, ?int $now = null): ?PersonalAccessToken
    {
        $parsed = PersonalAccessToken::parsePlainText($plainTextToken);
        if (null === $parsed) {
            return null;
        }

        $found = $this->findEntryById($parsed['id']);
        if (null === $found) {
            return null;
        }
        $record = $found['record'];
        $tokenGen = $found['rev_gen'];
        $storeExpiresAt = $found['store_expires_at'];

        // Fail closed if principal revocation generation metadata expired/evicted OR token predates a revokeAll
        $storedGen = $this->storedRevocationGen($record->principalId);
        if (null === $storedGen || $tokenGen < $storedGen) {
            return null;
        }

        if (!hash_equals($record->tokenHash, hash('sha256', $parsed['secret']))) {
            return null;
        }

        $ts = $now ?? time();
        if ($record->isExpired($ts) || (null !== $storeExpiresAt && $ts >= $storeExpiresAt)) {
            $this->revoke($record->id);

            return null;
        }

        $updated = $record->withLastUsedAt($ts);
        // Only persist lastUsedAt if token has NOT been concurrently revoked, and NEVER extend past original storage deadline
        $currentGen = $this->storedRevocationGen($updated->principalId);
        if (
            null === $this->cache->get($this->revokedKey($updated->id))
            && null !== $currentGen
            && $tokenGen >= $currentGen
        ) {
            $deadline = $updated->expiresAt ?? $storeExpiresAt ?? ($updated->createdAt + $this->defaultTtlSeconds);
            $remaining = max(1, $deadline - $ts);
            $payload = $updated->toArray();
            $payload['_rev_gen'] = $tokenGen;
            $payload['_store_expires_at'] = $deadline;
            $this->cache->set($this->tokenKey($updated->id), $payload, $remaining);
        }

        return $updated;
    }

    public function listForPrincipal(string $principalId): array
    {
        $ids = $this->readIndex($principalId);
        $out = [];
        $aliveIds = [];
        $currentGen = $this->storedRevocationGen($principalId);
        if (null === $currentGen) {
            return [];
        }
        foreach ($ids as $id) {
            $found = $this->findEntryById($id);
            if (null !== $found && $found['record']->principalId === $principalId && $found['rev_gen'] >= $currentGen) {
                $out[] = $found['record'];
                $aliveIds[] = $id;
            }
        }
        if (count($aliveIds) !== count($ids)) {
            $this->writeIndex($principalId, $aliveIds);
        }

        return $out;
    }

    public function revoke(string $tokenId): bool
    {
        $record = $this->findById($tokenId);
        if (null === $record) {
            return false;
        }

        $tombstoneTtl = (null !== $record->expiresAt ? max(300, $record->expiresAt - time()) : max(300, $this->defaultTtlSeconds)) + 3600;
        $this->cache->set($this->revokedKey($tokenId), 1, $tombstoneTtl);
        $this->cache->delete($this->tokenKey($tokenId));
        $ids = array_values(array_filter(
            $this->readIndex($record->principalId),
            static fn(string $id): bool => $id !== $tokenId,
        ));
        $this->writeIndex($record->principalId, $ids);

        return true;
    }

    public function revokeAllForPrincipal(string $principalId): int
    {
        $observedMax = $this->cache->get($this->maxTtlKey($principalId));
        $genTtl = max($this->defaultTtlSeconds, is_int($observedMax) ? $observedMax : 0) + 86400;
        $genKey = $this->revGenKey($principalId);
        if ($this->cache instanceof AtomicCacheInterface) {
            $newGen = $this->cache->increment($genKey, 1, $genTtl);
            $this->cache->set($genKey, max(2, $newGen), $genTtl);
        } else {
            $this->cache->set($genKey, max(1, $this->storedRevocationGen($principalId) ?? 1) + 1, $genTtl);
        }

        $ids = $this->readIndex($principalId);
        $removed = 0;
        foreach ($ids as $id) {
            $record = $this->findById($id);
            if (null !== $record) {
                $tombstoneTtl = (null !== $record->expiresAt ? max(300, $record->expiresAt - time()) : max(300, $this->defaultTtlSeconds)) + 3600;
                $this->cache->set($this->revokedKey($id), 1, $tombstoneTtl);
                $this->cache->delete($this->tokenKey($id));
                ++$removed;
            }
        }
        $this->cache->delete($this->indexKey($principalId));

        return $removed;
    }

    public function toBearerResolver(): Closure
    {
        return fn(string $token): ?Principal => $this->authenticate($token)?->toPrincipal();
    }

    private function findById(string $id): ?PersonalAccessToken
    {
        return $this->findEntryById($id)['record'] ?? null;
    }

    /** @return array{record: PersonalAccessToken, rev_gen: int, store_expires_at: ?int}|null */
    private function findEntryById(string $id): ?array
    {
        if (null !== $this->cache->get($this->revokedKey($id))) {
            return null;
        }
        $raw = $this->cache->get($this->tokenKey($id));
        if (!is_array($raw)) {
            return null;
        }

        /** @var array<string, mixed> $normalized */
        $normalized = [];
        foreach ($raw as $k => $v) {
            $normalized[(string) $k] = $v;
        }

        $record = PersonalAccessToken::fromArray($normalized);
        if (null === $record) {
            return null;
        }

        return [
            'record' => $record,
            'rev_gen' => is_int($normalized['_rev_gen'] ?? null) ? $normalized['_rev_gen'] : 0,
            'store_expires_at' => is_int($normalized['_store_expires_at'] ?? null) ? $normalized['_store_expires_at'] : null,
        ];
    }

    /** @return list<string> */
    private function readIndex(string $principalId): array
    {
        $raw = $this->cache->get($this->indexKey($principalId));
        if (!is_array($raw)) {
            return [];
        }
        $ids = [];
        foreach ($raw as $id) {
            if (is_string($id) && '' !== $id) {
                $ids[] = $id;
            }
        }

        return $ids;
    }

    /** @param list<string> $ids */
    private function writeIndex(string $principalId, array $ids, ?int $ttlSeconds = null): void
    {
        if ([] === $ids) {
            $this->cache->delete($this->indexKey($principalId));

            return;
        }
        $this->cache->set($this->indexKey($principalId), $ids, max($this->defaultTtlSeconds, $ttlSeconds ?? $this->defaultTtlSeconds));
    }

    private function tokenKey(string $id): string
    {
        return $this->prefix . 'tok:' . $id;
    }

    private function revokedKey(string $id): string
    {
        return $this->prefix . 'rev:' . $id;
    }

    private function revGenKey(string $principalId): string
    {
        return $this->prefix . 'revgen:' . hash('sha256', $principalId);
    }

    private function maxTtlKey(string $principalId): string
    {
        return $this->prefix . 'maxttl:' . hash('sha256', $principalId);
    }

    private function storedRevocationGen(string $principalId): ?int
    {
        $raw = $this->cache->get($this->revGenKey($principalId));

        return is_int($raw) && $raw >= 1 ? $raw : null;
    }

    private function ensureRevocationGen(string $principalId, int $ttlSeconds): int
    {
        $genKey = $this->revGenKey($principalId);
        $existing = $this->storedRevocationGen($principalId);
        if (null !== $existing) {
            $this->cache->set($genKey, $existing, $ttlSeconds);

            return $existing;
        }

        if ($this->cache instanceof AtomicCacheInterface) {
            if ($this->cache->add($genKey, 1, $ttlSeconds)) {
                return 1;
            }
            $concurrent = $this->storedRevocationGen($principalId);
            if (null !== $concurrent) {
                $this->cache->set($genKey, $concurrent, $ttlSeconds);

                return $concurrent;
            }
        }

        $this->cache->set($genKey, 1, $ttlSeconds);

        return 1;
    }

    private function indexKey(string $principalId): string
    {
        return $this->prefix . 'idx:' . hash('sha256', $principalId);
    }
}
