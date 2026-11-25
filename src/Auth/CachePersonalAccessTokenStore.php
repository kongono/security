<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Closure;
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
        $this->cache->delete($this->revokedKey($id));
        $this->cache->set($this->tokenKey($id), $record->toArray(), $storeTtl);

        $ids = $this->readIndex($principal->id);
        if (!in_array($id, $ids, true)) {
            $ids[] = $id;
            $this->writeIndex($principal->id, $ids, max($this->defaultTtlSeconds, $storeTtl));
        }

        return new IssuedToken('kgn_pat_' . $id . '.' . $secret, $record);
    }

    public function authenticate(#[SensitiveParameter] string $plainTextToken, ?int $now = null): ?PersonalAccessToken
    {
        $parsed = PersonalAccessToken::parsePlainText($plainTextToken);
        if (null === $parsed) {
            return null;
        }

        $record = $this->findById($parsed['id']);
        if (null === $record) {
            return null;
        }

        // Check principal-wide revocation watermark (immune to concurrent index races)
        $revokedBefore = $this->cache->get($this->revokedBeforeKey($record->principalId));
        if (is_int($revokedBefore) && $record->createdAt <= $revokedBefore) {
            return null;
        }

        if (!hash_equals($record->tokenHash, hash('sha256', $parsed['secret']))) {
            return null;
        }

        $ts = $now ?? time();
        if ($record->isExpired($ts)) {
            $this->revoke($record->id);

            return null;
        }

        $updated = $record->withLastUsedAt($ts);
        // Only persist lastUsedAt if token has NOT been concurrently revoked (tombstone check prevents resurrection TOCTOU)
        if (null === $this->cache->get($this->revokedKey($updated->id))) {
            $remaining = null !== $updated->expiresAt ? max(1, $updated->expiresAt - $ts) : $this->defaultTtlSeconds;
            $this->cache->set($this->tokenKey($updated->id), $updated->toArray(), $remaining);
        }

        return $updated;
    }

    public function listForPrincipal(string $principalId): array
    {
        $ids = $this->readIndex($principalId);
        $out = [];
        $aliveIds = [];
        $revokedBefore = $this->cache->get($this->revokedBeforeKey($principalId));
        foreach ($ids as $id) {
            $record = $this->findById($id);
            if (null !== $record && $record->principalId === $principalId && !(is_int($revokedBefore) && $record->createdAt <= $revokedBefore)) {
                $out[] = $record;
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
        $this->cache->set($this->revokedBeforeKey($principalId), time(), $this->defaultTtlSeconds + 3600);
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

        return PersonalAccessToken::fromArray($normalized);
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

    private function revokedBeforeKey(string $principalId): string
    {
        return $this->prefix . 'revbefore:' . hash('sha256', $principalId);
    }

    private function indexKey(string $principalId): string
    {
        return $this->prefix . 'idx:' . hash('sha256', $principalId);
    }
}
