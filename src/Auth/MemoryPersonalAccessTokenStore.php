<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Closure;
use Kongono\Security\Principal;
use Kongono\Security\SecurityException;
use SensitiveParameter;

/** Fast deterministic in-memory Personal Access Token store for tests and single-process apps. */
final class MemoryPersonalAccessTokenStore implements PersonalAccessTokenStoreInterface
{
    /** @var array<string, PersonalAccessToken> */
    private array $tokens = [];

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
        $record = new PersonalAccessToken(
            id: $id,
            principalId: $principal->id,
            principalKind: $principal->kind,
            name: $cleanName,
            capabilities: $capabilities ?? $principal->capabilities,
            tokenHash: hash('sha256', $secret),
            createdAt: $ts,
            expiresAt: null !== $ttlSeconds ? $ts + max(1, $ttlSeconds) : null,
            lastUsedAt: null,
            attributes: $principal->attributes,
        );
        $this->tokens[$id] = $record;

        return new IssuedToken('kgn_pat_' . $id . '.' . $secret, $record);
    }

    public function authenticate(#[SensitiveParameter] string $plainTextToken, ?int $now = null): ?PersonalAccessToken
    {
        $parsed = PersonalAccessToken::parsePlainText($plainTextToken);
        if (null === $parsed) {
            return null;
        }

        $record = $this->tokens[$parsed['id']] ?? null;
        if (null === $record) {
            return null;
        }

        if (!hash_equals($record->tokenHash, hash('sha256', $parsed['secret']))) {
            return null;
        }

        $ts = $now ?? time();
        if ($record->isExpired($ts)) {
            unset($this->tokens[$record->id]);

            return null;
        }

        $updated = $record->withLastUsedAt($ts);
        $this->tokens[$record->id] = $updated;

        return $updated;
    }

    public function listForPrincipal(string $principalId): array
    {
        $out = [];
        foreach ($this->tokens as $token) {
            if ($token->principalId === $principalId) {
                $out[] = $token;
            }
        }

        return $out;
    }

    public function revoke(string $tokenId): bool
    {
        if (!isset($this->tokens[$tokenId])) {
            return false;
        }
        unset($this->tokens[$tokenId]);

        return true;
    }

    public function revokeAllForPrincipal(string $principalId): int
    {
        $removed = 0;
        foreach ($this->tokens as $id => $token) {
            if ($token->principalId === $principalId) {
                unset($this->tokens[$id]);
                ++$removed;
            }
        }

        return $removed;
    }

    public function toBearerResolver(): Closure
    {
        return fn(string $token): ?Principal => $this->authenticate($token)?->toPrincipal();
    }
}
