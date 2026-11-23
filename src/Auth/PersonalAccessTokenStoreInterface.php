<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Closure;
use Kongono\Security\Principal;
use SensitiveParameter;

/**
 * Store contract for revocable, SHA-256-hashed Personal Access Tokens (Sanctum-equivalent).
 */
interface PersonalAccessTokenStoreInterface
{
    /**
     * Issue a new scoped Personal Access Token for `$principal`.
     *
     * @param list<string>|null $capabilities Scoped token abilities (defaults to `$principal->capabilities`)
     */
    public function issue(
        Principal $principal,
        string $name,
        ?array $capabilities = null,
        ?int $ttlSeconds = null,
        ?int $now = null,
    ): IssuedToken;

    /**
     * Authenticate a raw `kgn_pat_<id>.<secret>` token using constant-time SHA-256 comparison,
     * enforce expiry, and update `lastUsedAt`. Returns `null` when invalid, revoked, or expired.
     */
    public function authenticate(#[SensitiveParameter] string $plainTextToken, ?int $now = null): ?PersonalAccessToken;

    /** @return list<PersonalAccessToken> */
    public function listForPrincipal(string $principalId): array;

    public function revoke(string $tokenId): bool;

    public function revokeAllForPrincipal(string $principalId): int;

    /**
     * Build a 1-line resolver closure for `new BearerAuthMiddleware($tokens->toBearerResolver())`.
     *
     * @return Closure(string): ?Principal
     */
    public function toBearerResolver(): Closure;
}
