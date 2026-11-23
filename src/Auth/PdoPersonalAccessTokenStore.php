<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Closure;
use Kongono\Database\ConnectionInterface;
use Kongono\Security\Principal;
use Kongono\Security\PrincipalKind;
use Kongono\Security\SecurityException;
use SensitiveParameter;

/**
 * Persistent SQL Personal Access Token store (PostgreSQL, SQLite, MySQL) storing only
 * SHA-256 token digests with `last_used_at` tracking and instant per-token or per-principal revocation.
 */
final readonly class PdoPersonalAccessTokenStore implements PersonalAccessTokenStoreInterface
{
    public function __construct(
        private ConnectionInterface $db,
        private string $table = 'kongono_access_tokens',
    ) {}

    public function installSchema(): void
    {
        $t = $this->db->dialect()->quoteIdentifier($this->table);
        $this->db->execute(sprintf(
            'CREATE TABLE IF NOT EXISTS %s ('
            . 'id VARCHAR(64) PRIMARY KEY, '
            . 'principal_id VARCHAR(192) NOT NULL, '
            . 'principal_kind VARCHAR(32) NOT NULL, '
            . 'name VARCHAR(192) NOT NULL, '
            . 'capabilities TEXT NOT NULL, '
            . 'token_hash VARCHAR(64) NOT NULL, '
            . 'attributes TEXT NOT NULL, '
            . 'created_at BIGINT NOT NULL, '
            . 'expires_at BIGINT, '
            . 'last_used_at BIGINT'
            . ')',
            $t,
        ));
    }

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
        $caps = $capabilities ?? $principal->capabilities;
        $hash = hash('sha256', $secret);
        $expiresAt = null !== $ttlSeconds ? $ts + max(1, $ttlSeconds) : null;

        $this->db->table($this->table)->insert([
            'id' => $id,
            'principal_id' => $principal->id,
            'principal_kind' => $principal->kind->value,
            'name' => $cleanName,
            'capabilities' => json_encode($caps, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'token_hash' => $hash,
            'attributes' => json_encode($principal->attributes, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'created_at' => $ts,
            'expires_at' => $expiresAt,
            'last_used_at' => null,
        ]);

        $record = new PersonalAccessToken(
            id: $id,
            principalId: $principal->id,
            principalKind: $principal->kind,
            name: $cleanName,
            capabilities: $caps,
            tokenHash: $hash,
            createdAt: $ts,
            expiresAt: $expiresAt,
            lastUsedAt: null,
            attributes: $principal->attributes,
        );

        return new IssuedToken('kgn_pat_' . $id . '.' . $secret, $record);
    }

    public function authenticate(#[SensitiveParameter] string $plainTextToken, ?int $now = null): ?PersonalAccessToken
    {
        $parsed = PersonalAccessToken::parsePlainText($plainTextToken);
        if (null === $parsed) {
            return null;
        }

        $row = $this->db->table($this->table)->where('id', '=', $parsed['id'])->first();
        if (null === $row) {
            return null;
        }

        $record = $this->hydrateRow($row);
        if (null === $record || !hash_equals($record->tokenHash, hash('sha256', $parsed['secret']))) {
            return null;
        }

        $ts = $now ?? time();
        if ($record->isExpired($ts)) {
            $this->revoke($record->id);

            return null;
        }

        $this->db->table($this->table)
            ->where('id', '=', $record->id)
            ->update(['last_used_at' => $ts]);

        return $record->withLastUsedAt($ts);
    }

    public function listForPrincipal(string $principalId): array
    {
        $rows = $this->db->table($this->table)
            ->where('principal_id', '=', $principalId)
            ->orderBy('created_at', 'DESC')
            ->get();

        $out = [];
        foreach ($rows as $row) {
            $hydrated = $this->hydrateRow($row);
            if (null !== $hydrated) {
                $out[] = $hydrated;
            }
        }

        return $out;
    }

    public function revoke(string $tokenId): bool
    {
        return $this->db->table($this->table)->where('id', '=', $tokenId)->delete() > 0;
    }

    public function revokeAllForPrincipal(string $principalId): int
    {
        return $this->db->table($this->table)->where('principal_id', '=', $principalId)->delete();
    }

    public function toBearerResolver(): Closure
    {
        return fn(string $token): ?Principal => $this->authenticate($token)?->toPrincipal();
    }

    /** @param array<string, mixed> $row */
    private function hydrateRow(array $row): ?PersonalAccessToken
    {
        if (!is_string($row['id'] ?? null) || !is_string($row['principal_id'] ?? null) || !is_string($row['token_hash'] ?? null)) {
            return null;
        }

        $kindVal = is_string($row['principal_kind'] ?? null) ? $row['principal_kind'] : PrincipalKind::Human->value;
        $kind = PrincipalKind::tryFrom($kindVal) ?? PrincipalKind::Human;

        $rawCaps = is_string($row['capabilities'] ?? null) ? json_decode($row['capabilities'], true) : [];
        /** @var list<string> $capabilities */
        $capabilities = [];
        if (is_array($rawCaps)) {
            foreach ($rawCaps as $cap) {
                if (is_string($cap) && '' !== $cap) {
                    $capabilities[] = $cap;
                }
            }
        }

        $rawAttrs = is_string($row['attributes'] ?? null) ? json_decode($row['attributes'], true) : [];
        /** @var array<string, mixed> $attributes */
        $attributes = [];
        if (is_array($rawAttrs)) {
            foreach ($rawAttrs as $k => $v) {
                $attributes[(string) $k] = $v;
            }
        }

        return new PersonalAccessToken(
            id: $row['id'],
            principalId: $row['principal_id'],
            principalKind: $kind,
            name: is_string($row['name'] ?? null) ? $row['name'] : '',
            capabilities: $capabilities,
            tokenHash: $row['token_hash'],
            createdAt: is_numeric($row['created_at'] ?? null) ? (int) $row['created_at'] : 0,
            expiresAt: is_numeric($row['expires_at'] ?? null) ? (int) $row['expires_at'] : null,
            lastUsedAt: is_numeric($row['last_used_at'] ?? null) ? (int) $row['last_used_at'] : null,
            attributes: $attributes,
        );
    }
}
