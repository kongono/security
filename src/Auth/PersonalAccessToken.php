<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Security\Principal;
use Kongono\Security\PrincipalKind;

/**
 * Immutable persisted metadata for a revocable Personal Access Token (Sanctum-equivalent).
 * Never holds the plaintext secret — only its SHA-256 hex digest.
 */
final readonly class PersonalAccessToken
{
    /**
     * @param list<string>         $capabilities
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        public string $id,
        public string $principalId,
        public PrincipalKind $principalKind,
        public string $name,
        public array $capabilities,
        public string $tokenHash,
        public int $createdAt,
        public ?int $expiresAt = null,
        public ?int $lastUsedAt = null,
        public array $attributes = [],
    ) {}

    public function isExpired(?int $now = null): bool
    {
        return null !== $this->expiresAt && ($now ?? time()) >= $this->expiresAt;
    }

    public function toPrincipal(): Principal
    {
        return new Principal(
            id: $this->principalId,
            kind: $this->principalKind,
            capabilities: $this->capabilities,
            attributes: [
                ...$this->attributes,
                '_token_id' => $this->id,
                '_token_name' => $this->name,
            ],
        );
    }

    public function withLastUsedAt(int $timestamp): self
    {
        return new self(
            id: $this->id,
            principalId: $this->principalId,
            principalKind: $this->principalKind,
            name: $this->name,
            capabilities: $this->capabilities,
            tokenHash: $this->tokenHash,
            createdAt: $this->createdAt,
            expiresAt: $this->expiresAt,
            lastUsedAt: $timestamp,
            attributes: $this->attributes,
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'principal_id' => $this->principalId,
            'principal_kind' => $this->principalKind->value,
            'name' => $this->name,
            'capabilities' => $this->capabilities,
            'token_hash' => $this->tokenHash,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'last_used_at' => $this->lastUsedAt,
            'attributes' => $this->attributes,
        ];
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): ?self
    {
        if (!is_string($data['id'] ?? null) || !is_string($data['principal_id'] ?? null) || !is_string($data['token_hash'] ?? null)) {
            return null;
        }

        $kindVal = is_string($data['principal_kind'] ?? null) ? $data['principal_kind'] : PrincipalKind::Human->value;
        $kind = PrincipalKind::tryFrom($kindVal) ?? PrincipalKind::Human;

        /** @var list<string> $capabilities */
        $capabilities = [];
        if (is_array($data['capabilities'] ?? null)) {
            foreach ($data['capabilities'] as $cap) {
                if (is_string($cap) && '' !== $cap) {
                    $capabilities[] = $cap;
                }
            }
        }

        /** @var array<string, mixed> $attributes */
        $attributes = [];
        if (is_array($data['attributes'] ?? null)) {
            foreach ($data['attributes'] as $k => $v) {
                $attributes[(string) $k] = $v;
            }
        }

        return new self(
            id: $data['id'],
            principalId: $data['principal_id'],
            principalKind: $kind,
            name: is_string($data['name'] ?? null) ? $data['name'] : '',
            capabilities: $capabilities,
            tokenHash: $data['token_hash'],
            createdAt: is_int($data['created_at'] ?? null) ? $data['created_at'] : 0,
            expiresAt: is_int($data['expires_at'] ?? null) ? $data['expires_at'] : null,
            lastUsedAt: is_int($data['last_used_at'] ?? null) ? $data['last_used_at'] : null,
            attributes: $attributes,
        );
    }

    /**
     * Parse a prefixed bearer token (`kgn_pat_<id>.<secret>`) without revealing timing info.
     *
     * @return array{id: string, secret: string}|null
     */
    public static function parsePlainText(string $plainTextToken): ?array
    {
        if (!str_starts_with($plainTextToken, 'kgn_pat_') || strlen($plainTextToken) > 256) {
            return null;
        }
        $body = substr($plainTextToken, 8);
        $parts = explode('.', $body, 2);
        if (2 !== count($parts)) {
            return null;
        }
        [$id, $secret] = $parts;
        if (1 !== preg_match('/\A[a-f0-9]{16,32}\z/', $id) || strlen($secret) < 32) {
            return null;
        }

        return ['id' => $id, 'secret' => $secret];
    }
}
