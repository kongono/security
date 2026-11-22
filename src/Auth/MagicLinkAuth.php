<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Core\Cache\CacheInterface;
use Kongono\Security\SecurityException;
use Kongono\Security\SignedUrl;
use SensitiveParameter;

/**
 * Passwordless, single-use, HMAC-signed Magic Link authentication.
 *
 * Combines expiring SignedUrl verification with single-use CacheInterface nonce
 * consumption so every magic link works exactly once and fails closed on replay or tampering.
 */
final readonly class MagicLinkAuth
{
    private SignedUrl $signer;

    public function __construct(
        #[SensitiveParameter]
        string $secretKey,
        private CacheInterface $cache,
        private string $cachePrefix = 'kongono:magic_link:',
    ) {
        $this->signer = new SignedUrl($secretKey);
    }

    /**
     * Issue a single-use expiring magic link path+query (e.g. `/auth/magic?nonce=...&expires=...&signature=...`).
     *
     * @param array<string, mixed> $claims Optional metadata stored server-side for this login token
     */
    public function createLink(
        string $path,
        string $email,
        int $ttlSeconds = 900,
        array $claims = [],
        ?int $now = null,
    ): string {
        $normalizedEmail = strtolower(trim($email));
        if ('' === $normalizedEmail || false === filter_var($normalizedEmail, FILTER_VALIDATE_EMAIL)) {
            throw new SecurityException('Magic link requires a valid email address.');
        }

        $ttl = max(30, $ttlSeconds);
        $nonce = bin2hex(random_bytes(24));
        $payload = [
            'email' => $normalizedEmail,
            'claims' => $claims,
        ];
        $this->cache->set(
            $this->cachePrefix . hash('sha256', $nonce),
            json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            $ttl + 5,
        );

        return $this->signer->temporary($path, $ttl, ['nonce' => $nonce], $now);
    }

    /**
     * Verify and atomically consume a single-use magic link.
     *
     * @return array{email: string, claims: array<string, mixed>}
     */
    public function consume(string $signedPathWithQuery, ?int $now = null): array
    {
        if (!$this->signer->verify($signedPathWithQuery, $now)) {
            throw new SecurityException('Magic link signature is invalid or expired.');
        }

        $parts = parse_url($signedPathWithQuery);
        if (false === $parts || !isset($parts['query'])) {
            throw new SecurityException('Magic link is missing query parameters.');
        }
        parse_str($parts['query'], $params);
        $nonce = $params['nonce'] ?? null;
        if (!is_string($nonce) || '' === $nonce) {
            throw new SecurityException('Magic link nonce is missing.');
        }

        $cacheKey = $this->cachePrefix . hash('sha256', $nonce);
        $raw = $this->cache->get($cacheKey);
        if (!is_string($raw) || '' === $raw) {
            throw new SecurityException('Magic link has already been consumed or expired.');
        }

        // Single-use: invalidate immediately before returning
        $this->cache->delete($cacheKey);

        $decoded = json_decode($raw, true);
        if (!is_array($decoded) || !is_string($decoded['email'] ?? null)) {
            throw new SecurityException('Stored magic link payload is corrupted.');
        }

        /** @var array<string, mixed> $claims */
        $claims = is_array($decoded['claims'] ?? null) ? $decoded['claims'] : [];

        return [
            'email' => $decoded['email'],
            'claims' => $claims,
        ];
    }
}
