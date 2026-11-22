<?php

declare(strict_types=1);

namespace Kongono\Security;

use JsonException;
use SensitiveParameter;

/** Constant-time HMAC-SHA256 stateless signed token & CSRF token generator/verifier. */
final readonly class TokenSigner
{
    public const int MAX_TOKEN_BYTES = 16_384;

    public function __construct(
        #[SensitiveParameter]
        private string $secretKey,
    ) {
        if (strlen($secretKey) < 16) {
            throw new SecurityException('TokenSigner secret key must be at least 16 bytes.');
        }
    }

    /**
     * Sign a payload array with an explicit expiration timestamp (Unix seconds).
     *
     * @param array<string, mixed> $claims
     */
    public function sign(array $claims, int $ttlSeconds = 3600, ?int $now = null): string
    {
        $issuedAt = $now ?? time();
        $envelope = [
            'iat' => $issuedAt,
            'exp' => $issuedAt + max(1, $ttlSeconds),
            'claims' => $claims,
        ];
        $encoded = $this->base64UrlEncode(json_encode($envelope, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        $sig = $this->base64UrlEncode(hash_hmac('sha256', $encoded, $this->secretKey, true));

        return $encoded . '.' . $sig;
    }

    /**
     * Verify a signed token and return its claims, or null if invalid or expired.
     *
     * @return array<string, mixed>|null
     */
    public function verify(#[SensitiveParameter] string $token, ?int $now = null): ?array
    {
        if ('' === $token || strlen($token) > self::MAX_TOKEN_BYTES) {
            return null;
        }
        $parts = explode('.', $token);
        if (2 !== count($parts)) {
            return null;
        }
        [$encoded, $signature] = $parts;
        $expected = $this->base64UrlEncode(hash_hmac('sha256', $encoded, $this->secretKey, true));
        if (!hash_equals($expected, $signature)) {
            return null;
        }

        $json = $this->base64UrlDecode($encoded);
        if (null === $json) {
            return null;
        }

        try {
            $envelope = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!is_array($envelope) || !is_int($envelope['exp'] ?? null) || !is_array($envelope['claims'] ?? null)) {
            return null;
        }

        $current = $now ?? time();
        if ($current >= $envelope['exp']) {
            return null;
        }

        /** @var array<string, mixed> $claims */
        $claims = [];
        foreach ($envelope['claims'] as $k => $v) {
            $claims[(string) $k] = $v;
        }

        return $claims;
    }

    public function generateCsrfToken(string $sessionContext, int $ttlSeconds = 7200, ?int $now = null): string
    {
        return $this->sign([
            'purpose' => 'csrf',
            'ctx' => hash('sha256', $sessionContext),
            'nonce' => bin2hex(random_bytes(16)),
        ], $ttlSeconds, $now);
    }

    public function verifyCsrfToken(#[SensitiveParameter] string $token, string $sessionContext, ?int $now = null): bool
    {
        $claims = $this->verify($token, $now);
        if (null === $claims || 'csrf' !== ($claims['purpose'] ?? null) || !is_string($claims['ctx'] ?? null)) {
            return false;
        }

        return hash_equals(hash('sha256', $sessionContext), $claims['ctx']);
    }

    private function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $encoded): ?string
    {
        $padded = strtr($encoded, '-_', '+/');
        $rem = strlen($padded) % 4;
        if (0 !== $rem) {
            $padded .= str_repeat('=', 4 - $rem);
        }
        $decoded = base64_decode($padded, true);

        return false === $decoded ? null : $decoded;
    }
}
