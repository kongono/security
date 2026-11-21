<?php

declare(strict_types=1);

namespace Kongono\Security;

use SensitiveParameter;

/** HMAC-SHA256 signed & expiring URL generator/verifier (email verification, downloads, magic links). */
final readonly class SignedUrl
{
    public function __construct(
        #[SensitiveParameter]
        private string $secretKey,
    ) {
        if (strlen($secretKey) < 16) {
            throw new SecurityException('SignedUrl secret key must be at least 16 bytes.');
        }
    }

    /**
     * Create a temporary signed URL valid for $ttlSeconds.
     *
     * @param array<string, string|int> $query
     */
    public function temporary(string $path, int $ttlSeconds = 900, array $query = [], ?int $now = null): string
    {
        $query['expires'] = (string) (($now ?? time()) + max(1, $ttlSeconds));

        return $this->sign($path, $query);
    }

    /**
     * Create a non-expiring signed URL.
     *
     * @param array<string, string|int> $query
     */
    public function sign(string $path, array $query = []): string
    {
        unset($query['signature']);
        ksort($query, SORT_STRING);
        $base = $path . ([] !== $query ? '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986) : '');
        $signature = hash_hmac('sha256', $base, $this->secretKey);
        $query['signature'] = $signature;

        return $path . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    /** Verify a signed URL string (checks constant-time HMAC and optional expiration). */
    public function verify(string $signedUrl, ?int $now = null): bool
    {
        $parts = parse_url($signedUrl);
        if (false === $parts || !isset($parts['path'], $parts['query'])) {
            return false;
        }
        parse_str($parts['query'], $params);
        $signature = $params['signature'] ?? null;
        if (!is_string($signature) || '' === $signature) {
            return false;
        }

        if (isset($params['expires'])) {
            if (!is_string($params['expires']) || !ctype_digit($params['expires'])) {
                return false;
            }
            if (($now ?? time()) >= (int) $params['expires']) {
                return false;
            }
        }

        unset($params['signature']);
        ksort($params, SORT_STRING);
        $base = $parts['path'] . ([] !== $params ? '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986) : '');
        $expected = hash_hmac('sha256', $base, $this->secretKey);

        return hash_equals($expected, $signature);
    }
}
