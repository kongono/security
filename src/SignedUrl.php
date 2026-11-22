<?php

declare(strict_types=1);

namespace Kongono\Security;

use SensitiveParameter;

/** HMAC-SHA256 signed & expiring URL generator/verifier (email verification, downloads, magic links). */
final readonly class SignedUrl
{
    private const int MAX_QUERY_PARAMS = 100;

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
        if (1 === preg_match('/[\x00-\x1f\x7f#]/', $path)) {
            throw new SecurityException('SignedUrl path cannot contain control characters or fragments.');
        }

        unset($query['signature']);
        /** @var array<string, string> $normalized */
        $normalized = [];
        foreach ($query as $k => $v) {
            if ('' === $k || str_contains($k, '[') || str_contains($k, ']')) {
                throw new SecurityException(sprintf('Invalid SignedUrl query key "%s".', $k));
            }
            $normalized[$k] = (string) $v;
        }
        ksort($normalized, SORT_STRING);

        $canonicalTarget = $this->canonicalTarget($path);
        $canonicalQuery = $this->encodeQuery($normalized);
        $base = $canonicalTarget . ('' !== $canonicalQuery ? '?' . $canonicalQuery : '');
        $signature = hash_hmac('sha256', $base, $this->secretKey);
        $normalized['signature'] = $signature;

        return $canonicalTarget . '?' . $this->encodeQuery($normalized);
    }

    /** Verify a signed URL string (strict canonical query parsing — immune to parse_str HPP & max_input_vars smuggling). */
    public function verify(string $signedUrl, ?int $now = null): bool
    {
        if ('' === $signedUrl || 1 === preg_match('/[\x00-\x1f\x7f]/', $signedUrl)) {
            return false;
        }

        $parts = parse_url($signedUrl);
        if (
            false === $parts
            || !isset($parts['path'], $parts['query'])
            || isset($parts['fragment'])
            || isset($parts['user'])
            || isset($parts['pass'])
        ) {
            return false;
        }

        $params = self::parseStrictQuery($parts['query']);
        if (null === $params) {
            return false;
        }

        $signature = $params['signature'] ?? null;
        if (!is_string($signature) || 64 !== strlen($signature) || !ctype_xdigit($signature)) {
            return false;
        }

        if (isset($params['expires'])) {
            if (!ctype_digit($params['expires'])) {
                return false;
            }
            if (($now ?? time()) >= (int) $params['expires']) {
                return false;
            }
        }

        unset($params['signature']);
        ksort($params, SORT_STRING);

        $target = '';
        if (isset($parts['scheme']) || isset($parts['host'])) {
            if (!isset($parts['scheme'], $parts['host'])) {
                return false;
            }
            $target = strtolower($parts['scheme']) . '://' . strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '');
        }
        $target .= $parts['path'];

        $canonicalQuery = $this->encodeQuery($params);
        $base = $target . ('' !== $canonicalQuery ? '?' . $canonicalQuery : '');
        $expected = hash_hmac('sha256', $base, $this->secretKey);

        return hash_equals($expected, $signature);
    }

    /**
     * Strictly parse a query string without PHP's parse_str() quirks (no duplicate keys, no dot/space mangling, no max_input_vars truncation).
     *
     * @return array<string, string>|null
     */
    public static function parseStrictQuery(string $query): ?array
    {
        if ('' === $query) {
            return [];
        }

        $pairs = explode('&', $query);
        if (count($pairs) > self::MAX_QUERY_PARAMS) {
            return null;
        }

        $params = [];
        foreach ($pairs as $pair) {
            if ('' === $pair) {
                return null;
            }
            $eqPos = strpos($pair, '=');
            if (false === $eqPos || 0 === $eqPos) {
                return null;
            }
            $rawKey = substr($pair, 0, $eqPos);
            $rawVal = substr($pair, $eqPos + 1);
            $key = rawurldecode($rawKey);
            $val = rawurldecode($rawVal);

            if (
                '' === trim($key)
                || str_contains($key, '[')
                || str_contains($key, ']')
                || array_key_exists($key, $params)
                || rawurlencode($key) !== $rawKey
                || rawurlencode($val) !== $rawVal
            ) {
                return null;
            }
            $params[$key] = $val;
        }

        return $params;
    }

    private function canonicalTarget(string $path): string
    {
        $parts = parse_url($path);
        if (false === $parts || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new SecurityException('Invalid SignedUrl target path.');
        }

        $target = '';
        if (isset($parts['scheme'], $parts['host'])) {
            $target = strtolower($parts['scheme']) . '://' . strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '');
        }
        $target .= $parts['path'] ?? '/';

        return $target;
    }

    /** @param array<string, string> $params */
    private function encodeQuery(array $params): string
    {
        if ([] === $params) {
            return '';
        }
        $pairs = [];
        foreach ($params as $k => $v) {
            $pairs[] = rawurlencode($k) . '=' . rawurlencode($v);
        }

        return implode('&', $pairs);
    }
}
