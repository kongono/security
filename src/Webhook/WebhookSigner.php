<?php

declare(strict_types=1);

namespace Kongono\Security\Webhook;

use Kongono\Security\SecurityException;
use SensitiveParameter;

/**
 * Constant-time HMAC-SHA256 webhook signer & replay-window verifier (`t=<unix>,v1=<hex>`).
 */
final readonly class WebhookSigner
{
    public const string DEFAULT_HEADER = 'X-Kongono-Signature';

    public function __construct(
        #[SensitiveParameter]
        private string $secret,
    ) {
        if (strlen($secret) < 16) {
            throw new SecurityException('Webhook signing secret must be at least 16 bytes.');
        }
    }

    /** Sign a raw request body and return a `t=<timestamp>,v1=<hmac>` header value. */
    public function sign(string $payload, ?int $timestamp = null): string
    {
        $ts = $timestamp ?? time();
        $sig = hash_hmac('sha256', $ts . '.' . $payload, $this->secret);

        return sprintf('t=%d,v1=%s', $ts, $sig);
    }

    /** Verify a `t=<timestamp>,v1=<hmac>` header with replay-window enforcement. */
    public function verify(string $payload, string $signatureHeader, int $toleranceSeconds = 300, ?int $now = null): bool
    {
        $timestamp = null;
        $signatures = [];

        foreach (explode(',', $signatureHeader) as $part) {
            $kv = explode('=', trim($part), 2);
            if (2 !== count($kv)) {
                continue;
            }
            if ('t' === $kv[0] && ctype_digit($kv[1])) {
                $timestamp = (int) $kv[1];
            } elseif ('v1' === $kv[0] && '' !== $kv[1]) {
                $signatures[] = $kv[1];
            }
        }

        if (null === $timestamp || [] === $signatures) {
            return false;
        }

        $current = $now ?? time();
        if (abs($current - $timestamp) > max(1, $toleranceSeconds)) {
            return false;
        }

        $expected = hash_hmac('sha256', $timestamp . '.' . $payload, $this->secret);
        foreach ($signatures as $candidate) {
            if (hash_equals($expected, $candidate)) {
                return true;
            }
        }

        return false;
    }
}
