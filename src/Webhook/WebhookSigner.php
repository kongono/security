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
    private const int MAX_SIGNATURE_CANDIDATES = 5;
    private const int MAX_FUTURE_SKEW_SECONDS = 60;

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

    /** Verify a `t=<timestamp>,v1=<hmac>` header with strict parsing and replay-window enforcement. */
    public function verify(string $payload, string $signatureHeader, int $toleranceSeconds = 300, ?int $now = null): bool
    {
        return null !== $this->verifyAndFingerprint($payload, $signatureHeader, $toleranceSeconds, $now);
    }

    /**
     * Verify a webhook signature and return a deterministic SHA-256 replay-deduplication fingerprint,
     * or null if verification fails.
     */
    public function verifyAndFingerprint(string $payload, string $signatureHeader, int $toleranceSeconds = 300, ?int $now = null): ?string
    {
        if ('' === $signatureHeader || strlen($signatureHeader) > 2048) {
            return null;
        }

        $timestamp = null;
        $signatures = [];

        foreach (explode(',', $signatureHeader) as $part) {
            $kv = explode('=', trim($part), 2);
            if (2 !== count($kv)) {
                continue;
            }
            if ('t' === $kv[0]) {
                // Reject duplicate or non-numeric timestamps to prevent parser ambiguity
                if (null !== $timestamp || !ctype_digit($kv[1])) {
                    return null;
                }
                $timestamp = (int) $kv[1];
            } elseif ('v1' === $kv[0]) {
                if (count($signatures) >= self::MAX_SIGNATURE_CANDIDATES) {
                    return null;
                }
                if (64 === strlen($kv[1]) && ctype_xdigit($kv[1])) {
                    $signatures[] = strtolower($kv[1]);
                }
            }
        }

        if (null === $timestamp || [] === $signatures) {
            return null;
        }

        $current = $now ?? time();
        $maxPast = max(1, $toleranceSeconds);
        $maxFuture = min(self::MAX_FUTURE_SKEW_SECONDS, $maxPast);
        if (($current - $timestamp) > $maxPast || ($timestamp - $current) > $maxFuture) {
            return null;
        }

        $expected = hash_hmac('sha256', $timestamp . '.' . $payload, $this->secret);
        foreach ($signatures as $candidate) {
            if (hash_equals($expected, $candidate)) {
                return hash('sha256', $timestamp . ':' . $expected);
            }
        }

        return null;
    }
}
