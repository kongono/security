<?php

declare(strict_types=1);

namespace Kongono\Security\Egress;

use Closure;
use Kongono\Security\SecurityException;

/**
 * Instance-scoped fake responder and request recorder for {@see SafeHttpClient}.
 *
 * Unlike static global HTTP fakes, `SafeHttpFake` holds zero static state, stays 100%
 * persistent-runtime and parallel-test safe, and still runs full `SafeHttpClient::admitTarget()`
 * SSRF validation before returning stubbed responses.
 */
final class SafeHttpFake
{
    /**
     * @var array<string, array{status: int, body: string}|Closure(string, string, array<string, string>, ?string): array{status: int, body: string}>|Closure(string, string, array<string, string>, ?string): array{status: int, body: string}
     */
    private readonly array|Closure $stubs;

    /** @var list<array{method: string, url: string, headers: array<string, string>, body: ?string, status: int}> */
    private array $recorded = [];

    /**
     * @param array<string, array{status: int, body: string}|Closure(string, string, array<string, string>, ?string): array{status: int, body: string}>|Closure(string, string, array<string, string>, ?string): array{status: int, body: string} $stubs
     */
    public function __construct(
        array|Closure $stubs = [],
        private readonly bool $preventStrayRequests = true,
    ) {
        $this->stubs = $stubs;
    }

    /** @return array{status: int, body: string} */
    public static function response(string $body = '', int $status = 200): array
    {
        return ['status' => $status, 'body' => $body];
    }

    /** @return array{status: int, body: string} */
    public static function json(mixed $payload, int $status = 200): array
    {
        return [
            'status' => $status,
            'body' => json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
        ];
    }

    /**
     * Resolve a stubbed response for an already SSRF-admitted outbound request and record it.
     *
     * @param array<string, string> $headers
     * @return array{status: int, body: string}
     */
    public function respond(string $method, string $url, array $headers = [], ?string $body = null): array
    {
        $resolved = $this->matchStub($method, $url, $headers, $body);
        if (null === $resolved) {
            if ($this->preventStrayRequests) {
                throw new SecurityException(sprintf(
                    'Stray outbound HTTP request blocked by SafeHttpFake: %s %s',
                    $method,
                    $url,
                ));
            }
            $resolved = ['status' => 200, 'body' => ''];
        }

        $this->recorded[] = [
            'method' => $method,
            'url' => $url,
            'headers' => $headers,
            'body' => $body,
            'status' => $resolved['status'],
        ];

        return $resolved;
    }

    /** @return list<array{method: string, url: string, headers: array<string, string>, body: ?string, status: int}> */
    public function recorded(): array
    {
        return $this->recorded;
    }

    public function reset(): void
    {
        $this->recorded = [];
    }

    /**
     * Assert that at least one (or exactly `$times`) outbound request matched `$matcher`
     * (either a URL/method+URL wildcard pattern such as `'POST https://api.stripe.com/*'`
     * or a predicate `Closure(array): bool`).
     *
     * @param string|Closure(array{method: string, url: string, headers: array<string, string>, body: ?string, status: int}): bool $matcher
     */
    public function assertSent(string|Closure $matcher, ?int $times = null): self
    {
        $matches = 0;
        foreach ($this->recorded as $entry) {
            $hit = $matcher instanceof Closure
                ? $matcher($entry)
                : self::matchesPattern($matcher, $entry['method'], $entry['url']);
            if ($hit) {
                ++$matches;
            }
        }

        if (null === $times) {
            if ($matches < 1) {
                throw new SecurityException(sprintf(
                    'Expected outbound HTTP request matching %s to be sent, but none were recorded (%d total).',
                    is_string($matcher) ? '"' . $matcher . '"' : 'predicate',
                    count($this->recorded),
                ));
            }
        } elseif ($matches !== $times) {
            throw new SecurityException(sprintf(
                'Expected outbound HTTP request matching %s to be sent %d time(s), got %d.',
                is_string($matcher) ? '"' . $matcher . '"' : 'predicate',
                $times,
                $matches,
            ));
        }

        return $this;
    }

    public function assertNothingSent(): self
    {
        if ([] !== $this->recorded) {
            throw new SecurityException(sprintf(
                'Expected zero outbound HTTP requests, but %d request(s) were recorded.',
                count($this->recorded),
            ));
        }

        return $this;
    }

    public function assertSentCount(int $expected): self
    {
        $actual = count($this->recorded);
        if ($actual !== $expected) {
            throw new SecurityException(sprintf(
                'Expected %d outbound HTTP request(s), got %d.',
                $expected,
                $actual,
            ));
        }

        return $this;
    }

    /**
     * @param array<string, string> $headers
     * @return ?array{status: int, body: string}
     */
    private function matchStub(string $method, string $url, array $headers, ?string $body): ?array
    {
        if ($this->stubs instanceof Closure) {
            return ($this->stubs)($method, $url, $headers, $body);
        }

        foreach ($this->stubs as $pattern => $handler) {
            if (self::matchesPattern($pattern, $method, $url)) {
                return $handler instanceof Closure
                    ? $handler($method, $url, $headers, $body)
                    : $handler;
            }
        }

        return null;
    }

    private static function matchesPattern(string $pattern, string $method, string $url): bool
    {
        $trimmed = trim($pattern);
        if ('*' === $trimmed) {
            return true;
        }

        $target = $url;
        if (1 === preg_match('/\A([A-Z]+)\s+(.+)\z/', $trimmed, $m)) {
            if (strtoupper($method) !== $m[1]) {
                return false;
            }
            $trimmed = trim($m[2]);
        }

        $regex = '/\A' . str_replace('\*', '.*', preg_quote($trimmed, '/')) . '\z/';

        return 1 === preg_match($regex, $target);
    }
}
