<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Http\Cookie;
use Kongono\Security\Principal;
use Kongono\Security\PrincipalKind;
use SensitiveParameter;

/**
 * Split selector/validator persistent "Remember Me" cookie manager with automatic
 * single-use rotation and stolen-cookie replay theft detection.
 *
 * Cookie format: `<24-hex-selector>.<64-hex-validator>`
 *   - Selector indexes server-side storage without timing side-channels
 *   - Validator is stored ONLY as its SHA-256 hex digest and compared via `hash_equals()`
 *   - Replaying an already-rotated selector (or presenting a wrong validator) immediately
 *     revokes the entire login series so stolen cookies cannot be reused.
 */
final readonly class RememberMeManager
{
    public function __construct(
        private CacheInterface $cache,
        private string $cookieName = 'kongono_remember',
        private bool $secure = false,
        private string $sameSite = 'Lax',
        private string $prefix = 'kongono:remember:',
    ) {}

    public function cookieName(): string
    {
        return $this->cookieName;
    }

    /** Issue a fresh persistent remember-me cookie for `$principal`. */
    public function issue(Principal $principal, int $ttlSeconds = 2_592_000, ?int $now = null): Cookie
    {
        $series = bin2hex(random_bytes(16));

        return $this->issueInSeries($principal, $series, max(60, $ttlSeconds), $now ?? time());
    }

    /**
     * Verify a remember-me cookie value, atomically consume it, and return both the hydrated
     * {@see Principal} and a freshly rotated {@see Cookie}.
     *
     * Returns `null` on invalid, expired, or replayed cookies (and automatically revokes
     * the entire series when replay/theft is detected).
     *
     * @return array{principal: Principal, cookie: Cookie}|null
     */
    public function consumeAndRotate(#[SensitiveParameter] string $cookieValue, ?int $now = null): ?array
    {
        $parsed = self::parseCookieValue($cookieValue);
        if (null === $parsed) {
            return null;
        }

        $ts = $now ?? time();
        $selectorKey = $this->selectorKey($parsed['selector']);
        $raw = $this->cache instanceof AtomicCacheInterface
            ? $this->cache->pull($selectorKey)
            : $this->getAndDelete($selectorKey);

        if (!is_array($raw)) {
            // Replay theft detection: if this selector was previously rotated, revoke the active token in its series!
            $usedSeries = $this->cache->get($this->usedKey($parsed['selector']));
            if (is_string($usedSeries) && '' !== $usedSeries) {
                $this->revokeSeries($usedSeries);
                $this->cache->delete($this->usedKey($parsed['selector']));
            }

            return null;
        }

        $series = is_string($raw['series'] ?? null) ? $raw['series'] : '';
        $validatorHash = is_string($raw['validator_hash'] ?? null) ? $raw['validator_hash'] : '';
        $expiresAt = is_int($raw['expires_at'] ?? null) ? $raw['expires_at'] : 0;
        $ttl = is_int($raw['ttl'] ?? null) ? $raw['ttl'] : 2_592_000;

        if ('' === $series || '' === $validatorHash || $ts >= $expiresAt) {
            if ('' !== $series) {
                $this->revokeSeries($series);
            }

            return null;
        }

        if (!hash_equals($validatorHash, hash('sha256', $parsed['validator']))) {
            // Wrong validator for a real selector indicates cookie tampering / guessing -> revoke series
            $this->revokeSeries($series);

            return null;
        }

        $principal = self::hydratePrincipal($raw['principal'] ?? null);
        if (null === $principal) {
            $this->revokeSeries($series);

            return null;
        }

        // Remember the consumed selector so any future replay by a thief revokes the newly rotated token
        $remaining = max(60, $expiresAt - $ts);
        $this->cache->set($this->usedKey($parsed['selector']), $series, $remaining);

        $rotatedCookie = $this->issueInSeries($principal, $series, $ttl, $ts);

        return [
            'principal' => $principal,
            'cookie' => $rotatedCookie,
        ];
    }

    /** Revoke the token and its entire login series when a user explicitly logs out. */
    public function revokeCookie(#[SensitiveParameter] string $cookieValue): void
    {
        $parsed = self::parseCookieValue($cookieValue);
        if (null === $parsed) {
            return;
        }

        $selectorKey = $this->selectorKey($parsed['selector']);
        $raw = $this->cache->get($selectorKey);
        $this->cache->delete($selectorKey);
        if (is_array($raw) && is_string($raw['series'] ?? null)) {
            $this->revokeSeries($raw['series']);
        }
    }

    /** Build an expired cookie header to clear the remember-me cookie from the browser. */
    public function expiredCookie(): Cookie
    {
        return new Cookie(
            name: $this->cookieName,
            value: '',
            maxAge: 0,
            path: '/',
            secure: $this->secure,
            httpOnly: true,
            sameSite: $this->sameSite,
        );
    }

    private function issueInSeries(Principal $principal, string $series, int $ttlSeconds, int $now): Cookie
    {
        $selector = bin2hex(random_bytes(12));
        $validator = bin2hex(random_bytes(32));

        $this->cache->set($this->selectorKey($selector), [
            'series' => $series,
            'validator_hash' => hash('sha256', $validator),
            'expires_at' => $now + $ttlSeconds,
            'ttl' => $ttlSeconds,
            'principal' => [
                'id' => $principal->id,
                'kind' => $principal->kind->value,
                'capabilities' => $principal->capabilities,
                'attributes' => $principal->attributes,
            ],
        ], $ttlSeconds + 5);

        $this->cache->set($this->seriesKey($series), $selector, $ttlSeconds + 5);

        return new Cookie(
            name: $this->cookieName,
            value: $selector . '.' . $validator,
            maxAge: $ttlSeconds,
            path: '/',
            secure: $this->secure,
            httpOnly: true,
            sameSite: $this->sameSite,
        );
    }

    private function revokeSeries(string $series): void
    {
        $activeSelector = $this->cache->get($this->seriesKey($series));
        if (is_string($activeSelector) && '' !== $activeSelector) {
            $this->cache->delete($this->selectorKey($activeSelector));
        }
        $this->cache->delete($this->seriesKey($series));
    }

    private function getAndDelete(string $key): mixed
    {
        $val = $this->cache->get($key);
        $this->cache->delete($key);

        return $val;
    }

    /** @return array{selector: string, validator: string}|null */
    private static function parseCookieValue(string $value): ?array
    {
        if ('' === $value || strlen($value) > 256) {
            return null;
        }
        $parts = explode('.', $value, 2);
        if (2 !== count($parts)) {
            return null;
        }
        [$selector, $validator] = $parts;
        if (1 !== preg_match('/\A[a-f0-9]{24}\z/', $selector) || 1 !== preg_match('/\A[a-f0-9]{64}\z/', $validator)) {
            return null;
        }

        return ['selector' => $selector, 'validator' => $validator];
    }

    private static function hydratePrincipal(mixed $raw): ?Principal
    {
        if (!is_array($raw) || !is_string($raw['id'] ?? null) || '' === $raw['id']) {
            return null;
        }

        $kindVal = is_string($raw['kind'] ?? null) ? $raw['kind'] : PrincipalKind::Human->value;
        $kind = PrincipalKind::tryFrom($kindVal) ?? PrincipalKind::Human;

        /** @var list<string> $capabilities */
        $capabilities = [];
        if (is_array($raw['capabilities'] ?? null)) {
            foreach ($raw['capabilities'] as $cap) {
                if (is_string($cap) && '' !== $cap) {
                    $capabilities[] = $cap;
                }
            }
        }

        /** @var array<string, mixed> $attributes */
        $attributes = [];
        if (is_array($raw['attributes'] ?? null)) {
            foreach ($raw['attributes'] as $k => $v) {
                $attributes[(string) $k] = $v;
            }
        }

        return new Principal($raw['id'], $kind, $capabilities, $attributes);
    }

    private function selectorKey(string $selector): string
    {
        return $this->prefix . 'sel:' . $selector;
    }

    private function seriesKey(string $series): string
    {
        return $this->prefix . 'series:' . $series;
    }

    private function usedKey(string $selector): string
    {
        return $this->prefix . 'used:' . $selector;
    }
}
