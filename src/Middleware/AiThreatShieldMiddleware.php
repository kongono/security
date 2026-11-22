<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Closure;
use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Http\HttpException;
use Kongono\Http\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Autonomous AI-hacker & automated recon defense middleware.
 *
 * Defends persistent-runtime Kongono apps with:
 * - Zero-trust IP ban enforcement backed by any CacheInterface
 * - Configurable recon honeypot trap paths (/.env, /wp-login.php, /actuator/env, etc.)
 * - Hidden form honeypot field trap (catches blind form-filling bots)
 * - 404/401/405 reconnaissance burst auto-banning
 * - Cost-aware compute/AI budget limiting per client window
 */
final readonly class AiThreatShieldMiddleware implements MiddlewareInterface
{
    /** @var list<string> */
    public const array DEFAULT_HONEYPOT_PATHS = [
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.git/config',
        '/wp-login.php',
        '/wp-admin',
        '/xmlrpc.php',
        '/phpinfo.php',
        '/actuator/env',
        '/config.php.bak',
        '/server-status',
    ];

    /**
     * @param list<string>                                   $honeypotPaths
     * @param (Closure(ServerRequestInterface): string)|null $clientResolver
     */
    public function __construct(
        private CacheInterface $cache,
        private array $honeypotPaths = self::DEFAULT_HONEYPOT_PATHS,
        private ?string $honeypotField = '_hp_website',
        private int $banSeconds = 900,
        private int $maxProbesPerWindow = 15,
        private int $probeWindowSeconds = 60,
        private int $maxCostUnitsPerWindow = 0,
        private int $costWindowSeconds = 60,
        private ?Closure $clientResolver = null,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $clientId = $this->resolveClient($request);

        if ($this->isBanned($clientId)) {
            return $this->blockedResponse('blocked', 'Access denied by Kongono AI Threat Shield.');
        }

        $normalizedPath = $this->canonicalizePath($request->getUri()->getPath());
        if ($this->matchesHoneypotPath($normalizedPath)) {
            $this->ban($clientId, 'honeypot_path:' . $normalizedPath);

            return $this->blockedResponse('honeypot-triggered', 'Forbidden.');
        }

        if (null !== $this->honeypotField && '' !== $this->honeypotField && $this->hasTriggeredHoneypotField($request, $this->honeypotField)) {
            $this->ban($clientId, 'honeypot_field:' . $this->honeypotField);

            return $this->blockedResponse('honeypot-field', 'Forbidden.');
        }

        if ($this->maxCostUnitsPerWindow > 0 && $this->currentCostUnits($clientId) >= $this->maxCostUnitsPerWindow) {
            return Response::json([
                'error' => [
                    'code' => 'KGN-SHIELD-BUDGET-429',
                    'message' => 'Compute budget exceeded for this window.',
                ],
            ], 429, [
                'Retry-After' => (string) $this->costWindowSeconds,
                'X-Kongono-Shield' => 'budget-exceeded',
            ]);
        }

        try {
            $response = $handler->handle($request);
        } catch (HttpException $e) {
            if ($this->maxProbesPerWindow > 0 && (401 === $e->statusCode || 404 === $e->statusCode || 405 === $e->statusCode)) {
                $probes = $this->incrementProbes($clientId);
                if ($probes >= $this->maxProbesPerWindow) {
                    $this->ban($clientId, 'recon_burst');
                }
            }
            throw $e;
        }

        $status = $response->getStatusCode();
        if ($this->maxProbesPerWindow > 0 && (401 === $status || 404 === $status || 405 === $status)) {
            $probes = $this->incrementProbes($clientId);
            if ($probes >= $this->maxProbesPerWindow) {
                $this->ban($clientId, 'recon_burst');
            }
        }

        return $response->withHeader('X-Kongono-Shield', 'active');
    }

    public function isBanned(string $clientId): bool
    {
        return null !== $this->cache->get($this->banKey($clientId));
    }

    public function ban(string $clientId, string $reason = 'manual'): void
    {
        $this->cache->set($this->banKey($clientId), $reason, max(1, $this->banSeconds));
    }

    public function unban(string $clientId): void
    {
        $this->cache->delete($this->banKey($clientId));
    }

    /**
     * Record weighted cost units (e.g. LLM tokens, heavy PDF renders, expensive queries)
     * against a client identifier for the current budget window.
     */
    public function recordCostUnits(string $clientId, int $units): int
    {
        $key = $this->costKey($clientId);
        $delta = max(0, $units);
        $ttl = max(1, $this->costWindowSeconds) + 1;
        if ($this->cache instanceof AtomicCacheInterface) {
            return $this->cache->increment($key, $delta, $ttl);
        }

        $raw = $this->cache->get($key, 0);
        $current = is_int($raw) ? $raw : 0;
        $updated = $current + $delta;
        $this->cache->set($key, $updated, $ttl);

        return $updated;
    }

    public function currentCostUnits(string $clientId): int
    {
        $raw = $this->cache->get($this->costKey($clientId), 0);

        return is_int($raw) ? $raw : 0;
    }

    private function matchesHoneypotPath(string $normalizedPath): bool
    {
        foreach ($this->honeypotPaths as $trap) {
            $canonicalTrap = $this->canonicalizePath($trap);
            if ('/' === $canonicalTrap) {
                continue;
            }
            if ($normalizedPath === $canonicalTrap || str_starts_with($normalizedPath, $canonicalTrap . '/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Canonicalize request paths before honeypot matching to defeat evasion via
     * `//.env`, `/../.env`, `/foo/../.env`, `/%2e%2e/.env`, `\.env`, `/.env;foo`, or trailing dots.
     */
    private function canonicalizePath(string $rawPath): string
    {
        $decoded = $rawPath;
        for ($i = 0; $i < 2; ++$i) {
            $next = rawurldecode($decoded);
            if ($next === $decoded) {
                break;
            }
            $decoded = $next;
        }
        $decoded = str_replace(["\0", '\\'], ['', '/'], $decoded);
        $collapsed = (string) preg_replace('#/+#', '/', '/' . ltrim($decoded, '/'));
        $segments = [];
        foreach (explode('/', $collapsed) as $seg) {
            // Strip RFC 3986 matrix parameters (e.g. /.env;foo=bar)
            $semi = strpos($seg, ';');
            if (false !== $semi) {
                $seg = substr($seg, 0, $semi);
            }
            if ('' === $seg || '.' === $seg) {
                continue;
            }
            if ('..' === $seg) {
                array_pop($segments);
                continue;
            }
            $cleaned = rtrim($seg, '. ');
            if ('' === $cleaned) {
                continue;
            }
            $segments[] = $cleaned;
        }

        return '/' . strtolower(implode('/', $segments));
    }

    private function hasTriggeredHoneypotField(ServerRequestInterface $request, string $field): bool
    {
        $method = strtoupper($request->getMethod());
        if (!in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            return false;
        }
        $parsed = $request->getParsedBody();
        if (is_array($parsed) && array_key_exists($field, $parsed)) {
            $value = $parsed[$field];

            return is_string($value) ? '' !== trim($value) : null !== $value && false !== $value;
        }

        // Also inspect JSON payloads so bot JSON POSTs cannot bypass the honeypot field check
        if (str_contains(strtolower($request->getHeaderLine('Content-Type')), 'application/json')) {
            $stream = $request->getBody();
            $size = $stream->getSize();
            if (null === $size || $size <= 1_048_576) {
                $raw = (string) $stream;
                if ($stream->isSeekable()) {
                    $stream->rewind();
                }
                if ('' !== $raw && strlen($raw) <= 1_048_576) {
                    $decoded = json_decode($raw, true);
                    if (is_array($decoded) && array_key_exists($field, $decoded)) {
                        $value = $decoded[$field];

                        return is_string($value) ? '' !== trim($value) : null !== $value && false !== $value;
                    }
                }
            }
        }

        return false;
    }

    private function incrementProbes(string $clientId): int
    {
        $window = max(1, $this->probeWindowSeconds);
        $bucket = (int) floor(time() / $window);
        $key = sprintf('threat_shield:probes:%s:%d', hash('sha256', $clientId), $bucket);
        if ($this->cache instanceof AtomicCacheInterface) {
            return $this->cache->increment($key, 1, $window + 1);
        }

        $raw = $this->cache->get($key, 0);
        $next = (is_int($raw) ? $raw : 0) + 1;
        $this->cache->set($key, $next, $window + 1);

        return $next;
    }

    private function resolveClient(ServerRequestInterface $request): string
    {
        if (null !== $this->clientResolver) {
            return ($this->clientResolver)($request);
        }

        $server = $request->getServerParams();

        return is_string($server['REMOTE_ADDR'] ?? null) && '' !== $server['REMOTE_ADDR']
            ? $server['REMOTE_ADDR']
            : 'local';
    }

    private function banKey(string $clientId): string
    {
        return 'threat_shield:ban:' . hash('sha256', $clientId);
    }

    private function costKey(string $clientId): string
    {
        $bucket = (int) floor(time() / max(1, $this->costWindowSeconds));

        return sprintf('threat_shield:cost:%s:%d', hash('sha256', $clientId), $bucket);
    }

    private function blockedResponse(string $reasonHeader, string $message): Response
    {
        return Response::json([
            'error' => [
                'code' => 'KGN-SHIELD-403',
                'message' => $message,
            ],
        ], 403, [
            'X-Kongono-Shield' => $reasonHeader,
        ]);
    }
}
