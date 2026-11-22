<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Closure;
use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Http\HttpException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Fixed-window HTTP rate limiter backed by any CacheInterface (atomic under AtomicCacheInterface).
 * Canonicalizes request paths identically to Router and fails closed with HTTP 429 + Retry-After.
 */
final readonly class RateLimitMiddleware implements MiddlewareInterface
{
    /** @param (Closure(ServerRequestInterface): string)|null $keyResolver */
    public function __construct(
        private CacheInterface $cache,
        private int $maxRequests = 60,
        private int $windowSeconds = 60,
        private ?Closure $keyResolver = null,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $clientKey = null !== $this->keyResolver
            ? ($this->keyResolver)($request)
            : $this->defaultClientKey($request);

        $window = max(1, $this->windowSeconds);
        $bucket = (int) floor(time() / $window);
        $cacheKey = sprintf('ratelimit:%s:%d', hash('sha256', $clientKey), $bucket);

        if ($this->cache instanceof AtomicCacheInterface) {
            $newCount = $this->cache->increment($cacheKey, 1, $window + 1);
            if ($newCount > $this->maxRequests) {
                throw new HttpException(
                    statusCode: 429,
                    message: 'Rate limit exceeded. Please try again later.',
                    headers: [
                        'Retry-After' => (string) $window,
                        'X-RateLimit-Limit' => (string) $this->maxRequests,
                        'X-RateLimit-Remaining' => '0',
                    ],
                );
            }
        } else {
            $rawCount = $this->cache->get($cacheKey, 0);
            $count = is_int($rawCount) ? $rawCount : 0;

            if ($count >= $this->maxRequests) {
                throw new HttpException(
                    statusCode: 429,
                    message: 'Rate limit exceeded. Please try again later.',
                    headers: [
                        'Retry-After' => (string) $window,
                        'X-RateLimit-Limit' => (string) $this->maxRequests,
                        'X-RateLimit-Remaining' => '0',
                    ],
                );
            }

            $newCount = $count + 1;
            $this->cache->set($cacheKey, $newCount, $window + 1);
        }

        $remaining = max(0, $this->maxRequests - $newCount);

        return $handler->handle($request)
            ->withHeader('X-RateLimit-Limit', (string) $this->maxRequests)
            ->withHeader('X-RateLimit-Remaining', (string) $remaining);
    }

    private function defaultClientKey(ServerRequestInterface $request): string
    {
        $server = $request->getServerParams();
        $ip = is_string($server['REMOTE_ADDR'] ?? null) ? $server['REMOTE_ADDR'] : 'local';

        // Scope by declared route template when available (finite cardinality, immune to /users/01/ vs /users/1/
        // dynamic param fragmentation and 404 cache/inode bombing); fall back to per-IP globally.
        $routePattern = $request->getAttribute('_route_pattern');
        if (is_string($routePattern) && '' !== $routePattern) {
            return $ip . ':' . $routePattern;
        }

        return $ip;
    }
}
