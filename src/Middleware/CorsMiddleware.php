<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Kongono\Http\HttpException;
use Kongono\Http\Response;
use Kongono\Security\SecurityException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Explicit, fail-closed CORS middleware with OPTIONS preflight support. */
final readonly class CorsMiddleware implements MiddlewareInterface
{
    /**
     * @param list<string> $allowedOrigins Exact origins (e.g. ['https://app.example.com']) or ['*']
     * @param list<string> $allowedMethods
     * @param list<string> $allowedHeaders
     */
    public function __construct(
        private array $allowedOrigins = [],
        private array $allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        private array $allowedHeaders = ['Content-Type', 'Authorization', 'X-CSRF-Token'],
        private bool $allowCredentials = false,
        private int $maxAgeSeconds = 600,
    ) {
        if ($allowCredentials) {
            foreach ($allowedOrigins as $origin) {
                $trimmed = strtolower(trim($origin));
                if ('*' === $trimmed || 'null' === $trimmed) {
                    throw new SecurityException(sprintf('CORS misconfiguration rejected: allowCredentials cannot be combined with origin "%s".', $origin));
                }
            }
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $origin = $request->getHeaderLine('Origin');
        $admittedOrigin = $this->matchOrigin($origin);
        $shouldVaryOrigin = [] !== $this->allowedOrigins && !in_array('*', $this->allowedOrigins, true);

        if ('OPTIONS' === strtoupper($request->getMethod()) && '' !== $origin) {
            $preflight = Response::noContent();
            if (null === $admittedOrigin) {
                $denied = $preflight->withStatus(403);

                return $shouldVaryOrigin ? $denied->withAddedHeader('Vary', 'Origin') : $denied;
            }

            return $this->applyCorsHeaders($preflight, $admittedOrigin)
                ->withHeader('Access-Control-Allow-Methods', implode(', ', $this->allowedMethods))
                ->withHeader('Access-Control-Allow-Headers', implode(', ', $this->allowedHeaders))
                ->withHeader('Access-Control-Max-Age', (string) $this->maxAgeSeconds);
        }

        try {
            $response = $handler->handle($request);
        } catch (HttpException $e) {
            if (null !== $admittedOrigin || $shouldVaryOrigin) {
                $headers = $e->headers;
                if (null !== $admittedOrigin) {
                    $headers['Access-Control-Allow-Origin'] = $admittedOrigin;
                    if ($this->allowCredentials && '*' !== $admittedOrigin) {
                        $headers['Access-Control-Allow-Credentials'] = 'true';
                    }
                }
                if (!self::headerArrayHasVaryOrigin($headers)) {
                    $existingVaryKey = null;
                    $existingVaryValue = '';
                    foreach ($headers as $k => $v) {
                        if ('vary' === strtolower($k)) {
                            $existingVaryKey = $k;
                            $existingVaryValue = trim(is_array($v) ? implode(', ', $v) : $v);
                            break;
                        }
                    }
                    if (null !== $existingVaryKey && 'Vary' !== $existingVaryKey) {
                        unset($headers[$existingVaryKey]);
                    }
                    $headers['Vary'] = '' !== $existingVaryValue
                        ? $existingVaryValue . ', Origin'
                        : 'Origin';
                }

                throw new HttpException($e->statusCode, $e->getMessage(), $headers, $e->diagnostic, $e);
            }
            throw $e;
        }

        if (null === $admittedOrigin) {
            return $shouldVaryOrigin && !self::responseHasVaryOrigin($response)
                ? $response->withAddedHeader('Vary', 'Origin')
                : $response;
        }

        return $this->applyCorsHeaders($response, $admittedOrigin);
    }

    private function matchOrigin(string $origin): ?string
    {
        if ('' === $origin) {
            return null;
        }
        if (in_array('*', $this->allowedOrigins, true) && !$this->allowCredentials) {
            return '*';
        }
        if (in_array($origin, $this->allowedOrigins, true)) {
            return $origin;
        }

        return null;
    }

    private function applyCorsHeaders(ResponseInterface $response, string $admittedOrigin): ResponseInterface
    {
        $response = $response->withHeader('Access-Control-Allow-Origin', $admittedOrigin);
        if (!self::responseHasVaryOrigin($response)) {
            $response = $response->withAddedHeader('Vary', 'Origin');
        }

        if ($this->allowCredentials && '*' !== $admittedOrigin) {
            $response = $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }

        return $response;
    }

    private static function responseHasVaryOrigin(ResponseInterface $response): bool
    {
        foreach ($response->getHeader('Vary') as $line) {
            foreach (explode(',', $line) as $token) {
                $t = strtolower(trim($token));
                if ('origin' === $t || '*' === $t) {
                    return true;
                }
            }
        }

        return false;
    }

    /** @param array<string, string|list<string>> $headers */
    private static function headerArrayHasVaryOrigin(array $headers): bool
    {
        foreach ($headers as $k => $v) {
            if ('vary' !== strtolower($k)) {
                continue;
            }
            $lines = is_array($v) ? $v : [$v];
            foreach ($lines as $line) {
                foreach (explode(',', $line) as $token) {
                    $t = strtolower(trim($token));
                    if ('origin' === $t || '*' === $t) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
