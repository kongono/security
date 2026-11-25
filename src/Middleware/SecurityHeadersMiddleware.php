<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Kongono\Http\HttpException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Applies hardened modern HTTP security headers by default (CSP, nosniff, XFO, Referrer, Permissions, HTTPS HSTS) including on error responses. */
final readonly class SecurityHeadersMiddleware implements MiddlewareInterface
{
    public function __construct(
        private string $contentSecurityPolicy = "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        private string $frameOptions = 'DENY',
        private string $referrerPolicy = 'strict-origin-when-cross-origin',
        private string $permissionsPolicy = 'camera=(), microphone=(), geolocation=()',
        private int $hstsMaxAgeSeconds = 31536000,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $response = $handler->handle($request);
        } catch (HttpException $e) {
            $mergedHeaders = $this->defaultHeadersFor($request);
            $lowerMap = [];
            foreach (array_keys($mergedHeaders) as $k) {
                $lowerMap[strtolower($k)] = $k;
            }
            foreach ($e->headers as $name => $value) {
                $lower = strtolower($name);
                if (isset($lowerMap[$lower])) {
                    unset($mergedHeaders[$lowerMap[$lower]]);
                }
                $mergedHeaders[$name] = $value;
                $lowerMap[$lower] = $name;
            }
            throw new HttpException(
                statusCode: $e->statusCode,
                message: $e->getMessage(),
                headers: $mergedHeaders,
                diagnostic: $e->diagnostic,
                previous: $e,
            );
        }

        foreach ($this->defaultHeadersFor($request) as $name => $value) {
            if (!$response->hasHeader($name)) {
                $response = $response->withHeader($name, $value);
            }
        }

        return $response;
    }

    /** @return array<string, string> */
    private function defaultHeadersFor(ServerRequestInterface $request): array
    {
        $headers = [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => $this->frameOptions,
            'Referrer-Policy' => $this->referrerPolicy,
        ];
        if ('' !== $this->permissionsPolicy) {
            $headers['Permissions-Policy'] = $this->permissionsPolicy;
        }
        if ('' !== $this->contentSecurityPolicy) {
            $headers['Content-Security-Policy'] = $this->contentSecurityPolicy;
        }
        if ($this->hstsMaxAgeSeconds > 0 && 'https' === strtolower($request->getUri()->getScheme())) {
            $headers['Strict-Transport-Security'] = sprintf('max-age=%d; includeSubDomains', $this->hstsMaxAgeSeconds);
        }

        return $headers;
    }
}
