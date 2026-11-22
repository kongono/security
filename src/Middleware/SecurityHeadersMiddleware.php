<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Applies hardened modern HTTP security headers by default (CSP, nosniff, XFO, Referrer, Permissions, HTTPS HSTS). */
final readonly class SecurityHeadersMiddleware implements MiddlewareInterface
{
    public function __construct(
        private string $contentSecurityPolicy = "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        private string $frameOptions = 'DENY',
        private string $referrerPolicy = 'strict-origin-when-cross-origin',
        private string $permissionsPolicy = 'camera=(), microphone=(), geolocation=()',
        private int $hstsMaxAgeSeconds = 31536000,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        if (!$response->hasHeader('X-Content-Type-Options')) {
            $response = $response->withHeader('X-Content-Type-Options', 'nosniff');
        }
        if (!$response->hasHeader('X-Frame-Options')) {
            $response = $response->withHeader('X-Frame-Options', $this->frameOptions);
        }
        if (!$response->hasHeader('Referrer-Policy')) {
            $response = $response->withHeader('Referrer-Policy', $this->referrerPolicy);
        }
        if ('' !== $this->permissionsPolicy && !$response->hasHeader('Permissions-Policy')) {
            $response = $response->withHeader('Permissions-Policy', $this->permissionsPolicy);
        }
        if ('' !== $this->contentSecurityPolicy && !$response->hasHeader('Content-Security-Policy')) {
            $response = $response->withHeader('Content-Security-Policy', $this->contentSecurityPolicy);
        }
        if (
            $this->hstsMaxAgeSeconds > 0
            && 'https' === strtolower($request->getUri()->getScheme())
            && !$response->hasHeader('Strict-Transport-Security')
        ) {
            $response = $response->withHeader(
                'Strict-Transport-Security',
                sprintf('max-age=%d; includeSubDomains', $this->hstsMaxAgeSeconds),
            );
        }

        return $response;
    }
}
