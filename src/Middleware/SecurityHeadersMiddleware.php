<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Applies hardened modern HTTP security headers by default. */
final readonly class SecurityHeadersMiddleware implements MiddlewareInterface
{
    public function __construct(
        private string $contentSecurityPolicy = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        private string $frameOptions = 'DENY',
        private string $referrerPolicy = 'strict-origin-when-cross-origin',
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
        if ('' !== $this->contentSecurityPolicy && !$response->hasHeader('Content-Security-Policy')) {
            $response = $response->withHeader('Content-Security-Policy', $this->contentSecurityPolicy);
        }

        return $response;
    }
}
