<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Kongono\Http\HttpException;
use Kongono\Http\Response;
use Kongono\Security\Principal;
use Kongono\Security\SecurityException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Fail-closed authentication guard requiring any authenticated {@see Principal}.
 *
 * When `$redirectTo` is set (e.g. `'/login'`), unauthenticated browser HTML requests
 * receive a 302 redirect while JSON/API/Live requests receive HTTP 401.
 */
final readonly class RequireAuthenticatedMiddleware implements MiddlewareInterface
{
    public function __construct(
        private ?string $redirectTo = null,
    ) {
        if (null !== $redirectTo && (!str_starts_with($redirectTo, '/') || str_starts_with($redirectTo, '//') || false !== strpbrk($redirectTo, "\r\n\0"))) {
            throw new SecurityException('RequireAuthenticatedMiddleware redirectTo must be a safe same-origin relative path starting with "/".');
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $principal = $request->getAttribute(Principal::class);
        if ($principal instanceof Principal) {
            return $handler->handle($request);
        }

        if (null !== $this->redirectTo && self::prefersHtmlRedirect($request)) {
            return Response::redirect($this->redirectTo, 302);
        }

        throw new HttpException(401, 'Authentication required.');
    }

    public static function prefersHtmlRedirect(ServerRequestInterface $request): bool
    {
        $accept = strtolower($request->getHeaderLine('Accept'));
        if (str_contains($accept, 'application/json') || 'true' === strtolower($request->getHeaderLine('X-Kongono-Bridge'))) {
            return false;
        }
        if (str_starts_with($request->getUri()->getPath(), '/api/')) {
            return false;
        }

        return str_contains($accept, 'text/html') || '' === trim($accept) || str_contains($accept, '*/*');
    }
}
