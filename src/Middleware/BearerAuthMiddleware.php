<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Closure;
use Kongono\Http\HttpException;
use Kongono\Security\Principal;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Authenticates Bearer tokens into a typed Principal attached as a request attribute.
 * Fails closed with HTTP 401 when required and token is missing or invalid.
 */
final readonly class BearerAuthMiddleware implements MiddlewareInterface
{
    /** @param Closure(string): ?Principal $resolver */
    public function __construct(
        private Closure $resolver,
        private bool $required = true,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $header = trim($request->getHeaderLine('Authorization'));
        $token = null;
        if (str_starts_with(strtolower($header), 'bearer ')) {
            $candidate = trim(substr($header, 7));
            if ('' !== $candidate) {
                $token = $candidate;
            }
        }

        if (null === $token) {
            if ($this->required) {
                throw new HttpException(401, 'Missing Bearer authentication token.', ['WWW-Authenticate' => 'Bearer']);
            }

            return $handler->handle($request);
        }

        $principal = ($this->resolver)($token);
        if (null === $principal) {
            throw new HttpException(401, 'Invalid or expired Bearer token.', ['WWW-Authenticate' => 'Bearer error="invalid_token"']);
        }

        return $handler->handle($request->withAttribute(Principal::class, $principal));
    }
}
