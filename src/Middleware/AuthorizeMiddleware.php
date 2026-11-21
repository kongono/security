<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Kongono\Http\HttpException;
use Kongono\Security\Gate;
use Kongono\Security\Principal;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Fail-closed capability enforcement middleware powered by Principal and Gate. */
final readonly class AuthorizeMiddleware implements MiddlewareInterface
{
    public function __construct(
        private string $ability,
        private Gate $gate = new Gate(),
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $principal = $request->getAttribute(Principal::class);
        if (!$principal instanceof Principal) {
            throw new HttpException(401, 'Authentication required.');
        }

        $this->gate->authorize($principal, $this->ability);

        return $handler->handle($request);
    }
}
