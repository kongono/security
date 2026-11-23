<?php

declare(strict_types=1);

namespace Kongono\Security\Attributes;

use Attribute;
use Kongono\Core\Container;
use Kongono\Http\Routing\MiddlewareAttributeInterface;
use Kongono\Security\Middleware\RequireAuthenticatedMiddleware;
use Psr\Http\Server\MiddlewareInterface;

/**
 * Declarative authentication attribute requiring any logged-in {@see \Kongono\Security\Principal}.
 *
 * Examples:
 *   `#[Authenticated]`
 *   `#[Authenticated(redirectTo: '/login')]`
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class Authenticated implements MiddlewareAttributeInterface
{
    public function __construct(
        public ?string $redirectTo = null,
    ) {}

    public function toMiddleware(Container $container): MiddlewareInterface
    {
        return new RequireAuthenticatedMiddleware($this->redirectTo);
    }
}
