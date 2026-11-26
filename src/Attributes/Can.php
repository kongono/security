<?php

declare(strict_types=1);

namespace Kongono\Security\Attributes;

use Attribute;
use Kongono\Core\Container;
use Kongono\Http\Routing\MiddlewareAttributeInterface;
use Kongono\Security\Gate;
use Kongono\Security\Middleware\AuthorizeMiddleware;
use Psr\Http\Server\MiddlewareInterface;

/**
 * Declarative capability authorization attribute for controllers and route methods.
 *
 * Example: `#[Can('notes.write')]`
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION | Attribute::IS_REPEATABLE)]
final readonly class Can implements MiddlewareAttributeInterface
{
    public function __construct(
        public string $ability,
    ) {}

    public function toMiddleware(Container $container): MiddlewareInterface
    {
        $gate = $container->has(Gate::class) ? $container->make(Gate::class) : new Gate();

        return new AuthorizeMiddleware($this->ability, $gate);
    }
}
