<?php

declare(strict_types=1);

namespace Kongono\Security\Attributes;

use Attribute;
use Kongono\Core\Capabilities\ExecutionCapabilities;
use Kongono\Core\Container;
use Kongono\Http\Routing\MiddlewareAttributeInterface;
use Kongono\Security\Middleware\CapabilityMiddleware;
use Psr\Http\Server\MiddlewareInterface;

/**
 * Least-privilege route capability sandbox: enforces a strict maximum SQL query count per request,
 * catching runaway N+1 query loops live before they overload the database.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class MaxQueries implements MiddlewareAttributeInterface
{
    public function __construct(
        public int $limit,
    ) {}

    public function toMiddleware(Container $container): MiddlewareInterface
    {
        return new CapabilityMiddleware($container, new ExecutionCapabilities(maxQueries: max(1, $this->limit)));
    }
}
