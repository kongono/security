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
 * Least-privilege route capability sandbox: hard-blocks all mutating/DDL SQL (`INSERT`, `UPDATE`,
 * `DELETE`, `DROP`, `ALTER`, CTE writes, etc.) at the database driver BEFORE execution.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class ReadOnlyDb implements MiddlewareAttributeInterface
{
    public function toMiddleware(Container $container): MiddlewareInterface
    {
        return new CapabilityMiddleware($container, new ExecutionCapabilities(readOnlyDb: true));
    }
}
