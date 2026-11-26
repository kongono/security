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
 * Least-privilege route capability sandbox: enforces a strict per-request AI spend ceiling in USD
 * exposed via `$request->getAttribute(ExecutionCapabilities::class)->recordAiSpend(...)`.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class MaxAiCost implements MiddlewareAttributeInterface
{
    public function __construct(
        public float $maxUsd,
    ) {}

    public function toMiddleware(Container $container): MiddlewareInterface
    {
        return new CapabilityMiddleware($container, new ExecutionCapabilities(maxAiCostUsd: max(0.0, $this->maxUsd)));
    }
}
