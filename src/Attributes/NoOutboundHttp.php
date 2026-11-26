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
 * Least-privilege route capability sandbox: hard-blocks all outbound HTTP calls via `SafeHttpClient`
 * BEFORE DNS resolution or socket creation, eliminating SSRF / data exfiltration on this endpoint.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class NoOutboundHttp implements MiddlewareAttributeInterface
{
    public function toMiddleware(Container $container): MiddlewareInterface
    {
        return new CapabilityMiddleware($container, new ExecutionCapabilities(noOutboundHttp: true));
    }
}
