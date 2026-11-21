<?php

declare(strict_types=1);

namespace Kongono\Security\Attributes;

use Attribute;
use Kongono\Core\Container;
use Kongono\Http\Routing\MiddlewareAttributeInterface;
use Kongono\Security\Middleware\VerifyWebhookMiddleware;
use Kongono\Security\Webhook\WebhookSigner;
use Psr\Http\Server\MiddlewareInterface;

/** Declarative inbound webhook HMAC verification attribute for controllers and route methods. */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class VerifyWebhook implements MiddlewareAttributeInterface
{
    public function __construct(
        public string $headerName = WebhookSigner::DEFAULT_HEADER,
        public int $toleranceSeconds = 300,
    ) {}

    public function toMiddleware(Container $container): MiddlewareInterface
    {
        $signer = $container->make(WebhookSigner::class);

        return new VerifyWebhookMiddleware($signer, $this->headerName, $this->toleranceSeconds);
    }
}
