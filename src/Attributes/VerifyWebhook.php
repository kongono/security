<?php

declare(strict_types=1);

namespace Kongono\Security\Attributes;

use Attribute;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Core\Container;
use Kongono\Http\Routing\MiddlewareAttributeInterface;
use Kongono\Security\Middleware\VerifyWebhookMiddleware;
use Kongono\Security\Webhook\WebhookSigner;
use Psr\Http\Server\MiddlewareInterface;

/** Declarative inbound webhook HMAC verification attribute with automatic replay protection when CacheInterface is bound. */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class VerifyWebhook implements MiddlewareAttributeInterface
{
    public function __construct(
        public string $headerName = WebhookSigner::DEFAULT_HEADER,
        public int $toleranceSeconds = 300,
        public bool $preventReplay = true,
        public int $maxBodyBytes = 1_048_576,
    ) {}

    public function toMiddleware(Container $container): MiddlewareInterface
    {
        $signer = $container->make(WebhookSigner::class);
        $replayCache = $this->preventReplay && $container->has(CacheInterface::class)
            ? $container->make(CacheInterface::class)
            : null;

        return new VerifyWebhookMiddleware($signer, $this->headerName, $this->toleranceSeconds, $replayCache, $this->maxBodyBytes);
    }
}
