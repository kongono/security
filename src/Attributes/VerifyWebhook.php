<?php

declare(strict_types=1);

namespace Kongono\Security\Attributes;

use Attribute;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Core\Cache\MemoryCache;
use Kongono\Core\Container;
use Kongono\Http\Routing\MiddlewareAttributeInterface;
use Kongono\Security\Middleware\VerifyWebhookMiddleware;
use Kongono\Security\Webhook\WebhookSigner;
use Psr\Http\Server\MiddlewareInterface;

/** Declarative inbound webhook HMAC verification attribute with fail-closed replay protection. */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class VerifyWebhook implements MiddlewareAttributeInterface
{
    private const string FALLBACK_REPLAY_CACHE_ID = 'kongono.webhook.replay_cache';

    public function __construct(
        public string $headerName = WebhookSigner::DEFAULT_HEADER,
        public int $toleranceSeconds = 300,
        public bool $preventReplay = true,
        public int $maxBodyBytes = 1_048_576,
    ) {}

    public function toMiddleware(Container $container): MiddlewareInterface
    {
        $signer = $container->make(WebhookSigner::class);
        $replayCache = null;
        if ($this->preventReplay) {
            if ($container->has(CacheInterface::class)) {
                $replayCache = $container->make(CacheInterface::class);
            } else {
                // Never silently fail open: bind a process-local atomic MemoryCache on the container for replay deduplication
                if (!$container->has(self::FALLBACK_REPLAY_CACHE_ID)) {
                    $container->instance(self::FALLBACK_REPLAY_CACHE_ID, new MemoryCache());
                }
                $fallback = $container->get(self::FALLBACK_REPLAY_CACHE_ID);
                $replayCache = $fallback instanceof CacheInterface ? $fallback : new MemoryCache();
            }
        }

        return new VerifyWebhookMiddleware($signer, $this->headerName, $this->toleranceSeconds, $replayCache, $this->maxBodyBytes);
    }
}
