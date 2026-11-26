<?php

declare(strict_types=1);

namespace Kongono\Security\Attributes;

use Attribute;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Core\Cache\MemoryCache;
use Kongono\Core\Container;
use Kongono\Http\Routing\MiddlewareAttributeInterface;
use Kongono\Security\Middleware\VerifyWebhookMiddleware;
use Kongono\Security\SecurityException;
use Kongono\Security\Webhook\WebhookSigner;
use Kongono\Security\Webhook\WebhookSignerRegistry;
use Psr\Http\Server\MiddlewareInterface;

/**
 * Declarative inbound webhook HMAC verification attribute with fail-closed replay protection.
 *
 * Supports both single-signer apps (`#[VerifyWebhook]` / `#[VerifyWebhook('X-Custom-Signature')]`)
 * and multi-provider apps via {@see WebhookSignerRegistry} (`#[VerifyWebhook('stripe')]` or
 * `#[VerifyWebhook(headerName: 'Stripe-Signature', signer: 'stripe')]`).
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class VerifyWebhook implements MiddlewareAttributeInterface
{
    private const string FALLBACK_REPLAY_CACHE_ID = 'kongono.webhook.replay_cache';

    public function __construct(
        public string $headerName = WebhookSigner::DEFAULT_HEADER,
        public int $toleranceSeconds = 300,
        public bool $preventReplay = true,
        public int $maxBodyBytes = 1_048_576,
        public ?string $signer = null,
    ) {}

    public function toMiddleware(Container $container): MiddlewareInterface
    {
        [$signer, $effectiveHeader] = $this->resolveSignerAndHeader($container);

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

        return new VerifyWebhookMiddleware($signer, $effectiveHeader, $this->toleranceSeconds, $replayCache, $this->maxBodyBytes);
    }

    /** @return array{0: WebhookSigner, 1: string} */
    private function resolveSignerAndHeader(Container $container): array
    {
        if (null !== $this->signer) {
            if (!$container->has(WebhookSignerRegistry::class)) {
                throw new SecurityException(sprintf(
                    'Named webhook signer "%s" requires a %s bound in the container.',
                    $this->signer,
                    WebhookSignerRegistry::class,
                ));
            }
            $registry = $container->make(WebhookSignerRegistry::class);
            $effectiveHeader = WebhookSigner::DEFAULT_HEADER === $this->headerName
                ? $registry->headerFor($this->signer)
                : $this->headerName;

            return [$registry->signer($this->signer), $effectiveHeader];
        }

        // Shorthand: `#[VerifyWebhook('stripe')]` automatically resolves named provider from WebhookSignerRegistry
        if ($container->has(WebhookSignerRegistry::class)) {
            $registry = $container->make(WebhookSignerRegistry::class);
            if ($registry->has($this->headerName)) {
                return [$registry->signer($this->headerName), $registry->headerFor($this->headerName)];
            }
        }

        return [$container->make(WebhookSigner::class), $this->headerName];
    }
}
