<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Http\HttpException;
use Kongono\Security\Webhook\WebhookSigner;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Verifies inbound signed webhooks with body size cap, constant-time HMAC-SHA256, and optional replay deduplication. */
final readonly class VerifyWebhookMiddleware implements MiddlewareInterface
{
    public function __construct(
        private WebhookSigner $signer,
        private string $headerName = WebhookSigner::DEFAULT_HEADER,
        private int $toleranceSeconds = 300,
        private ?CacheInterface $replayCache = null,
        private int $maxBodyBytes = 1_048_576,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $sigHeader = $request->getHeaderLine($this->headerName);
        if ('' === $sigHeader) {
            throw new HttpException(401, sprintf('Missing webhook signature header "%s".', $this->headerName));
        }

        $stream = $request->getBody();
        $reportedSize = $stream->getSize();
        if (null !== $reportedSize && $reportedSize > $this->maxBodyBytes) {
            throw new HttpException(413, 'Webhook payload exceeds maximum allowed size.');
        }

        $body = (string) $stream;
        if (strlen($body) > $this->maxBodyBytes) {
            throw new HttpException(413, 'Webhook payload exceeds maximum allowed size.');
        }

        $fingerprint = $this->signer->verifyAndFingerprint($body, $sigHeader, $this->toleranceSeconds);
        if (null === $fingerprint) {
            throw new HttpException(401, 'Invalid or expired webhook signature.');
        }

        if (null !== $this->replayCache) {
            $replayKey = 'kongono:webhook:seen:' . $fingerprint;
            $ttl = max(60, $this->toleranceSeconds * 2);
            if ($this->replayCache instanceof AtomicCacheInterface) {
                if (!$this->replayCache->add($replayKey, true, $ttl)) {
                    throw new HttpException(409, 'Webhook delivery replay detected.');
                }
            } else {
                if ($this->replayCache->has($replayKey)) {
                    throw new HttpException(409, 'Webhook delivery replay detected.');
                }
                $this->replayCache->set($replayKey, true, $ttl);
            }
        }

        return $handler->handle($request->withAttribute('_webhook_verified', true));
    }
}
