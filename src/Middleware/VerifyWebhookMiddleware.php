<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Http\HttpException;
use Kongono\Http\Stream;
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

        // Bounded streaming read prevents OOM when stream size is unknown (e.g. chunked transfer)
        if ($stream->isSeekable()) {
            $stream->rewind();
        }
        $body = '';
        $limit = max(1, $this->maxBodyBytes);
        while (!$stream->eof()) {
            $chunk = $stream->read(min(65536, ($limit - strlen($body)) + 1));
            if ('' === $chunk) {
                break;
            }
            $body .= $chunk;
            if (strlen($body) > $limit) {
                throw new HttpException(413, 'Webhook payload exceeds maximum allowed size.');
            }
        }
        if ($stream->isSeekable()) {
            $stream->rewind();
        } else {
            $request = $request->withBody(Stream::fromString($body));
        }

        $fingerprint = $this->signer->verifyAndFingerprint($body, $sigHeader, $this->toleranceSeconds);
        if (null === $fingerprint) {
            throw new HttpException(401, 'Invalid or expired webhook signature.');
        }

        if (null !== $this->replayCache) {
            $replayKey = 'kongono:webhook:seen:' . $fingerprint;
            // Cover full tolerance window + max future skew (60s) + 60s safety margin
            $ttl = max(1, $this->toleranceSeconds) + 120;
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
