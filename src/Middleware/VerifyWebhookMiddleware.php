<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Kongono\Http\HttpException;
use Kongono\Security\Webhook\WebhookSigner;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Verifies inbound signed webhooks using constant-time HMAC-SHA256 & replay-window enforcement. */
final readonly class VerifyWebhookMiddleware implements MiddlewareInterface
{
    public function __construct(
        private WebhookSigner $signer,
        private string $headerName = WebhookSigner::DEFAULT_HEADER,
        private int $toleranceSeconds = 300,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $sigHeader = $request->getHeaderLine($this->headerName);
        if ('' === $sigHeader) {
            throw new HttpException(401, sprintf('Missing webhook signature header "%s".', $this->headerName));
        }

        $body = (string) $request->getBody();
        if (!$this->signer->verify($body, $sigHeader, $this->toleranceSeconds)) {
            throw new HttpException(401, 'Invalid or expired webhook signature.');
        }

        return $handler->handle($request->withAttribute('_webhook_verified', true));
    }
}
