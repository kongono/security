<?php

declare(strict_types=1);

namespace Kongono\Security\Webhook;

use Kongono\Security\Egress\SafeHttpClient;

/**
 * SSRF-hardened outbound webhook dispatcher signing every JSON delivery with HMAC-SHA256.
 */
final readonly class WebhookDispatcher
{
    public function __construct(
        private SafeHttpClient $http,
        private WebhookSigner $signer,
        private string $signatureHeader = WebhookSigner::DEFAULT_HEADER,
    ) {}

    /**
     * Dispatch a signed JSON webhook event to an allowlisted, SSRF-verified HTTPS destination.
     *
     * @param array<string, mixed> $payload
     * @return array{status: int, body: string, signature: string}
     */
    public function send(string $url, string $event, array $payload, ?int $timestamp = null): array
    {
        $body = json_encode([
            'event' => $event,
            'timestamp' => gmdate(DATE_ATOM, $timestamp ?? time()),
            'data' => $payload,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $signature = $this->signer->sign($body, $timestamp);
        $response = $this->http->request('POST', $url, [
            'Content-Type' => 'application/json',
            'X-Kongono-Event' => $event,
            $this->signatureHeader => $signature,
        ], $body);

        return [
            'status' => $response['status'],
            'body' => $response['body'],
            'signature' => $signature,
        ];
    }
}
