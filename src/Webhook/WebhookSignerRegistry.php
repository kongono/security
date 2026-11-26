<?php

declare(strict_types=1);

namespace Kongono\Security\Webhook;

use Kongono\Security\SecurityException;
use SensitiveParameter;

/**
 * Immutable named registry of inbound {@see WebhookSigner} instances and default signature headers.
 *
 * Allows a single application to verify multiple webhook providers cleanly via `#[VerifyWebhook('stripe')]`,
 * `#[VerifyWebhook('internal')]`, or `#[VerifyWebhook(headerName: 'Stripe-Signature', signer: 'stripe')]`.
 */
final readonly class WebhookSignerRegistry
{
    /**
     * @param array<string, array{signer: WebhookSigner, header: string}> $entries
     */
    public function __construct(
        private array $entries = [],
    ) {}

    /** Register a named webhook signer and its default HTTP signature header. */
    public function register(
        string $name,
        WebhookSigner $signer,
        string $headerName = WebhookSigner::DEFAULT_HEADER,
    ): self {
        $key = self::normalizeName($name);
        $cleanHeader = trim($headerName);
        if ('' === $cleanHeader) {
            throw new SecurityException('Webhook signature header name cannot be empty.');
        }

        $entries = $this->entries;
        $entries[$key] = [
            'signer' => $signer,
            'header' => $cleanHeader,
        ];

        return new self($entries);
    }

    /**
     * Register a Stripe / Stripe Connect webhook endpoint secret (`Stripe-Signature: t=...,v1=...`).
     */
    public function registerStripe(
        #[SensitiveParameter]
        string $webhookSecret,
        string $name = 'stripe',
    ): self {
        return $this->register($name, new WebhookSigner($webhookSecret), 'Stripe-Signature');
    }

    public function has(string $name): bool
    {
        $trimmed = strtolower(trim($name));

        return '' !== $trimmed && isset($this->entries[$trimmed]);
    }

    public function signer(string $name): WebhookSigner
    {
        $key = self::normalizeName($name);
        if (!isset($this->entries[$key])) {
            throw new SecurityException(sprintf('Webhook signer "%s" is not registered.', $name));
        }

        return $this->entries[$key]['signer'];
    }

    public function headerFor(string $name): string
    {
        $key = self::normalizeName($name);
        if (!isset($this->entries[$key])) {
            throw new SecurityException(sprintf('Webhook signer "%s" is not registered.', $name));
        }

        return $this->entries[$key]['header'];
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->entries);
    }

    private static function normalizeName(string $name): string
    {
        $clean = strtolower(trim($name));
        if ('' === $clean) {
            throw new SecurityException('Webhook signer name cannot be empty.');
        }

        return $clean;
    }
}
