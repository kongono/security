<?php

declare(strict_types=1);

namespace Kongono\Security\Tests;

use Kongono\Core\Cache\CacheInterface;
use Kongono\Core\Cache\MemoryCache;
use Kongono\Http\App;
use Kongono\Http\Response;
use Kongono\Http\Routing\Post;
use Kongono\Http\Testing\TestClient;
use Kongono\Security\Attributes\VerifyWebhook;
use Kongono\Security\SecurityException;
use Kongono\Security\Webhook\WebhookSigner;
use Kongono\Security\Webhook\WebhookSignerRegistry;
use PHPUnit\Framework\TestCase;

final readonly class MultiProviderWebhookController
{
    #[Post('/webhooks/stripe')]
    #[VerifyWebhook('stripe')]
    public function stripe(): Response
    {
        return Response::json(['provider' => 'stripe', 'ok' => true]);
    }

    #[Post('/webhooks/internal')]
    #[VerifyWebhook(signer: 'internal')]
    public function internal(): Response
    {
        return Response::json(['provider' => 'internal', 'ok' => true]);
    }
}

final class WebhookSignerRegistryTest extends TestCase
{
    public function testMultiProviderStripeAndInternalWebhooksIsolateSecretsAndBlockReplays(): void
    {
        $stripeSecret = 'whsec_' . str_repeat('a1b2', 8);
        $internalSecret = 'kgn_wh_' . str_repeat('c3d4', 8);

        $registry = (new WebhookSignerRegistry())
            ->registerStripe($stripeSecret)
            ->register('internal', new WebhookSigner($internalSecret));

        self::assertSame(['stripe', 'internal'], $registry->names());
        self::assertSame('Stripe-Signature', $registry->headerFor('stripe'));
        self::assertSame('X-Kongono-Signature', $registry->headerFor('internal'));

        $app = App::create(sys_get_temp_dir(), name: 'Webhook Registry Test')
            ->instance(CacheInterface::class, new MemoryCache())
            ->instance(WebhookSignerRegistry::class, $registry)
            ->controller(MultiProviderWebhookController::class);

        $client = new TestClient($app);
        $payload = '{"id":"evt_123","type":"payment_intent.succeeded"}';

        // 1. Valid Stripe-Signature passes #[VerifyWebhook('stripe')]
        $stripeSig = (new WebhookSigner($stripeSecret))->sign($payload);
        $client->request('POST', '/webhooks/stripe', body: $payload, headers: [
            'Content-Type' => 'application/json',
            'Stripe-Signature' => $stripeSig,
        ])->assertOk()->assertJsonPath('provider', 'stripe');

        // 2. Replaying the same Stripe delivery is rejected with 409
        $client->request('POST', '/webhooks/stripe', body: $payload, headers: [
            'Content-Type' => 'application/json',
            'Stripe-Signature' => $stripeSig,
        ])->assertStatus(409);

        // 3. Cross-provider secret isolation: internal secret rejected on Stripe endpoint
        $wrongSig = (new WebhookSigner($internalSecret))->sign($payload);
        $client->request('POST', '/webhooks/stripe', body: $payload, headers: [
            'Content-Type' => 'application/json',
            'Stripe-Signature' => $wrongSig,
        ])->assertStatus(401);

        // 4. Valid X-Kongono-Signature passes #[VerifyWebhook(signer: 'internal')]
        $client->request('POST', '/webhooks/internal', body: $payload, headers: [
            'Content-Type' => 'application/json',
            'X-Kongono-Signature' => $wrongSig,
        ])->assertOk()->assertJsonPath('provider', 'internal');

        // 5. Unknown named signer fails closed
        $this->expectException(SecurityException::class);
        $registry->signer('nonexistent');
    }
}
