<?php

declare(strict_types=1);

namespace Kongono\Security\Tests;

use Kongono\Core\Notifications\Notification;
use Kongono\Core\Notifications\NotificationDispatcher;
use Kongono\Security\Egress\SafeHttpClient;
use Kongono\Security\SecurityException;
use Kongono\Security\Webhook\WebhookDispatcher;
use Kongono\Security\Webhook\WebhookNotificationChannel;
use Kongono\Security\Webhook\WebhookSigner;
use PHPUnit\Framework\TestCase;

final class WebhookNotificationChannelTest extends TestCase
{
    public function testDeliversSignedNotificationPayloadAndIntegratesWithNotificationDispatcher(): void
    {
        $secret = 'whsec_test_secret_key_for_hmac_1234567890';
        $signer = new WebhookSigner($secret);
        $fakeHttp = SafeHttpClient::fake([
            'https://hooks.partner.test/*' => [
                'status' => 200,
                'body' => '{"accepted":true}',
            ],
        ]);

        $channel = new WebhookNotificationChannel(new WebhookDispatcher($fakeHttp, $signer));
        self::assertSame('webhook', $channel->name());

        $customChannel = new WebhookNotificationChannel(new WebhookDispatcher($fakeHttp, $signer), 'slack');
        self::assertSame('slack', $customChannel->name());

        $notification = new Notification(
            type: 'billing.invoice.paid',
            subject: 'Invoice #42 Paid',
            body: 'Payment received.',
            data: ['invoice_id' => 42, 'amount_cents' => 9900],
        );

        $dispatcher = (new NotificationDispatcher())->registerChannel($channel);
        $results = $dispatcher->send(
            ['webhook_url' => 'https://hooks.partner.test/events'],
            $notification,
            ['webhook'],
        );

        self::assertSame(['webhook' => ['ok' => true]], $results);

        $recorder = $fakeHttp->fakeRecorder();
        self::assertNotNull($recorder);
        $recorded = $recorder->recorded();
        self::assertCount(1, $recorded);
        self::assertSame('POST', $recorded[0]['method']);
        self::assertSame('https://hooks.partner.test/events', $recorded[0]['url']);
        self::assertSame('billing.invoice.paid', $recorded[0]['headers']['X-Kongono-Event']);

        $sigHeader = $recorded[0]['headers'][WebhookSigner::DEFAULT_HEADER] ?? '';
        self::assertNotSame('', $sigHeader);
        $rawBody = $recorded[0]['body'] ?? '';
        self::assertTrue($signer->verify($rawBody, $sigHeader));

        $decoded = json_decode($rawBody, true, 16, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertSame('billing.invoice.paid', $decoded['event']);
        self::assertSame('Invoice #42 Paid', $decoded['data']['subject']);
        self::assertSame('Payment received.', $decoded['data']['body']);
        self::assertSame(['invoice_id' => 42, 'amount_cents' => 9900], $decoded['data']['data']);
    }

    public function testRejectsMissingOrBlankWebhookUrlAndBlocksSsrfTargets(): void
    {
        $fakeHttp = SafeHttpClient::fake([
            'https://hooks.partner.test/*' => ['status' => 200, 'body' => '{}'],
        ]);
        $channel = new WebhookNotificationChannel(new WebhookDispatcher($fakeHttp, new WebhookSigner('whsec_secret_1234567890')));
        $notification = new Notification('alert', 'Subject', 'Body');

        try {
            $channel->send(['webhook_url' => '   '], $notification);
            self::fail('Blank webhook_url must throw SecurityException.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('webhook_url', $e->getMessage());
        }

        // SSRF defense enforced through SafeHttpClient even under fake transport
        $dispatcher = (new NotificationDispatcher())->registerChannel($channel);
        $ssrfResult = $dispatcher->send(
            ['webhook_url' => 'http://169.254.169.254/latest/meta-data/'],
            $notification,
        );
        self::assertFalse($ssrfResult['webhook']['ok']);
        self::assertArrayHasKey('error', $ssrfResult['webhook']);
    }
}
