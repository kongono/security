<?php

declare(strict_types=1);

namespace Kongono\Security\Webhook;

use Kongono\Core\Notifications\Notification;
use Kongono\Core\Notifications\NotificationChannelInterface;
use Kongono\Security\SecurityException;

/** Delivers Kongono Notifications over SSRF-hardened signed HTTPS webhooks (Slack, Discord, custom). */
final readonly class WebhookNotificationChannel implements NotificationChannelInterface
{
    public function __construct(
        private WebhookDispatcher $dispatcher,
        private string $channelName = 'webhook',
    ) {}

    public function name(): string
    {
        return $this->channelName;
    }

    public function send(array $recipient, Notification $notification): void
    {
        $url = is_string($recipient['webhook_url'] ?? null) ? trim($recipient['webhook_url']) : '';
        if ('' === $url) {
            throw new SecurityException('WebhookNotificationChannel requires recipient["webhook_url"].');
        }

        $this->dispatcher->send($url, $notification->type, [
            'subject' => $notification->subject,
            'body' => $notification->body,
            'data' => $notification->data,
        ]);
    }
}
