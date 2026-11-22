<?php

declare(strict_types=1);

namespace Kongono\Security\Tests;

use Kongono\Core\Cache\MemoryCache;
use Kongono\Http\App;
use Kongono\Http\HttpException;
use Kongono\Http\Request;
use Kongono\Http\Response;
use Kongono\Http\Routing\Get;
use Kongono\Http\Routing\Middleware;
use Kongono\Http\Routing\Post;
use Kongono\Http\Routing\Router;
use Kongono\Security\Attributes\Can;
use Kongono\Security\Attributes\VerifyWebhook;
use Kongono\Security\Egress\SafeHttpClient;
use Kongono\Security\Encryptor;
use Kongono\Security\Gate;
use Kongono\Security\Middleware\AiThreatShieldMiddleware;
use Kongono\Security\Middleware\BearerAuthMiddleware;
use Kongono\Security\Middleware\CorsMiddleware;
use Kongono\Security\Middleware\CsrfMiddleware;
use Kongono\Security\Middleware\RateLimitMiddleware;
use Kongono\Security\Middleware\SecurityHeadersMiddleware;
use Kongono\Security\PasswordHasher;
use Kongono\Security\Principal;
use Kongono\Security\PrincipalKind;
use Kongono\Security\SecurityException;
use Kongono\Security\SignedUrl;
use Kongono\Security\TokenSigner;
use Kongono\Security\Totp;
use Kongono\Security\Webhook\WebhookSigner;
use PHPUnit\Framework\TestCase;

final class SecurityTest extends TestCase
{
    public function testPrincipalAndGateFailClosed(): void
    {
        $human = new Principal('user-1', PrincipalKind::Human, ['notes.read']);
        $agent = new Principal('agent-chie', PrincipalKind::Agent, ['graph.read']);

        $gate = (new Gate())->define('notes.own', static fn(Principal $p, mixed $ownerId): bool => $p->id === $ownerId);

        self::assertTrue($gate->allows($human, 'notes.read'));
        self::assertFalse($gate->allows($human, 'notes.delete'));
        self::assertFalse($gate->allows(null, 'notes.read'));
        self::assertTrue($gate->allows($human, 'notes.own', 'user-1'));
        self::assertFalse($gate->allows($agent, 'notes.own', 'user-1'));
        self::assertTrue($agent->isAgent());

        $this->expectException(HttpException::class);
        $gate->authorize($agent, 'notes.delete');
    }

    public function testPasswordHasherAndTokenSigner(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('correct-horse-battery-staple');
        self::assertTrue($hasher->verify('correct-horse-battery-staple', $hash));
        self::assertFalse($hasher->verify('wrong-password', $hash));

        $signer = new TokenSigner('0123456789abcdef0123456789abcdef');
        $token = $signer->sign(['sub' => 'user-42'], ttlSeconds: 60, now: 1000);
        self::assertSame(['sub' => 'user-42'], $signer->verify($token, now: 1030));
        self::assertNull($signer->verify($token, now: 1061));
        self::assertNull($signer->verify($token . 'tampered', now: 1030));

        $csrf = $signer->generateCsrfToken('sess-123', ttlSeconds: 300, now: 1000);
        self::assertTrue($signer->verifyCsrfToken($csrf, 'sess-123', now: 1100));
        self::assertFalse($signer->verifyCsrfToken($csrf, 'sess-other', now: 1100));
    }

    public function testSecurityHeadersCorsBearerAndCsrfMiddleware(): void
    {
        $signer = new TokenSigner('secret-key-at-least-16-bytes-long');

        $app = App::create(__DIR__)
            ->middleware(
                new SecurityHeadersMiddleware(),
                new CorsMiddleware(allowedOrigins: ['https://app.kongono.com']),
                new CsrfMiddleware($signer, exemptPrefixes: ['/api/']),
            )
            ->routes(static function (Router $r): void {
                $r->get('/api/me', static function (Request $req): Response {
                    $principal = $req->getAttribute(Principal::class);

                    return Response::json(['id' => $principal instanceof Principal ? $principal->id : null]);
                })->middleware(new BearerAuthMiddleware(
                    static fn(string $token): ?Principal => 'valid-tok' === $token
                        ? new Principal('u-9', PrincipalKind::Human, ['me.read'])
                        : null,
                ));

                $r->post('/form', static fn(): Response => Response::text('ok'));
            });

        // Missing bearer fails closed 401
        $unauth = $app->handle(Request::create('GET', '/api/me'));
        self::assertSame(401, $unauth->getStatusCode());
        self::assertSame('nosniff', $unauth->getHeaderLine('X-Content-Type-Options'));

        // Valid bearer attaches Principal + allowed CORS origin
        $auth = $app->handle(Request::create('GET', '/api/me', [
            'Authorization' => 'Bearer valid-tok',
            'Origin' => 'https://app.kongono.com',
        ]));
        self::assertSame(200, $auth->getStatusCode());
        self::assertSame('{"id":"u-9"}', (string) $auth->getBody());
        self::assertSame('https://app.kongono.com', $auth->getHeaderLine('Access-Control-Allow-Origin'));

        // Disallowed CORS preflight rejected 403
        $badPreflight = $app->handle(Request::create('OPTIONS', '/api/me', ['Origin' => 'https://evil.example']));
        self::assertSame(403, $badPreflight->getStatusCode());

        // Browser POST without CSRF rejected 403
        $noCsrf = $app->handle(Request::create('POST', '/form'));
        self::assertSame(403, $noCsrf->getStatusCode());

        // Browser POST with valid signed CSRF token passes
        $csrfToken = $signer->generateCsrfToken('browser-sess-1');
        $withCsrf = Request::create('POST', '/form', ['X-CSRF-Token' => $csrfToken])
            ->withCookieParams(['kongono_session' => 'browser-sess-1']);
        self::assertInstanceOf(Request::class, $withCsrf);
        $okForm = $app->handle($withCsrf);
        self::assertSame(200, $okForm->getStatusCode());
    }

    public function testSafeHttpClientBlocksSsrfAndAdmitsAllowlistedPublicHost(): void
    {
        $client = new SafeHttpClient(
            allowedHosts: ['api.example.com', 'metadata.internal'],
            dnsResolver: static fn(string $host): array => match ($host) {
                'api.example.com' => ['93.184.216.34'],
                'metadata.internal' => ['169.254.169.254'],
                default => ['127.0.0.1'],
            },
        );

        $admitted = $client->admitTarget('https://api.example.com/v1/status');
        self::assertSame('93.184.216.34', $admitted['ip']);
        self::assertSame(443, $admitted['port']);

        // Cloud metadata IP blocked
        try {
            $client->admitTarget('https://metadata.internal/latest/meta-data/');
            self::fail('Expected SSRF metadata IP to be blocked.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('SSRF blocked', $e->getMessage());
        }

        // Plain HTTP blocked by default
        try {
            $client->admitTarget('http://api.example.com/v1');
            self::fail('Expected plain HTTP to be blocked.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('scheme "http"', $e->getMessage());
        }

        // Unlisted host blocked
        try {
            $client->admitTarget('https://unlisted.example.org/');
            self::fail('Expected unlisted host to be blocked.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('allowlist', $e->getMessage());
        }
    }

    public function testRateLimitMiddlewareEnforcesQuotaAndReturns429(): void
    {
        $app = App::create(__DIR__)
            ->middleware(new RateLimitMiddleware(new MemoryCache(), maxRequests: 2, windowSeconds: 60))
            ->routes(static function (Router $r): void {
                $r->get('/api/ping', static fn(): array => ['ok' => true]);
            });

        $r1 = $app->handle(Request::create('GET', '/api/ping'));
        self::assertSame(200, $r1->getStatusCode());
        self::assertSame('1', $r1->getHeaderLine('X-RateLimit-Remaining'));

        $r2 = $app->handle(Request::create('GET', '/api/ping'));
        self::assertSame(200, $r2->getStatusCode());
        self::assertSame('0', $r2->getHeaderLine('X-RateLimit-Remaining'));

        $r3 = $app->handle(Request::create('GET', '/api/ping'));
        self::assertSame(429, $r3->getStatusCode());
        self::assertSame('60', $r3->getHeaderLine('Retry-After'));
    }

    public function testEncryptorAeadAndKeyRotation(): void
    {
        $oldKey = Encryptor::generateKey();
        $newKey = Encryptor::generateKey();

        $oldEnc = new Encryptor($oldKey);
        $cipher = $oldEnc->encrypt('top-secret-payload', associatedData: 'tenant:42');
        self::assertStringStartsWith('v1.', $cipher);
        self::assertSame('top-secret-payload', $oldEnc->decrypt($cipher, associatedData: 'tenant:42'));

        // Key rotation decrypts old payloads transparently with previousKeys
        $rotated = new Encryptor($newKey, previousKeys: [$oldKey]);
        self::assertSame('top-secret-payload', $rotated->decrypt($cipher, associatedData: 'tenant:42'));

        // Wrong associated data fails closed
        try {
            $rotated->decrypt($cipher, associatedData: 'tenant:99');
            self::fail('Expected AAD mismatch to throw SecurityException.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('Decryption failed', $e->getMessage());
        }

        // Tampered ciphertext fails closed
        $this->expectException(SecurityException::class);
        $rotated->decrypt($cipher . 'A', associatedData: 'tenant:42');
    }

    public function testSignedUrlSignsVerifiesAndExpires(): void
    {
        $signer = new SignedUrl('signed-url-secret-key-at-least-16-bytes');

        $permanent = $signer->sign('/downloads/report.pdf', ['user' => 7]);
        self::assertTrue($signer->verify($permanent));
        self::assertFalse($signer->verify($permanent . '&evil=1'));
        self::assertFalse($signer->verify(str_replace('user=7', 'user=8', $permanent)));

        $temp = $signer->temporary('/verify-email', ttlSeconds: 300, query: ['id' => 42], now: 1000);
        self::assertTrue($signer->verify($temp, now: 1200));
        self::assertFalse($signer->verify($temp, now: 1300));
    }

    public function testCanAttributeEnforcesCapabilitiesOnControllers(): void
    {
        $bearer = new BearerAuthMiddleware(static fn(string $token): ?Principal => match ($token) {
            'reader-tok' => new Principal('u-1', PrincipalKind::Human, ['reports.read']),
            'admin-tok' => new Principal('u-2', PrincipalKind::Human, ['reports.read', 'reports.delete']),
            default => null,
        });

        $app = App::create(__DIR__)
            ->instance(BearerAuthMiddleware::class, $bearer)
            ->controller(GuardedReportsController::class);

        self::assertSame(401, $app->handle(Request::create('GET', '/reports/secret'))->getStatusCode());
        self::assertSame(403, $app->handle(Request::create('GET', '/reports/secret', ['Authorization' => 'Bearer reader-tok']))->getStatusCode());
        self::assertSame(200, $app->handle(Request::create('GET', '/reports/secret', ['Authorization' => 'Bearer admin-tok']))->getStatusCode());
    }

    public function testWebhookSignerAndVerifyWebhookAttribute(): void
    {
        $signer = new WebhookSigner('webhook-signing-secret-1234567890');
        $body = '{"event":"invoice.paid","amount":4200}';
        $sig = $signer->sign($body, timestamp: 1000);

        self::assertTrue($signer->verify($body, $sig, toleranceSeconds: 300, now: 1200));
        self::assertFalse($signer->verify($body, $sig, toleranceSeconds: 300, now: 1500));
        self::assertFalse($signer->verify($body . 'x', $sig, toleranceSeconds: 300, now: 1200));

        $app = App::create(__DIR__)
            ->instance(WebhookSigner::class, $signer)
            ->controller(GuardedReportsController::class);

        // Missing or invalid signature fails closed 401
        self::assertSame(401, $app->handle(Request::create('POST', '/webhooks/billing', body: $body))->getStatusCode());
        self::assertSame(401, $app->handle(Request::create('POST', '/webhooks/billing', [WebhookSigner::DEFAULT_HEADER => 't=1,v1=bad'], body: $body))->getStatusCode());

        // Valid fresh signature succeeds 200
        $freshSig = $signer->sign($body);
        $ok = $app->handle(Request::create('POST', '/webhooks/billing', [WebhookSigner::DEFAULT_HEADER => $freshSig], body: $body));
        self::assertSame(200, $ok->getStatusCode());
        self::assertSame('{"received":true}', (string) $ok->getBody());
    }

    public function testTotpRfc6238VerificationProvisioningUriAndRecoveryCodes(): void
    {
        // RFC 6238 Appendix B SHA-1 test vector: ASCII "12345678901234567890" -> Base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        $rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
        $totp8 = new Totp(digits: 8, period: 30);
        self::assertSame('94287082', $totp8->code($rfcSecret, timestamp: 59));

        $totp6 = new Totp(digits: 6, period: 30);
        $secret = Totp::generateSecret();
        $code = $totp6->code($secret, timestamp: 1_700_000_000);
        self::assertSame(6, strlen($code));
        self::assertTrue($totp6->verify($secret, $code, window: 1, timestamp: 1_700_000_000));
        self::assertTrue($totp6->verify($secret, $code, window: 1, timestamp: 1_700_000_030)); // +/- 1 step drift
        self::assertFalse($totp6->verify($secret, $code, window: 1, timestamp: 1_700_000_120)); // too old
        self::assertFalse($totp6->verify($secret, '000000', window: 0, timestamp: 1_700_000_000));

        $uri = $totp6->provisioningUri($secret, 'ada@kongono.dev', 'Kongono');
        self::assertStringStartsWith('otpauth://totp/Kongono:ada%40kongono.dev?', $uri);
        self::assertStringContainsString('secret=' . $secret, $uri);

        $recovery = Totp::generateRecoveryCodes(4);
        self::assertCount(4, $recovery);
        self::assertMatchesRegularExpression('/\A[0-9A-F]{4}-[0-9A-F]{4}\z/', $recovery[0]);
    }

    public function testAiThreatShieldBlocksHoneypotsReconBurstsAndComputeBudgets(): void
    {
        $cache = new MemoryCache();
        $shield = new AiThreatShieldMiddleware(
            cache: $cache,
            banSeconds: 600,
            maxProbesPerWindow: 2,
            maxCostUnitsPerWindow: 100,
        );

        $app = App::create(__DIR__)->middleware($shield);
        $app->router()->get('/ok', static fn(): Response => Response::json(['ok' => true]));
        $app->router()->post('/signup', static fn(): Response => Response::json(['ok' => true]));

        // Normal traffic succeeds with active shield header
        $goodReq = Request::create('GET', '/ok', serverParams: ['REMOTE_ADDR' => '198.51.100.10']);
        $goodRes = $app->handle($goodReq);
        self::assertSame(200, $goodRes->getStatusCode());
        self::assertSame('active', $goodRes->getHeaderLine('X-Kongono-Shield'));

        // Autonomous recon bot probing /.env gets banned immediately
        $botEnv = Request::create('GET', '/.env', serverParams: ['REMOTE_ADDR' => '198.51.100.20']);
        $trapRes = $app->handle($botEnv);
        self::assertSame(403, $trapRes->getStatusCode());
        self::assertSame('honeypot-triggered', $trapRes->getHeaderLine('X-Kongono-Shield'));
        self::assertTrue($shield->isBanned('198.51.100.20'));

        // Subsequent request to a real endpoint from the banned IP fails closed 403
        $followUp = $app->handle(Request::create('GET', '/ok', serverParams: ['REMOTE_ADDR' => '198.51.100.20']));
        self::assertSame(403, $followUp->getStatusCode());
        self::assertSame('blocked', $followUp->getHeaderLine('X-Kongono-Shield'));

        // Hidden honeypot form field catches blind form-filling bot
        $formBot = Request::create('POST', '/signup', parsedBody: [
            'email' => 'bot@spam.example',
            '_hp_website' => 'https://spam.example',
        ], serverParams: ['REMOTE_ADDR' => '198.51.100.30']);
        $formRes = $app->handle($formBot);
        self::assertSame(403, $formRes->getStatusCode());
        self::assertSame('honeypot-field', $formRes->getHeaderLine('X-Kongono-Shield'));

        // 404 recon burst auto-bans after threshold
        $scannerIp = '198.51.100.40';
        self::assertSame(404, $app->handle(Request::create('GET', '/nope-1', serverParams: ['REMOTE_ADDR' => $scannerIp]))->getStatusCode());
        self::assertFalse($shield->isBanned($scannerIp));
        self::assertSame(404, $app->handle(Request::create('GET', '/nope-2', serverParams: ['REMOTE_ADDR' => $scannerIp]))->getStatusCode());
        self::assertTrue($shield->isBanned($scannerIp));
        $shield->unban($scannerIp);
        self::assertFalse($shield->isBanned($scannerIp));

        // Cost-aware compute budget guard fails closed with 429
        $budgetIp = '198.51.100.50';
        self::assertSame(100, $shield->recordCostUnits($budgetIp, 100));
        $budgetRes = $app->handle(Request::create('GET', '/ok', serverParams: ['REMOTE_ADDR' => $budgetIp]));
        self::assertSame(429, $budgetRes->getStatusCode());
        self::assertSame('budget-exceeded', $budgetRes->getHeaderLine('X-Kongono-Shield'));
    }

    public function testSafeHttpClientRequestManyEnforcesSsrfFailClosedUpfront(): void
    {
        $client = new SafeHttpClient(dnsResolver: static fn(string $host): array => match ($host) {
            'api.example.com' => ['93.184.216.34'],
            'internal.local' => ['10.0.0.5'],
            default => ['127.0.0.1'],
        });

        self::assertSame([], $client->requestMany([]));

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('SSRF blocked');
        $client->requestMany([
            'safe' => ['url' => 'https://api.example.com/v1/status'],
            'ssrf' => ['url' => 'https://internal.local/admin'],
        ]);
    }
}

final readonly class GuardedReportsController
{
    #[Get('/reports/secret', name: 'reports.secret')]
    #[Middleware(BearerAuthMiddleware::class)]
    #[Can('reports.delete')]
    public function secret(Principal $principal): Response
    {
        return Response::json(['ok' => true, 'actor' => $principal->id]);
    }

    #[Post('/webhooks/billing', name: 'webhooks.billing')]
    #[VerifyWebhook]
    public function billingWebhook(): Response
    {
        return Response::json(['received' => true]);
    }
}
