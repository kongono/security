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
use Kongono\Security\Auth\MagicLinkAuth;
use Kongono\Security\Auth\PasskeyVerifier;
use Kongono\Security\Auth\PkceOAuthClient;
use Kongono\Security\Egress\SafeHttpClient;
use Kongono\Security\Encryptor;
use Kongono\Security\Gate;
use Kongono\Security\Middleware\AiThreatShieldMiddleware;
use Kongono\Security\Middleware\BearerAuthMiddleware;
use Kongono\Security\Middleware\CorsMiddleware;
use Kongono\Security\Middleware\CsrfMiddleware;
use Kongono\Security\Middleware\RateLimitMiddleware;
use Kongono\Security\Middleware\SecurityHeadersMiddleware;
use Kongono\Security\Middleware\VerifyWebhookMiddleware;
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
        self::assertMatchesRegularExpression('/\A[0-9A-F]{4}(?:-[0-9A-F]{4}){4}\z/', $recovery[0]);
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

    public function testZeroVendorAuthSuiteMagicLinkPkceOAuthAndPasskeys(): void
    {
        $cache = new MemoryCache();

        // 1. Single-use Magic Link auth
        $magic = new MagicLinkAuth('super-secret-magic-link-signing-key-32bytes', $cache);
        $link = $magic->createLink('/auth/magic', 'Ada@Kongono.dev', ttlSeconds: 600, claims: ['role' => 'owner'], now: 1000);
        $consumed = $magic->consume($link, now: 1100);
        self::assertSame('ada@kongono.dev', $consumed['email']);
        self::assertSame(['role' => 'owner'], $consumed['claims']);

        // Replaying the same magic link fails closed
        try {
            $magic->consume($link, now: 1105);
            self::fail('Expected replayed magic link to fail.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('already been consumed', $e->getMessage());
        }

        // 2. PKCE S256 OAuth2 Client (GitHub & Google presets)
        $oauthCalls = [];
        $github = PkceOAuthClient::github(
            clientId: 'gh_client_1',
            clientSecret: 'gh_secret_1',
            transportOverride: static function (string $method, string $url, array $headers, ?string $body) use (&$oauthCalls): array {
                $oauthCalls[] = [$method, $url, $body];
                if (str_contains($url, 'access_token')) {
                    return ['status' => 200, 'body' => '{"access_token":"gho_test_token","token_type":"bearer"}'];
                }

                return ['status' => 200, 'body' => '{"id":7,"login":"ada","email":"ada@kongono.dev"}'];
            },
        );
        $authStart = $github->beginAuthorization('https://app.kongono.dev/auth/github/callback');
        self::assertStringStartsWith('https://github.com/login/oauth/authorize?', $authStart['url']);
        self::assertStringContainsString('code_challenge_method=S256', $authStart['url']);
        $expectedChallenge = PasskeyVerifier::base64UrlEncode(hash('sha256', $authStart['code_verifier'], true));
        self::assertSame($expectedChallenge, $authStart['code_challenge']);

        $github->verifyState($authStart['state'], $authStart['state']);
        $tokens = $github->exchangeCode('auth_code_123', 'https://app.kongono.dev/auth/github/callback', $authStart['code_verifier']);
        self::assertSame('gho_test_token', $tokens['access_token']);
        $profile = $github->fetchUserInfo('gho_test_token');
        self::assertSame('ada', $profile['login']);
        self::assertCount(2, $oauthCalls);

        // 3. Pure PHP WebAuthn / FIDO2 Passkey verification (EdDSA Ed25519)
        $passkeys = new PasskeyVerifier($cache);
        $challengeData = $passkeys->createChallenge('kongono.dev', 'https://kongono.dev', ttlSeconds: 300, now: 2000);

        $kp = sodium_crypto_sign_keypair();
        $secretKey = sodium_crypto_sign_secretkey($kp);
        $publicKeyHex = bin2hex(sodium_crypto_sign_publickey($kp));

        $clientDataRaw = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $challengeData['challenge'],
            'origin' => 'https://kongono.dev',
        ], JSON_THROW_ON_ERROR);
        $authData = hash('sha256', 'kongono.dev', true) . chr(0x05) . pack('N', 4); // UP|UV flags, signCount=4
        $signature = sodium_crypto_sign_detached($authData . hash('sha256', $clientDataRaw, true), $secretKey);

        $verified = $passkeys->verifyAssertion(
            expectedChallenge: $challengeData['challenge'],
            clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($clientDataRaw),
            authenticatorDataBase64Url: PasskeyVerifier::base64UrlEncode($authData),
            signatureBase64Url: PasskeyVerifier::base64UrlEncode($signature),
            publicKey: $publicKeyHex,
            algorithm: 'EdDSA',
            previousSignCount: 3,
            requireUserVerification: true,
            now: 2050,
        );
        self::assertSame(4, $verified['signCount']);
        self::assertTrue($verified['userPresent']);
        self::assertTrue($verified['userVerified']);

        // Replay of consumed WebAuthn challenge fails closed
        try {
            $passkeys->verifyAssertion(
                expectedChallenge: $challengeData['challenge'],
                clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($clientDataRaw),
                authenticatorDataBase64Url: PasskeyVerifier::base64UrlEncode($authData),
                signatureBase64Url: PasskeyVerifier::base64UrlEncode($signature),
                publicKey: $publicKeyHex,
                algorithm: 'EdDSA',
                now: 2055,
            );
            self::fail('Expected replayed passkey challenge to fail.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('already consumed', $e->getMessage());
        }

        // Cloned authenticator signCount rollback fails closed
        $c2 = $passkeys->createChallenge('kongono.dev', 'https://kongono.dev', now: 2100);
        $cd2 = json_encode(['type' => 'webauthn.get', 'challenge' => $c2['challenge'], 'origin' => 'https://kongono.dev'], JSON_THROW_ON_ERROR);
        $ad2 = hash('sha256', 'kongono.dev', true) . chr(0x01) . pack('N', 4);
        $sig2 = sodium_crypto_sign_detached($ad2 . hash('sha256', $cd2, true), $secretKey);
        try {
            $passkeys->verifyAssertion(
                expectedChallenge: $c2['challenge'],
                clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($cd2),
                authenticatorDataBase64Url: PasskeyVerifier::base64UrlEncode($ad2),
                signatureBase64Url: PasskeyVerifier::base64UrlEncode($sig2),
                publicKey: $publicKeyHex,
                algorithm: 'EdDSA',
                previousSignCount: 4,
                now: 2110,
            );
            self::fail('Expected cloned authenticator signCount rollback to fail.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('cloned authenticator', $e->getMessage());
        }
    }

    public function testBrutalSecurityHardeningSsrfIpv6CsrfHoneypotHeadersCorsAndCrossOriginPasskey(): void
    {
        // 1. SafeHttpClient blocks IPv4-mapped IPv6, CGNAT, ULA, link-local, 0.0.0.0, and mixed-record DNS rebinding
        $safeHttp = new SafeHttpClient(dnsResolver: static fn(string $host): array => match ($host) {
            'rebind.evil.test' => ['93.184.216.34', '127.0.0.1'],
            'v6mapped.test' => ['::ffff:169.254.169.254'],
            default => ['93.184.216.34'],
        });
        self::assertFalse($safeHttp->isIpAdmitted('::ffff:127.0.0.1'));
        self::assertFalse($safeHttp->isIpAdmitted('::ffff:169.254.169.254'));
        self::assertFalse($safeHttp->isIpAdmitted('::ffff:10.0.0.1'));
        self::assertFalse($safeHttp->isIpAdmitted('100.64.0.1'));
        self::assertFalse($safeHttp->isIpAdmitted('0.0.0.0'));
        self::assertFalse($safeHttp->isIpAdmitted('fd00::1'));
        self::assertFalse($safeHttp->isIpAdmitted('fe80::1'));
        self::assertTrue($safeHttp->isIpAdmitted('93.184.216.34'));

        foreach (['https://rebind.evil.test/', 'https://v6mapped.test/'] as $hostileUrl) {
            try {
                $safeHttp->admitTarget($hostileUrl);
                self::fail('Expected SSRF target to fail closed: ' . $hostileUrl);
            } catch (SecurityException $e) {
                self::assertStringContainsString('SSRF blocked', $e->getMessage());
            }
        }

        // 2. CsrfMiddleware rejects query-string CSRF tokens and traversal bypasses of exemptPrefixes
        $signer = new TokenSigner('csrf-hardening-secret-key-at-least-32-bytes');
        $csrfApp = App::create(__DIR__)
            ->middleware(new CsrfMiddleware($signer, exemptPrefixes: ['/api/']))
            ->routes(static function (Router $r): void {
                $r->post('/form', static fn(): Response => Response::text('ok'));
                $r->post('/api/../form', static fn(): Response => Response::text('bypassed'));
            });
        $validCsrf = $signer->generateCsrfToken('sess-abc');
        $queryTokenReq = Request::create('POST', '/form?_csrf=' . rawurlencode($validCsrf))
            ->withCookieParams(['kongono_session' => 'sess-abc']);
        self::assertInstanceOf(Request::class, $queryTokenReq);
        self::assertSame(403, $csrfApp->handle($queryTokenReq)->getStatusCode());
        self::assertSame(403, $csrfApp->handle(Request::create('POST', '/api/../form'))->getStatusCode());

        // 3. AiThreatShieldMiddleware catches obfuscated honeypot paths (//.env, /./.env, /%2eenv, /.env.)
        foreach (['//.env', '/./.env', '/%2eenv', '/.env.'] as $idx => $evasionPath) {
            $shield = new AiThreatShieldMiddleware(new MemoryCache());
            $shieldApp = App::create(__DIR__)->middleware($shield);
            $ip = '203.0.113.' . (10 + $idx);
            $res = $shieldApp->handle(Request::create('GET', $evasionPath, serverParams: ['REMOTE_ADDR' => $ip]));
            self::assertSame(403, $res->getStatusCode(), 'Expected honeypot catch for ' . $evasionPath);
            self::assertTrue($shield->isBanned($ip));
        }

        // 4. SecurityHeadersMiddleware emits hardened CSP, Permissions-Policy, and HTTPS HSTS
        $secApp = App::create(__DIR__)
            ->middleware(new SecurityHeadersMiddleware())
            ->routes(static function (Router $r): void {
                $r->get('/secure', static fn(): Response => Response::text('ok'));
            });
        $secRes = $secApp->handle(Request::create('GET', 'https://app.kongono.dev/secure'));
        self::assertStringContainsString("object-src 'none'", $secRes->getHeaderLine('Content-Security-Policy'));
        self::assertStringContainsString("base-uri 'self'", $secRes->getHeaderLine('Content-Security-Policy'));
        self::assertStringContainsString('camera=()', $secRes->getHeaderLine('Permissions-Policy'));
        self::assertStringContainsString('max-age=31536000', $secRes->getHeaderLine('Strict-Transport-Security'));

        // 5. CorsMiddleware rejects wildcard origin + credentials misconfiguration at construction
        try {
            new CorsMiddleware(allowedOrigins: ['*'], allowCredentials: true);
            self::fail('Expected wildcard CORS + credentials misconfiguration to fail closed.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('allowCredentials', $e->getMessage());
        }

        // 5b. PasswordHasher & TokenSigner reject oversized DoS payloads
        $hasher = new PasswordHasher();
        $hugePassword = str_repeat('a', PasswordHasher::MAX_PASSWORD_BYTES + 1);
        try {
            $hasher->hash($hugePassword);
            self::fail('Expected oversized password hash to fail closed.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('exceeds maximum length', $e->getMessage());
        }
        self::assertFalse($hasher->verify($hugePassword, '$argon2id$v=19$m=65536,t=4,p=1$fake$fake'));
        self::assertNull($signer->verify(str_repeat('A', TokenSigner::MAX_TOKEN_BYTES + 10)));

        // 6. PasskeyVerifier rejects crossOrigin: true assertions by default
        $cache = new MemoryCache();
        $passkeys = new PasskeyVerifier($cache);
        $ch = $passkeys->createChallenge('kongono.dev', 'https://kongono.dev', now: 3000);
        $kp = sodium_crypto_sign_keypair();
        $cdCross = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $ch['challenge'],
            'origin' => 'https://kongono.dev',
            'crossOrigin' => true,
        ], JSON_THROW_ON_ERROR);
        $ad = hash('sha256', 'kongono.dev', true) . chr(0x01) . pack('N', 1);
        $sig = sodium_crypto_sign_detached($ad . hash('sha256', $cdCross, true), sodium_crypto_sign_secretkey($kp));
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Cross-origin passkey assertions are denied');
        $passkeys->verifyAssertion(
            expectedChallenge: $ch['challenge'],
            clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($cdCross),
            authenticatorDataBase64Url: PasskeyVerifier::base64UrlEncode($ad),
            signatureBase64Url: PasskeyVerifier::base64UrlEncode($sig),
            publicKey: bin2hex(sodium_crypto_sign_publickey($kp)),
            algorithm: 'EdDSA',
            now: 3010,
        );
    }

    public function testRound3SsrfSignedUrlRateLimitThreatShieldPasskeyTotpTokenAndWebhookHardening(): void
    {
        // 1. SafeHttpClient blocks percent-encoded hosts, invalid HTTP methods, and IPv6/IPv4 special-use ranges
        $client = new SafeHttpClient(
            dnsResolver: static fn(): array => ['93.184.216.34'],
        );
        foreach (['https://%72ebind.example.com/', 'https://evil\\@example.com/'] as $badUrl) {
            try {
                $client->request('GET', $badUrl);
                self::fail('Expected SafeHttpClient to reject: ' . $badUrl);
            } catch (SecurityException) {
                self::addToAssertionCount(1);
            }
        }
        try {
            $client->request("GET / HTTP/1.1\r\nHost: evil", 'https://example.com/');
            self::fail('Expected invalid HTTP method to be rejected.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('Invalid outbound HTTP method', $e->getMessage());
        }
        foreach (['2002:a9fe:a9fe::1', '2001:0000:4136:e378::1', '100::1', 'fec0::1', '198.18.0.1', '192.0.2.1'] as $blockedIp) {
            $ipClient = new SafeHttpClient(dnsResolver: static fn(): array => [$blockedIp]);
            try {
                $ipClient->request('GET', 'https://target.example.com/');
                self::fail('Expected special-use IP to be blocked: ' . $blockedIp);
            } catch (SecurityException $e) {
                self::assertStringContainsString('SSRF blocked', $e->getMessage());
            }
        }

        // 2. SignedUrl: rejects HPP duplicate params, fragments, origin mismatches, and >100 params; preserves full URL origin
        $signedUrl = new SignedUrl('signed-url-round3-key-at-least-32-bytes!');
        $fullSigned = $signedUrl->temporary('https://app.kongono.dev/download', 300, ['file' => 'a.pdf'], now: 5000);
        self::assertTrue($signedUrl->verify($fullSigned, now: 5010));
        self::assertFalse($signedUrl->verify(str_replace('https://app.kongono.dev', 'https://evil.test', $fullSigned), now: 5010));
        self::assertFalse($signedUrl->verify($fullSigned . '&file=evil.pdf', now: 5010));
        self::assertFalse($signedUrl->verify($fullSigned . '#frag', now: 5010));
        $manyParams = '/p?' . implode('&', array_map(static fn(int $i): string => "k{$i}=1", range(1, 105)));
        self::assertFalse($signedUrl->verify($manyParams, now: 5010));

        // 3. RateLimitMiddleware canonicalizes /login, /login/, //login into ONE shared bucket
        $rlCache = new MemoryCache();
        $rlApp = App::create(__DIR__)
            ->middleware(new RateLimitMiddleware($rlCache, maxRequests: 2, windowSeconds: 60))
            ->routes(static function (Router $r): void {
                $r->post('/login', static fn(): Response => Response::text('ok'));
            });
        self::assertSame(200, $rlApp->handle(Request::create('POST', '/login', serverParams: ['REMOTE_ADDR' => '198.51.100.9']))->getStatusCode());
        self::assertSame(200, $rlApp->handle(Request::create('POST', '/login/', serverParams: ['REMOTE_ADDR' => '198.51.100.9']))->getStatusCode());
        self::assertSame(429, $rlApp->handle(Request::create('POST', '//login///', serverParams: ['REMOTE_ADDR' => '198.51.100.9']))->getStatusCode());

        // 4. AiThreatShieldMiddleware catches dot-segment & matrix-param evasions AND global-middleware 401 recon bursts
        foreach (['/../.env', '/foo/../.env', '/%2e%2e/.env', '/.env;foo=bar', '/.../.env'] as $idx => $evasion) {
            $shield = new AiThreatShieldMiddleware(new MemoryCache());
            $app = App::create(__DIR__)->middleware($shield);
            $ip = '198.51.100.' . (20 + $idx);
            $res = $app->handle(Request::create('GET', $evasion, serverParams: ['REMOTE_ADDR' => $ip]));
            self::assertSame(403, $res->getStatusCode(), 'Expected evasion catch for ' . $evasion);
            self::assertTrue($shield->isBanned($ip));
        }

        $burstShield = new AiThreatShieldMiddleware(new MemoryCache(), maxProbesPerWindow: 2);
        $burstApp = App::create(__DIR__)
            ->middleware($burstShield)
            ->routes(static function (Router $r): void {
                $r->get('/secret', static function (): Response {
                    throw new HttpException(401, 'Unauthorized');
                });
            });
        $attackerIp = '198.51.100.99';
        self::assertSame(401, $burstApp->handle(Request::create('GET', '/secret', serverParams: ['REMOTE_ADDR' => $attackerIp]))->getStatusCode());
        self::assertSame(401, $burstApp->handle(Request::create('GET', '/secret', serverParams: ['REMOTE_ADDR' => $attackerIp]))->getStatusCode());
        self::assertTrue($burstShield->isBanned($attackerIp));
        self::assertSame(403, $burstApp->handle(Request::create('GET', '/secret', serverParams: ['REMOTE_ADDR' => $attackerIp]))->getStatusCode());

        // 5. PasskeyVerifier: W3C signCount=0 clone detection when previousSignCount > 0 + atomic single-use challenge
        $pkCache = new MemoryCache();
        $passkeys = new PasskeyVerifier($pkCache);
        $ch = $passkeys->createChallenge('kongono.dev', 'https://kongono.dev', now: 4000);
        $kp = sodium_crypto_sign_keypair();
        $cd = json_encode(['type' => 'webauthn.get', 'challenge' => $ch['challenge'], 'origin' => 'https://kongono.dev', 'crossOrigin' => false], JSON_THROW_ON_ERROR);
        $adZero = hash('sha256', 'kongono.dev', true) . chr(0x01) . pack('N', 0);
        $sigZero = sodium_crypto_sign_detached($adZero . hash('sha256', $cd, true), sodium_crypto_sign_secretkey($kp));
        try {
            $passkeys->verifyAssertion(
                expectedChallenge: $ch['challenge'],
                clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($cd),
                authenticatorDataBase64Url: PasskeyVerifier::base64UrlEncode($adZero),
                signatureBase64Url: PasskeyVerifier::base64UrlEncode($sigZero),
                publicKey: bin2hex(sodium_crypto_sign_publickey($kp)),
                algorithm: 'EdDSA',
                previousSignCount: 5,
                now: 4010,
            );
            self::fail('Expected signCount=0 rollback to be flagged as cloned authenticator.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('cloned authenticator', strtolower($e->getMessage()));
        }

        // 6. Totp: 80-bit recovery codes + single-use replay rejection
        $codes = Totp::generateRecoveryCodes(4);
        self::assertCount(4, $codes);
        self::assertMatchesRegularExpression('/\A[0-9A-F]{4}(?:-[0-9A-F]{4}){4}\z/', $codes[0]);
        $totp = new Totp();
        $totpSecret = Totp::generateSecret();
        $code = $totp->code($totpSecret, timestamp: 1_700_000_000);
        $replayCache = new MemoryCache();
        $step = $totp->verifyAndReturnTimeStep($totpSecret, $code, timestamp: 1_700_000_000, replayCache: $replayCache);
        self::assertNotNull($step);
        self::assertNull($totp->verifyAndReturnTimeStep($totpSecret, $code, timestamp: 1_700_000_000, replayCache: $replayCache));
        self::assertNull($totp->verifyAndReturnTimeStep($totpSecret, $code, timestamp: 1_700_000_000, lastVerifiedStep: $step));

        // 7. TokenSigner: domain separation prevents CSRF token from verifying as general bearer token
        $signer = new TokenSigner('domain-sep-key-at-least-32-bytes-long!!');
        $csrfTok = $signer->generateCsrfToken('sess-123');
        self::assertNull($signer->verify($csrfTok));
        self::assertTrue($signer->verifyCsrfToken($csrfTok, 'sess-123'));

        // 8. WebhookSigner duplicate t= rejection & VerifyWebhookMiddleware atomic replay protection (409)
        $whSigner = new WebhookSigner('webhook-secret-key-at-least-32-bytes!!');
        $payload = '{"event":"invoice.paid"}';
        $now = time();
        $goodSig = $whSigner->sign($payload, $now);
        self::assertNull($whSigner->verifyAndFingerprint($payload, "t={$now},t={$now}," . substr($goodSig, strpos($goodSig, 'v1=') ?: 0)));

        $whApp = App::create(__DIR__)
            ->middleware(new VerifyWebhookMiddleware($whSigner, replayCache: new MemoryCache()))
            ->routes(static function (Router $r): void {
                $r->post('/hook', static fn(): Response => Response::text('ok'));
            });
        self::assertSame(200, $whApp->handle(Request::create('POST', '/hook', ['X-Kongono-Signature' => $goodSig], $payload))->getStatusCode());
        self::assertSame(409, $whApp->handle(Request::create('POST', '/hook', ['X-Kongono-Signature' => $goodSig], $payload))->getStatusCode());

        // 9. SecurityHeadersMiddleware attaches security headers even on thrown HttpException responses
        $hdrApp = App::create(__DIR__)
            ->middleware(new SecurityHeadersMiddleware())
            ->routes(static function (Router $r): void {
                $r->get('/boom', static function (): Response {
                    throw new HttpException(404, 'Missing');
                });
            });
        $errRes = $hdrApp->handle(Request::create('GET', '/boom'));
        self::assertSame(404, $errRes->getStatusCode());
        self::assertSame('nosniff', $errRes->getHeaderLine('X-Content-Type-Options'));
        self::assertSame('DENY', $errRes->getHeaderLine('X-Frame-Options'));
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
