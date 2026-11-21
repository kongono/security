<?php

declare(strict_types=1);

namespace Kongono\Security\Tests;

use Kongono\Core\Cache\MemoryCache;
use Kongono\Http\App;
use Kongono\Http\HttpException;
use Kongono\Http\Request;
use Kongono\Http\Response;
use Kongono\Http\Routing\Router;
use Kongono\Security\Egress\SafeHttpClient;
use Kongono\Security\Encryptor;
use Kongono\Security\Gate;
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
}
