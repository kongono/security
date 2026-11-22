<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Closure;
use Kongono\Security\Egress\SafeHttpClient;
use Kongono\Security\SecurityException;
use SensitiveParameter;

/**
 * Pure PHP 8.5 RFC 7636 OAuth 2.0 + PKCE (S256) client running over SSRF-hardened SafeHttpClient.
 *
 * Includes zero-dependency presets for GitHub and Google plus support for any standard OIDC provider.
 */
final readonly class PkceOAuthClient
{
    /**
     * @param list<string>                                                                                          $defaultScopes
     * @param (Closure(string, string, array<string, string>, ?string): array{status: int, body: string})|null      $transportOverride Optional test HTTP transport
     */
    public function __construct(
        private string $clientId,
        #[SensitiveParameter]
        private string $clientSecret,
        private string $authorizeUrl,
        private string $tokenUrl,
        private ?string $userInfoUrl = null,
        private array $defaultScopes = [],
        private ?SafeHttpClient $httpClient = null,
        private ?Closure $transportOverride = null,
    ) {
        if ('' === trim($clientId)) {
            throw new SecurityException('OAuth client ID cannot be empty.');
        }
    }

    /**
     * @param (Closure(string, string, array<string, string>, ?string): array{status: int, body: string})|null $transportOverride
     */
    public static function github(
        string $clientId,
        #[SensitiveParameter]
        string $clientSecret,
        ?SafeHttpClient $httpClient = null,
        ?Closure $transportOverride = null,
    ): self {
        return new self(
            clientId: $clientId,
            clientSecret: $clientSecret,
            authorizeUrl: 'https://github.com/login/oauth/authorize',
            tokenUrl: 'https://github.com/login/oauth/access_token',
            userInfoUrl: 'https://api.github.com/user',
            defaultScopes: ['read:user', 'user:email'],
            httpClient: $httpClient ?? new SafeHttpClient(allowedHosts: ['github.com', 'api.github.com']),
            transportOverride: $transportOverride,
        );
    }

    /**
     * @param (Closure(string, string, array<string, string>, ?string): array{status: int, body: string})|null $transportOverride
     */
    public static function google(
        string $clientId,
        #[SensitiveParameter]
        string $clientSecret,
        ?SafeHttpClient $httpClient = null,
        ?Closure $transportOverride = null,
    ): self {
        return new self(
            clientId: $clientId,
            clientSecret: $clientSecret,
            authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenUrl: 'https://oauth2.googleapis.com/token',
            userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
            defaultScopes: ['openid', 'email', 'profile'],
            httpClient: $httpClient ?? new SafeHttpClient(allowedHosts: ['oauth2.googleapis.com', 'openidconnect.googleapis.com']),
            transportOverride: $transportOverride,
        );
    }

    /**
     * Generate a PKCE S256 verifier/challenge pair, CSRF state token, and provider authorization URL.
     *
     * @param list<string> $scopes
     * @return array{url: string, state: string, code_verifier: string, code_challenge: string}
     */
    public function beginAuthorization(string $redirectUri, array $scopes = []): array
    {
        $state = self::base64UrlEncode(random_bytes(24));
        $verifier = self::base64UrlEncode(random_bytes(32));
        $challenge = self::base64UrlEncode(hash('sha256', $verifier, true));
        $effectiveScopes = [] !== $scopes ? $scopes : $this->defaultScopes;

        $query = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ];
        if ([] !== $effectiveScopes) {
            $query['scope'] = implode(' ', $effectiveScopes);
        }

        $sep = str_contains($this->authorizeUrl, '?') ? '&' : '?';

        return [
            'url' => $this->authorizeUrl . $sep . http_build_query($query, '', '&', PHP_QUERY_RFC3986),
            'state' => $state,
            'code_verifier' => $verifier,
            'code_challenge' => $challenge,
        ];
    }

    /** Constant-time CSRF state check on callback. */
    public function verifyState(string $expectedState, string $receivedState): void
    {
        if ('' === $expectedState || !hash_equals($expectedState, $receivedState)) {
            throw new SecurityException('OAuth state verification failed (possible CSRF attack).');
        }
    }

    /**
     * Exchange an authorization code + PKCE code_verifier for tokens over SafeHttpClient.
     *
     * @return array<string, mixed>
     */
    public function exchangeCode(string $code, string $redirectUri, #[SensitiveParameter] string $codeVerifier): array
    {
        if ('' === trim($code) || '' === trim($codeVerifier)) {
            throw new SecurityException('OAuth authorization code and PKCE code_verifier are required.');
        }

        $form = http_build_query([
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
        ], '', '&', PHP_QUERY_RFC3986);

        $res = $this->send('POST', $this->tokenUrl, [
            'Accept' => 'application/json',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ], $form);

        if ($res['status'] < 200 || $res['status'] >= 300) {
            throw new SecurityException(sprintf('OAuth token exchange failed with HTTP %d.', $res['status']));
        }

        $decoded = json_decode($res['body'], true);
        if (!is_array($decoded)) {
            throw new SecurityException('OAuth token endpoint returned non-JSON payload.');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * Fetch the authenticated user profile from the provider's UserInfo endpoint.
     *
     * @return array<string, mixed>
     */
    public function fetchUserInfo(#[SensitiveParameter] string $accessToken): array
    {
        if (null === $this->userInfoUrl || '' === $this->userInfoUrl) {
            throw new SecurityException('No OAuth userInfoUrl is configured for this provider.');
        }

        $res = $this->send('GET', $this->userInfoUrl, [
            'Accept' => 'application/json',
            'Authorization' => 'Bearer ' . $accessToken,
            'User-Agent' => 'Kongono-Framework/1.4',
        ], null);

        if ($res['status'] < 200 || $res['status'] >= 300) {
            throw new SecurityException(sprintf('OAuth userinfo request failed with HTTP %d.', $res['status']));
        }

        $decoded = json_decode($res['body'], true);
        if (!is_array($decoded)) {
            throw new SecurityException('OAuth userinfo endpoint returned non-JSON payload.');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param array<string, string> $headers
     * @return array{status: int, body: string}
     */
    private function send(string $method, string $url, array $headers, ?string $body): array
    {
        if (null !== $this->transportOverride) {
            return ($this->transportOverride)($method, $url, $headers, $body);
        }

        $client = $this->httpClient ?? new SafeHttpClient();

        return $client->request($method, $url, $headers, $body);
    }

    private static function base64UrlEncode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
