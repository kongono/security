<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Kongono\Http\HttpException;
use Kongono\Http\Request;
use Kongono\Http\Session\Session;
use Kongono\Security\TokenSigner;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Protects browser state-changing methods (POST/PUT/PATCH/DELETE) with signed CSRF tokens.
 * Safe methods (GET/HEAD/OPTIONS) and explicitly listed stateless prefixes (e.g. /api/) are skipped.
 */
final readonly class CsrfMiddleware implements MiddlewareInterface
{
    private const array SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

    /** @param list<string> $exemptPrefixes */
    public function __construct(
        private TokenSigner $signer,
        private string $sessionCookieName = 'kongono_session',
        private string $headerName = 'X-CSRF-Token',
        private string $formField = '_csrf',
        private array $exemptPrefixes = [],
        private bool $requirePersistedSession = false,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $method = strtoupper($request->getMethod());
        if (in_array($method, self::SAFE_METHODS, true)) {
            return $handler->handle($request);
        }

        $cookies = $request->getCookieParams();
        $hasSessionCookie = array_key_exists($this->sessionCookieName, $cookies);
        $authHeader = trim($request->getHeaderLine('Authorization'));
        // Stateless Bearer-authenticated API requests that do not send a session cookie are immune to ambient-cookie CSRF
        if (!$hasSessionCookie && str_starts_with(strtolower($authHeader), 'bearer ') && strlen($authHeader) > 7) {
            return $handler->handle($request);
        }

        $rawPath = $request->getUri()->getPath();
        // Match exemptPrefixes strictly against the non-decoded Router-canonical path and refuse any traversal,
        // backslash, NUL, or percent-encoded path delimiter/dot (%2e/%2f/%5c/%25/%00) to prevent parser differentials
        if (
            !str_contains($rawPath, '..')
            && !str_contains($rawPath, '\\')
            && !str_contains($rawPath, "\0")
            && 1 !== preg_match('/%(?:2e|2f|5c|25|00)/i', $rawPath)
        ) {
            $normalizedPath = (string) preg_replace('#/+#', '/', '/' . ltrim($rawPath, '/'));
            foreach ($this->exemptPrefixes as $prefix) {
                if ('' === $prefix) {
                    continue;
                }
                $matches = str_ends_with($prefix, '/')
                    ? str_starts_with($normalizedPath, $prefix)
                    : ($normalizedPath === $prefix || str_starts_with($normalizedPath, $prefix . '/'));
                if ($matches) {
                    return $handler->handle($request);
                }
            }
        }

        $session = $request->getAttribute(Session::class);
        if ($session instanceof Session) {
            if (!$session->isPersisted()) {
                throw new HttpException(403, 'CSRF verification failed: session is missing, expired, or revoked.');
            }
            $sessionId = $session->id();
        } else {
            if ($this->requirePersistedSession) {
                throw new HttpException(403, 'CSRF verification failed: verified session middleware context is required.');
            }
            $rawCookie = $cookies[$this->sessionCookieName] ?? null;
            $sessionId = is_string($rawCookie) ? $rawCookie : '';
            if ('' === $sessionId || strlen($sessionId) > 128 || 1 === preg_match('/[\x00-\x20\x7f]/', $sessionId)) {
                throw new HttpException(403, 'CSRF verification failed: missing session context.');
            }
        }

        $token = trim($request->getHeaderLine($this->headerName));
        if ('' === $token) {
            // Only read CSRF token from POST/parsed body — NEVER from URL query parameters
            $parsedBody = $request->getParsedBody();
            if (is_array($parsedBody) && is_string($parsedBody[$this->formField] ?? null)) {
                $token = trim($parsedBody[$this->formField]);
            } elseif ($request instanceof Request && str_contains(strtolower($request->getHeaderLine('Content-Type')), 'application/json')) {
                $json = $request->jsonBody();
                if (is_string($json[$this->formField] ?? null)) {
                    $token = trim($json[$this->formField]);
                }
            }
        }

        if ('' === $token || !$this->signer->verifyCsrfToken($token, $sessionId)) {
            throw new HttpException(403, 'CSRF token is missing or invalid.');
        }

        return $handler->handle($request);
    }
}
