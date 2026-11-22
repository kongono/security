<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Kongono\Http\HttpException;
use Kongono\Http\Request;
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
        private array $exemptPrefixes = ['/api/'],
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $method = strtoupper($request->getMethod());
        if (in_array($method, self::SAFE_METHODS, true)) {
            return $handler->handle($request);
        }

        $rawPath = $request->getUri()->getPath();
        $decodedPath = rawurldecode($rawPath);
        // Never allow path traversal / backslash smuggling to match an exempt prefix
        if (!str_contains($rawPath, '..') && !str_contains($decodedPath, '..') && !str_contains($rawPath, '\\') && !str_contains($decodedPath, '\\')) {
            $normalizedPath = (string) preg_replace('#/+#', '/', '/' . ltrim($decodedPath, '/'));
            foreach ($this->exemptPrefixes as $prefix) {
                if (str_starts_with($normalizedPath, $prefix)) {
                    return $handler->handle($request);
                }
            }
        }

        $cookies = $request->getCookieParams();
        $sessionId = is_string($cookies[$this->sessionCookieName] ?? null) ? $cookies[$this->sessionCookieName] : '';
        if ('' === $sessionId) {
            throw new HttpException(403, 'CSRF verification failed: missing session context.');
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
