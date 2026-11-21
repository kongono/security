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

        $path = $request->getUri()->getPath();
        foreach ($this->exemptPrefixes as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return $handler->handle($request);
            }
        }

        $cookies = $request->getCookieParams();
        $sessionId = is_string($cookies[$this->sessionCookieName] ?? null) ? $cookies[$this->sessionCookieName] : '';
        if ('' === $sessionId) {
            throw new HttpException(403, 'CSRF verification failed: missing session context.');
        }

        $token = trim($request->getHeaderLine($this->headerName));
        if ('' === $token && $request instanceof Request) {
            $raw = $request->input($this->formField);
            if (is_string($raw)) {
                $token = trim($raw);
            }
        }

        if ('' === $token || !$this->signer->verifyCsrfToken($token, $sessionId)) {
            throw new HttpException(403, 'CSRF token is missing or invalid.');
        }

        return $handler->handle($request);
    }
}
