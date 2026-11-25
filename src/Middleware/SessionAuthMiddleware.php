<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Closure;
use Kongono\Http\Cookie;
use Kongono\Http\HttpException;
use Kongono\Http\Response;
use Kongono\Http\Session\Session;
use Kongono\Security\Auth\RememberMeManager;
use Kongono\Security\Auth\SessionAuth;
use Kongono\Security\Principal;
use Kongono\Security\SecurityException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Hydrates a typed {@see Principal} from Kongono's persistent-runtime-safe {@see Session}
 * (and optionally rotates a {@see RememberMeManager} cookie on resume).
 *
 * Place AFTER `SessionMiddleware` in your middleware stack.
 *   - `$required = false` (default): hydrates `Principal::class` when logged in and lets public routes run
 *   - `$required = true`: rejects guests with a 302 redirect to `$loginRedirectUrl` (for browser HTML) or HTTP 401 (for JSON/API)
 */
final readonly class SessionAuthMiddleware implements MiddlewareInterface
{
    /**
     * @param (Closure(Principal): ?Principal)|null $principalResolver Optional live re-hydration / revocation check
     */
    public function __construct(
        private ?Closure $principalResolver = null,
        private bool $required = false,
        private ?string $loginRedirectUrl = null,
        private SessionAuth $auth = new SessionAuth(),
        private ?RememberMeManager $rememberMe = null,
    ) {
        if (null !== $loginRedirectUrl && (!str_starts_with($loginRedirectUrl, '/') || str_starts_with($loginRedirectUrl, '//') || 1 === preg_match('/[\x00-\x1f\x7f\\\\]/', $loginRedirectUrl))) {
            throw new SecurityException('SessionAuthMiddleware loginRedirectUrl must be a safe same-origin relative path starting with "/".');
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $session = $request->getAttribute(Session::class);
        $principal = $request->getAttribute(Principal::class);
        $rotatedCookie = null;

        if (!$principal instanceof Principal && $session instanceof Session) {
            $candidate = $this->auth->principalFromSession($session);

            if (null === $candidate && null !== $this->rememberMe) {
                $cookies = $request->getCookieParams();
                $rawRemember = $cookies[$this->rememberMe->cookieName()] ?? null;
                if (is_string($rawRemember) && '' !== $rawRemember) {
                    $resumed = $this->rememberMe->consumeAndRotate($rawRemember);
                    if (null !== $resumed) {
                        $resolved = null !== $this->principalResolver
                            ? ($this->principalResolver)($resumed['principal'])
                            : $resumed['principal'];
                        if (null !== $resolved) {
                            $this->auth->login($session, $resolved);
                            $principal = $resolved;
                            $rotatedCookie = $resumed['cookie'];
                        } else {
                            $this->rememberMe->revokeCookie($resumed['cookie']->value);
                            $rotatedCookie = $this->rememberMe->expiredCookie();
                        }
                    } else {
                        $rotatedCookie = $this->rememberMe->expiredCookie();
                    }
                }
            } elseif (null !== $candidate) {
                $resolved = null !== $this->principalResolver
                    ? ($this->principalResolver)($candidate)
                    : $candidate;
                if (null === $resolved) {
                    $this->auth->logout($session);
                } else {
                    $principal = $resolved;
                }
            }
        }

        if ($principal instanceof Principal) {
            $request = $request->withAttribute(Principal::class, $principal);
        } elseif ($this->required) {
            if (null !== $this->loginRedirectUrl && RequireAuthenticatedMiddleware::prefersHtmlRedirect($request)) {
                return $this->attachCookie(Response::redirect($this->loginRedirectUrl, 302), $rotatedCookie);
            }

            $headers = [];
            if (null !== $rotatedCookie) {
                $headers['Set-Cookie'] = $rotatedCookie->toHeaderValue();
                $headers['Cache-Control'] = 'private, no-cache="Set-Cookie"';
            }

            throw new HttpException(401, 'Authentication required.', $headers);
        }

        try {
            $response = $handler->handle($request);
        } catch (HttpException $e) {
            if (null !== $rotatedCookie) {
                $headers = $e->headers;
                $headers['Set-Cookie'] = $rotatedCookie->toHeaderValue();
                $existingCcKey = null;
                foreach (array_keys($headers) as $k) {
                    if ('cache-control' === strtolower($k)) {
                        $existingCcKey = $k;
                        break;
                    }
                }
                $ccVal = null !== $existingCcKey ? strtolower($headers[$existingCcKey]) : '';
                if ('' === $ccVal || (!str_contains($ccVal, 'private') && !str_contains($ccVal, 'no-store'))) {
                    if (null !== $existingCcKey) {
                        unset($headers[$existingCcKey]);
                    }
                    $headers['Cache-Control'] = 'private, no-cache="Set-Cookie"';
                }

                throw new HttpException($e->statusCode, $e->getMessage(), $headers, $e->diagnostic, $e);
            }
            throw $e;
        }

        return $this->attachCookie($response, $rotatedCookie);
    }

    private function attachCookie(ResponseInterface $response, ?Cookie $cookie): ResponseInterface
    {
        if (null === $cookie) {
            return $response;
        }

        $withCookie = $response->withAddedHeader('Set-Cookie', $cookie->toHeaderValue());
        $cc = strtolower($withCookie->getHeaderLine('Cache-Control'));
        if ('' === $cc || (!str_contains($cc, 'private') && !str_contains($cc, 'no-store'))) {
            $withCookie = $withCookie->withHeader('Cache-Control', 'private, no-cache="Set-Cookie"');
        }

        return $withCookie;
    }
}
