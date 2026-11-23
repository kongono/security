<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Http\Session\Session;
use Kongono\Security\Principal;
use Kongono\Security\PrincipalKind;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Persistent-runtime-safe session authentication helper.
 *
 * Guarantees session fixation defense on login (always regenerates session ID)
 * and clean destruction on logout (always invalidates session & expires cookie).
 */
final readonly class SessionAuth
{
    public const string SESSION_KEY = '_auth_principal';

    public function __construct(
        private string $sessionKey = self::SESSION_KEY,
    ) {}

    /**
     * Authenticate `$principal` into `$session`, unconditionally rotating the session ID
     * to prevent session fixation attacks.
     */
    public function login(Session $session, Principal $principal): void
    {
        $session->regenerate();
        $session->set($this->sessionKey, [
            'id' => $principal->id,
            'kind' => $principal->kind->value,
            'capabilities' => $principal->capabilities,
            'attributes' => $principal->attributes,
        ]);
    }

    /** Destroy the authenticated session and expire the client session cookie. */
    public function logout(Session $session): void
    {
        $session->invalidate();
    }

    /** Hydrate a typed {@see Principal} from `$session`, or return `null` when unauthenticated or malformed. */
    public function principalFromSession(Session $session): ?Principal
    {
        $raw = $session->get($this->sessionKey);
        if (!is_array($raw) || !is_string($raw['id'] ?? null) || '' === $raw['id']) {
            return null;
        }

        $kindVal = is_string($raw['kind'] ?? null) ? $raw['kind'] : PrincipalKind::Human->value;
        $kind = PrincipalKind::tryFrom($kindVal) ?? PrincipalKind::Human;

        /** @var list<string> $capabilities */
        $capabilities = [];
        if (is_array($raw['capabilities'] ?? null)) {
            foreach ($raw['capabilities'] as $cap) {
                if (is_string($cap) && '' !== $cap) {
                    $capabilities[] = $cap;
                }
            }
        }

        /** @var array<string, mixed> $attributes */
        $attributes = [];
        if (is_array($raw['attributes'] ?? null)) {
            foreach ($raw['attributes'] as $k => $v) {
                $attributes[(string) $k] = $v;
            }
        }

        return new Principal($raw['id'], $kind, $capabilities, $attributes);
    }

    /** Return the authenticated {@see Principal} attached to `$request`, or `null`. */
    public function principal(ServerRequestInterface $request): ?Principal
    {
        $principal = $request->getAttribute(Principal::class);

        return $principal instanceof Principal ? $principal : null;
    }

    public function check(ServerRequestInterface $request): bool
    {
        return null !== $this->principal($request);
    }
}
