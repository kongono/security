<?php

declare(strict_types=1);

namespace Kongono\Security;

use Closure;
use Kongono\Http\HttpException;

/** Explicit, fail-closed capability and policy authorization gate. */
final class Gate
{
    /** @var array<string, Closure(Principal, mixed): bool> */
    private array $policies = [];

    /**
     * Register a custom authorization policy for a capability name.
     *
     * @param Closure(Principal, mixed): bool $policy
     */
    public function define(string $capability, Closure $policy): self
    {
        $this->policies[$capability] = $policy;

        return $this;
    }

    /** Check whether a Principal is authorized for a capability (fail-closed by default). */
    public function allows(?Principal $principal, string $capability, mixed $resource = null): bool
    {
        if (null === $principal) {
            return false;
        }
        if (isset($this->policies[$capability])) {
            return ($this->policies[$capability])($principal, $resource);
        }

        return $principal->hasCapability($capability);
    }

    /** Enforce authorization or throw HTTP 401/403 HttpException. */
    public function authorize(?Principal $principal, string $capability, mixed $resource = null): void
    {
        if (null === $principal) {
            throw new HttpException(401, 'Authentication required.');
        }
        if (!$this->allows($principal, $capability, $resource)) {
            throw new HttpException(403, sprintf('Forbidden: missing capability "%s".', $capability));
        }
    }
}
