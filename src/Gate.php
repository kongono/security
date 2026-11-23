<?php

declare(strict_types=1);

namespace Kongono\Security;

use Closure;
use Kongono\Http\HttpException;

/**
 * Explicit, fail-closed capability and resource-policy authorization gate.
 *
 * Supports:
 *   - `before()` global override/audit hooks (e.g. super-admin or suspended-account checks)
 *   - `define($capability, $closure)` explicit named rules
 *   - `policy($resourceClass, $policy)` object-scoped policy classes
 *   - Direct `Principal::hasCapability()` fallback
 */
final class Gate
{
    /** @var list<Closure(Principal, string, mixed): ?bool> */
    private array $beforeHooks = [];

    /** @var array<string, Closure(Principal, mixed): bool> */
    private array $policies = [];

    /** @var array<class-string, object|class-string> */
    private array $resourcePolicies = [];

    /**
     * Register a hook evaluated BEFORE named rules, resource policies, or capabilities.
     * Return `true` to allow immediately, `false` to deny immediately, or `null` to continue.
     *
     * @param Closure(Principal, string, mixed): ?bool $callback
     */
    public function before(Closure $callback): self
    {
        $this->beforeHooks[] = $callback;

        return $this;
    }

    /**
     * Register a custom authorization policy closure for a capability name.
     *
     * @param Closure(Principal, mixed): bool $policy
     */
    public function define(string $capability, Closure $policy): self
    {
        $this->policies[$capability] = $policy;

        return $this;
    }

    /**
     * Bind a resource policy instance or class-string to a domain object / DTO class.
     * Ability names like `'orders.update'` or `'update'` map to `$policy->update($principal, $resource)`.
     *
     * @param class-string        $resourceClass
     * @param object|class-string $policy
     */
    public function policy(string $resourceClass, object|string $policy): self
    {
        $this->resourcePolicies[$resourceClass] = $policy;

        return $this;
    }

    /** Check whether a Principal is authorized for a capability (fail-closed by default). */
    public function allows(?Principal $principal, string $capability, mixed $resource = null): bool
    {
        if (null === $principal) {
            return false;
        }

        foreach ($this->beforeHooks as $hook) {
            $decision = $hook($principal, $capability, $resource);
            if (is_bool($decision)) {
                return $decision;
            }
        }

        if (isset($this->policies[$capability])) {
            return ($this->policies[$capability])($principal, $resource);
        }

        if (is_object($resource)) {
            $policyDecision = $this->evaluateResourcePolicy($principal, $capability, $resource);
            if (is_bool($policyDecision)) {
                return $policyDecision;
            }
        }

        return $principal->hasCapability($capability);
    }

    public function denies(?Principal $principal, string $capability, mixed $resource = null): bool
    {
        return !$this->allows($principal, $capability, $resource);
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

    private function evaluateResourcePolicy(Principal $principal, string $capability, object $resource): ?bool
    {
        $policyEntry = null;
        $exactClass = $resource::class;
        if (isset($this->resourcePolicies[$exactClass])) {
            $policyEntry = $this->resourcePolicies[$exactClass];
        } else {
            foreach ($this->resourcePolicies as $class => $candidate) {
                if ($resource instanceof $class) {
                    $policyEntry = $candidate;
                    break;
                }
            }
        }

        if (null === $policyEntry) {
            return null;
        }

        $policyObj = is_object($policyEntry) ? $policyEntry : new $policyEntry();
        $method = self::abilityToMethodName($capability);
        if ('' === $method || !method_exists($policyObj, $method)) {
            return null;
        }

        $callable = [$policyObj, $method];
        if (!is_callable($callable)) {
            return null;
        }

        return (bool) $callable($principal, $resource);
    }

    private static function abilityToMethodName(string $capability): string
    {
        // Map 'orders.update-status' -> 'updateStatus', 'view' -> 'view'
        $segments = explode('.', $capability);
        $tail = end($segments);
        $rawParts = preg_split('/[-_]+/', trim($tail));
        $parts = is_array($rawParts) ? $rawParts : [];
        $parts = array_values(array_filter($parts, static fn(string $p): bool => '' !== $p));
        if ([] === $parts) {
            return '';
        }

        $first = strtolower($parts[0]);
        $rest = array_map(static fn(string $p): string => ucfirst(strtolower($p)), array_slice($parts, 1));

        return $first . implode('', $rest);
    }
}
