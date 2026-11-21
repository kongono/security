<?php

declare(strict_types=1);

namespace Kongono\Security;

/**
 * First-class security Principal (Human, Service, Agent, or System).
 *
 * Identity alone grants zero implicit authority; capabilities must be explicitly assigned.
 */
final readonly class Principal
{
    /**
     * @param list<string>         $capabilities
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        public string $id,
        public PrincipalKind $kind,
        public array $capabilities = [],
        public array $attributes = [],
    ) {}

    public function hasCapability(string $capability): bool
    {
        return in_array($capability, $this->capabilities, true);
    }

    public function isAgent(): bool
    {
        return PrincipalKind::Agent === $this->kind;
    }

    public function isHuman(): bool
    {
        return PrincipalKind::Human === $this->kind;
    }
}
