<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

/**
 * One-time issuance result containing the plaintext bearer token (`kgn_pat_<id>.<secret>`)
 * to display once to the user alongside the persisted {@see PersonalAccessToken} record.
 */
final readonly class IssuedToken
{
    public function __construct(
        public string $plainTextToken,
        public PersonalAccessToken $record,
    ) {}
}
