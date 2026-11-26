<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

/**
 * Verified WebAuthn / FIDO2 passkey credential returned by {@see PasskeyVerifier::verifyRegistration()}.
 *
 * Persist `credentialId`, `publicKey`, `algorithm`, `signCount`, and `userId` in your user store
 * and pass them back into {@see PasskeyVerifier::verifyAssertion()} on future sign-ins.
 */
final readonly class RegisteredPasskey
{
    /**
     * @param list<string> $transports Optional authenticator transports (e.g. `['internal', 'hybrid']`)
     */
    public function __construct(
        public string $credentialId,
        public string $publicKey,
        public string $algorithm,
        public int $signCount,
        public string $userId,
        public string $aaguid,
        public bool $userPresent,
        public bool $userVerified,
        public bool $backupEligible,
        public bool $backupState,
        public string $attestationFormat,
        public array $transports = [],
    ) {}
}
