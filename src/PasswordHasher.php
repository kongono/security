<?php

declare(strict_types=1);

namespace Kongono\Security;

use SensitiveParameter;

/** Modern Argon2id password hashing helper (zero legacy MD5/SHA1/bcrypt defaults). */
final readonly class PasswordHasher
{
    private string $algorithm;

    public function __construct(?string $algorithm = null)
    {
        $this->algorithm = $algorithm ?? (defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT);
    }

    public function hash(#[SensitiveParameter] string $plainPassword): string
    {
        if ('' === $plainPassword) {
            throw new SecurityException('Password cannot be empty.');
        }

        return password_hash($plainPassword, $this->algorithm);
    }

    public function verify(#[SensitiveParameter] string $plainPassword, string $hash): bool
    {
        if ('' === $plainPassword || '' === $hash) {
            return false;
        }

        return password_verify($plainPassword, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm);
    }
}
