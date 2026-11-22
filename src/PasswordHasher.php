<?php

declare(strict_types=1);

namespace Kongono\Security;

use SensitiveParameter;

/** Modern Argon2id password hashing helper (zero legacy MD5/SHA1/bcrypt defaults). */
final readonly class PasswordHasher
{
    public const int MAX_PASSWORD_BYTES = 4096;

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
        if (strlen($plainPassword) > self::MAX_PASSWORD_BYTES) {
            throw new SecurityException(sprintf('Password exceeds maximum length of %d bytes.', self::MAX_PASSWORD_BYTES));
        }

        return password_hash($plainPassword, $this->algorithm);
    }

    public function verify(#[SensitiveParameter] string $plainPassword, string $hash): bool
    {
        if ('' === $plainPassword || '' === $hash || strlen($plainPassword) > self::MAX_PASSWORD_BYTES) {
            return false;
        }

        return password_verify($plainPassword, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm);
    }
}
