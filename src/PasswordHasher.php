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
        if ($this->usesBcrypt()) {
            if (strlen($plainPassword) > 72) {
                throw new SecurityException('Bcrypt passwords cannot exceed 72 bytes (would silently truncate).');
            }
            if (str_contains($plainPassword, "\0")) {
                throw new SecurityException('Bcrypt passwords cannot contain NUL bytes.');
            }
        }

        return password_hash($plainPassword, $this->algorithm);
    }

    public function verify(#[SensitiveParameter] string $plainPassword, #[SensitiveParameter] string $hash): bool
    {
        if ('' === $plainPassword || '' === $hash || strlen($plainPassword) > self::MAX_PASSWORD_BYTES) {
            return false;
        }
        if ((str_starts_with($hash, '$2y$') || str_starts_with($hash, '$2a$') || str_starts_with($hash, '$2b$'))
            && (strlen($plainPassword) > 72 || str_contains($plainPassword, "\0"))
        ) {
            return false;
        }

        return password_verify($plainPassword, $hash);
    }

    public function needsRehash(#[SensitiveParameter] string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm);
    }

    private function usesBcrypt(): bool
    {
        return PASSWORD_BCRYPT === $this->algorithm;
    }
}
