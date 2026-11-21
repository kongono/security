<?php

declare(strict_types=1);

namespace Kongono\Security;

use SensitiveParameter;

/**
 * Pure PHP 8.5 RFC 6238 TOTP (Time-based One-Time Password) authenticator for 2FA/MFA.
 *
 * Compatible with Google Authenticator, 1Password, Apple Passwords, and Authy with zero dependencies.
 */
final readonly class Totp
{
    private const string BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * @param positive-int $digits Number of digits (standard: 6)
     * @param positive-int $period Time step in seconds (standard: 30)
     */
    public function __construct(
        private int $digits = 6,
        private int $period = 30,
        private string $algorithm = 'sha1',
    ) {}

    /** Generate a cryptographically random RFC 4648 Base32 secret (default 160 bits). */
    public static function generateSecret(int $byteLength = 20): string
    {
        return self::base32Encode(random_bytes(max(16, $byteLength)));
    }

    /**
     * Generate human-friendly single-use backup recovery codes (`XXXX-XXXX`).
     *
     * @param positive-int $count
     * @return list<string>
     */
    public static function generateRecoveryCodes(int $count = 8): array
    {
        $codes = [];
        for ($i = 0; $i < $count; ++$i) {
            $hex = strtoupper(bin2hex(random_bytes(4)));
            $codes[] = substr($hex, 0, 4) . '-' . substr($hex, 4, 4);
        }

        return $codes;
    }

    /** Compute the current (or timestamp-specific) TOTP code. */
    public function code(#[SensitiveParameter] string $base32Secret, ?int $timestamp = null): string
    {
        $counter = intdiv($timestamp ?? time(), $this->period);

        return $this->hotp($base32Secret, $counter);
    }

    /** Verify a user-supplied TOTP code in constant time across +/- $window time steps. */
    public function verify(
        #[SensitiveParameter]
        string $base32Secret,
        string $userCode,
        int $window = 1,
        ?int $timestamp = null,
    ): bool {
        $normalized = preg_replace('/[\s-]+/', '', trim($userCode));
        if (!is_string($normalized) || strlen($normalized) !== $this->digits || !ctype_digit($normalized)) {
            return false;
        }

        $counter = intdiv($timestamp ?? time(), $this->period);
        $drift = max(0, $window);
        $matched = false;

        for ($offset = -$drift; $offset <= $drift; ++$offset) {
            $expected = $this->hotp($base32Secret, $counter + $offset);
            if (hash_equals($expected, $normalized)) {
                $matched = true;
            }
        }

        return $matched;
    }

    /** Build an `otpauth://totp/...` provisioning URI for authenticator QR code scanning. */
    public function provisioningUri(#[SensitiveParameter] string $base32Secret, string $account, string $issuer): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        $query = http_build_query([
            'secret' => strtoupper(trim($base32Secret)),
            'issuer' => $issuer,
            'algorithm' => strtoupper($this->algorithm),
            'digits' => $this->digits,
            'period' => $this->period,
        ], '', '&', PHP_QUERY_RFC3986);

        return sprintf('otpauth://totp/%s?%s', $label, $query);
    }

    private function hotp(#[SensitiveParameter] string $base32Secret, int $counter): string
    {
        $key = self::base32Decode($base32Secret);
        $binaryCounter = pack('N2', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
        $hash = hash_hmac($this->algorithm, $binaryCounter, $key, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $truncated = (
            ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF)
        );
        $mod = 10 ** $this->digits;

        return str_pad((string) ($truncated % $mod), $this->digits, '0', STR_PAD_LEFT);
    }

    private static function base32Encode(string $bytes): string
    {
        $bits = '';
        $len = strlen($bytes);
        for ($i = 0; $i < $len; ++$i) {
            $bits .= str_pad(decbin(ord($bytes[$i])), 8, '0', STR_PAD_LEFT);
        }

        $out = '';
        $bitLen = strlen($bits);
        for ($i = 0; $i < $bitLen; $i += 5) {
            $chunk = str_pad(substr($bits, $i, 5), 5, '0', STR_PAD_RIGHT);
            $out .= self::BASE32_ALPHABET[(int) bindec($chunk)];
        }

        return $out;
    }

    private static function base32Decode(#[SensitiveParameter] string $encoded): string
    {
        $clean = strtoupper(rtrim(str_replace([' ', '-'], '', $encoded), '='));
        if ('' === $clean) {
            throw new SecurityException('TOTP Base32 secret cannot be empty.');
        }

        $bits = '';
        $len = strlen($clean);
        for ($i = 0; $i < $len; ++$i) {
            $pos = strpos(self::BASE32_ALPHABET, $clean[$i]);
            if (false === $pos) {
                throw new SecurityException(sprintf('Invalid Base32 character "%s" in TOTP secret.', $clean[$i]));
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        $out = '';
        $bitLen = strlen($bits);
        for ($i = 0; $i + 8 <= $bitLen; $i += 8) {
            $out .= chr(((int) bindec(substr($bits, $i, 8))) & 0xFF);
        }

        return $out;
    }
}
