<?php

declare(strict_types=1);

namespace Kongono\Security;

use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Security\Auth\QrCodeSvg;
use SensitiveParameter;

/**
 * Pure PHP 8.5 RFC 6238 TOTP (Time-based One-Time Password) authenticator for 2FA/MFA.
 *
 * Compatible with Google Authenticator, 1Password, Apple Passwords, and Authy with zero dependencies.
 */
final readonly class Totp
{
    private const string BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    private string $algorithm;

    /**
     * @param int                        $digits      Number of digits (6-8, standard: 6)
     * @param int                        $period      Time step in seconds (standard: 30)
     * @param ?AtomicCacheInterface      $replayCache Optional default atomic replay cache applied automatically on every verify() call
     */
    public function __construct(
        private int $digits = 6,
        private int $period = 30,
        string $algorithm = 'sha1',
        private ?AtomicCacheInterface $replayCache = null,
    ) {
        if ($digits < 6 || $digits > 8) {
            throw new SecurityException('TOTP digits must be between 6 and 8.');
        }
        if ($period < 1) {
            throw new SecurityException('TOTP period must be at least 1 second.');
        }
        $normalizedAlg = strtolower(trim($algorithm));
        if (!in_array($normalizedAlg, ['sha1', 'sha256', 'sha512'], true)) {
            throw new SecurityException(sprintf('Unsupported TOTP HMAC algorithm "%s". Allowed: sha1, sha256, sha512.', $algorithm));
        }
        $this->algorithm = $normalizedAlg;
    }

    /** Generate a cryptographically random RFC 4648 Base32 secret (default 160 bits). */
    public static function generateSecret(int $byteLength = 20): string
    {
        return self::base32Encode(random_bytes(max(16, $byteLength)));
    }

    /**
     * Generate human-friendly single-use 80-bit backup recovery codes (`XXXX-XXXX-XXXX-XXXX-XXXX`).
     *
     * @param positive-int $count
     * @return list<string>
     */
    public static function generateRecoveryCodes(int $count = 8): array
    {
        $codes = [];
        for ($i = 0; $i < $count; ++$i) {
            $hex = strtoupper(bin2hex(random_bytes(10)));
            $codes[] = implode('-', str_split($hex, 4));
        }

        return $codes;
    }

    /** Compute the current (or timestamp-specific) TOTP code. */
    public function code(#[SensitiveParameter] string $base32Secret, ?int $timestamp = null): string
    {
        $counter = intdiv($timestamp ?? time(), $this->period);

        return $this->hotp($base32Secret, $counter);
    }

    /**
     * Verify a user-supplied TOTP code in constant time across +/- $window time steps.
     * Supports RFC 6238 Section 5.2 single-use anti-replay via `$lastVerifiedStep` and/or `$replayCache`.
     */
    public function verify(
        #[SensitiveParameter]
        string $base32Secret,
        string $userCode,
        int $window = 1,
        ?int $timestamp = null,
        ?int $lastVerifiedStep = null,
        ?CacheInterface $replayCache = null,
    ): bool {
        $step = $this->verifyAndReturnTimeStep($base32Secret, $userCode, $window, $timestamp, $lastVerifiedStep, $replayCache);

        return null !== $step;
    }

    /**
     * Strictly single-use RFC 6238 verification requiring an `AtomicCacheInterface` replay store.
     * Returns the matched time-step counter on first valid use, or `null` on mismatch or replay.
     */
    public function verifyOnce(
        #[SensitiveParameter]
        string $base32Secret,
        string $userCode,
        AtomicCacheInterface $replayCache,
        int $window = 1,
        ?int $timestamp = null,
        ?int $lastVerifiedStep = null,
    ): ?int {
        return $this->verifyAndReturnTimeStep($base32Secret, $userCode, $window, $timestamp, $lastVerifiedStep, $replayCache);
    }

    /**
     * Verify a TOTP code and return the matched time-step counter (or null on failure/replay)
     * so callers can persist `lastVerifiedStep` and reject duplicate use per RFC 6238 Section 5.2.
     */
    public function verifyAndReturnTimeStep(
        #[SensitiveParameter]
        string $base32Secret,
        string $userCode,
        int $window = 1,
        ?int $timestamp = null,
        ?int $lastVerifiedStep = null,
        ?CacheInterface $replayCache = null,
    ): ?int {
        $normalized = preg_replace('/[\s-]+/', '', trim($userCode));
        if (!is_string($normalized) || strlen($normalized) !== $this->digits || !ctype_digit($normalized)) {
            return null;
        }

        $key = self::base32Decode($base32Secret);
        $counter = intdiv($timestamp ?? time(), $this->period);
        $drift = max(0, $window);
        $matchedStep = null;

        for ($offset = -$drift; $offset <= $drift; ++$offset) {
            $step = $counter + $offset;
            $expected = $this->hotpFromRawKey($key, $step);
            if (hash_equals($expected, $normalized)) {
                $matchedStep = $step;
            }
        }

        if (null === $matchedStep) {
            return null;
        }
        if (null !== $lastVerifiedStep && $matchedStep <= $lastVerifiedStep) {
            return null;
        }

        $effectiveReplayCache = $replayCache ?? $this->replayCache;
        if (null !== $effectiveReplayCache) {
            if (!$effectiveReplayCache instanceof AtomicCacheInterface) {
                throw new SecurityException('TOTP replay protection requires an AtomicCacheInterface implementation to prevent concurrent code reuse.');
            }
            $secretScope = hash('sha256', $key . ':' . $this->algorithm . ':' . $this->digits . ':' . $this->period);
            $lastStepKey = 'kongono:totp:last:' . $secretScope;
            $cachedLast = $effectiveReplayCache->get($lastStepKey);
            if (is_int($cachedLast) && $matchedStep <= $cachedLast) {
                return null;
            }

            $replayKey = 'kongono:totp:used:' . hash('sha256', $secretScope . ':' . $matchedStep);
            $ttl = (2 * $drift + 2) * $this->period;
            if (!$effectiveReplayCache->add($replayKey, true, $ttl)) {
                return null;
            }

            $nextLast = is_int($cachedLast) ? max($cachedLast, $matchedStep) : $matchedStep;
            $effectiveReplayCache->set($lastStepKey, $nextLast, $ttl);
        }

        return $matchedStep;
    }

    /** Build an `otpauth://totp/...` provisioning URI for authenticator QR code scanning. */
    public function provisioningUri(#[SensitiveParameter] string $base32Secret, string $account, string $issuer): string
    {
        $normalizedSecret = strtoupper(rtrim(str_replace([' ', '-'], '', trim($base32Secret)), '='));
        self::base32Decode($normalizedSecret);
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        $query = http_build_query([
            'secret' => $normalizedSecret,
            'issuer' => $issuer,
            'algorithm' => strtoupper($this->algorithm),
            'digits' => $this->digits,
            'period' => $this->period,
        ], '', '&', PHP_QUERY_RFC3986);

        return sprintf('otpauth://totp/%s?%s', $label, $query);
    }

    /**
     * Render a strict-CSP inline `<svg>` QR code for scanning with Google Authenticator,
     * 1Password, Apple Passwords, or Authy (zero external libraries or CDN calls).
     */
    public function provisioningQrSvg(
        #[SensitiveParameter]
        string $base32Secret,
        string $account,
        string $issuer,
        int $size = 220,
    ): string {
        return QrCodeSvg::render(
            payload: $this->provisioningUri($base32Secret, $account, $issuer),
            size: $size,
            ecLevel: 'M',
            ariaLabel: sprintf('2FA authenticator QR code for %s', $issuer),
        );
    }

    private function hotp(#[SensitiveParameter] string $base32Secret, int $counter): string
    {
        return $this->hotpFromRawKey(self::base32Decode($base32Secret), $counter);
    }

    private function hotpFromRawKey(#[SensitiveParameter] string $key, int $counter): string
    {
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
        if (strlen($out) < 10) {
            throw new SecurityException('TOTP Base32 secret must decode to at least 10 bytes (80 bits).');
        }

        return $out;
    }
}
