<?php

declare(strict_types=1);

namespace Kongono\Security;

use SensitiveParameter;

/**
 * Modern authenticated AEAD encryption (XChaCha20-Poly1305 via ext-sodium)
 * with 192-bit random nonces, associated data binding, and seamless key rotation.
 */
final readonly class Encryptor
{
    private string $primaryKey;

    /** @var list<string> */
    private array $previousKeys;

    /** @param list<string> $previousKeys Older keys accepted for decryption during rotation */
    public function __construct(
        #[SensitiveParameter]
        string $key,
        #[SensitiveParameter]
        array $previousKeys = [],
    ) {
        $this->primaryKey = $this->derive32ByteKey($key);
        $this->previousKeys = array_map($this->derive32ByteKey(...), $previousKeys);
    }

    public static function generateKey(): string
    {
        return base64_encode(random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES));
    }

    public function encrypt(#[SensitiveParameter] string $plaintext, string $associatedData = ''): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $boundAad = 'v1.' . $associatedData;
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $boundAad, $nonce, $this->primaryKey);

        return 'v1.' . $this->b64uEncode($nonce . $cipher);
    }

    public function decrypt(#[SensitiveParameter] string $payload, string $associatedData = ''): string
    {
        if (!str_starts_with($payload, 'v1.')) {
            throw new SecurityException('Unsupported encrypted payload format.');
        }

        $bytes = $this->b64uDecode(substr($payload, 3));
        $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
        $minLen = $nonceLen + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
        if (null === $bytes || strlen($bytes) < $minLen) {
            throw new SecurityException('Corrupted encrypted payload.');
        }

        $nonce = substr($bytes, 0, $nonceLen);
        $cipher = substr($bytes, $nonceLen);
        $boundAad = 'v1.' . $associatedData;

        foreach ([$this->primaryKey, ...$this->previousKeys] as $candidateKey) {
            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, $boundAad, $nonce, $candidateKey);
            if (false !== $plain) {
                return $plain;
            }
        }

        throw new SecurityException('Decryption failed: invalid key, tampered ciphertext, or mismatched associated data.');
    }

    private function derive32ByteKey(#[SensitiveParameter] string $rawKey): string
    {
        if (strlen($rawKey) < 16) {
            throw new SecurityException('Encryption key must be at least 16 bytes.');
        }

        return hash_hkdf('sha256', $rawKey, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 'kongono:encryptor:v1');
    }

    private function b64uEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private function b64uDecode(string $encoded): ?string
    {
        // Reject non-canonical base64url strings (+, /, = padding, or non-canonical trailing bits)
        if ('' === $encoded || 1 !== preg_match('/\A[A-Za-z0-9_-]+\z/', $encoded)) {
            return null;
        }
        $padded = strtr($encoded, '-_', '+/');
        $rem = strlen($padded) % 4;
        if (1 === $rem) {
            return null;
        }
        if (0 !== $rem) {
            $padded .= str_repeat('=', 4 - $rem);
        }
        $decoded = base64_decode($padded, true);
        if (false === $decoded || $this->b64uEncode($decoded) !== $encoded) {
            return null;
        }

        return $decoded;
    }
}
