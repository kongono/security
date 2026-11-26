# Kongono Security (`kongono/security`)

> **Read-only subtree split** of [`kongono/framework`](https://github.com/kongono/framework). Open issues and pull requests in the main monorepo.

Standalone, zero-Symfony PHP 8.5.13+ security & passwordless authentication primitives usable in **any** PHP application (Laravel, Symfony, Slim, or vanilla PHP):

- **Cryptographic QR Login & Pure-PHP SVG QR Encoder:** `QrLoginAuth` (phishing-resistant cross-device sign-in with desktop-only `poll_secret`, 6-digit `XXX-XXX` QRLjacking verification code & atomic single-use `claim()`) + `QrCodeSvg` (ISO/IEC 18004 Versions 1–10 strict-CSP inline `<svg>`).
- **Passwordless, Passkeys & 2FA:** `PasskeyVerifier` (complete WebAuthn/FIDO2 registration & assertions with pure-PHP RFC 8949 `CborDecoder` for ES256 P-256, EdDSA Ed25519 & RS256 Windows Hello TPMs), `OneTimeCodeAuth` (Email/SMS OTP with HKDF storage & brute-force lockout), `MagicLinkAuth` (single-use HMAC links), `Totp` (RFC 6238 + `provisioningQrSvg()` + 80-bit recovery codes), `PkceOAuthClient` (GitHub/Google/OIDC S256).
- **Cryptography & App Defense:** HKDF `Encryptor` v2 (XChaCha20-Poly1305 AEAD + key rotation), Argon2id `PasswordHasher`, `TokenSigner`, `SignedUrl`, revocable SHA-256 `PersonalAccessToken`, HTML5 Lexbor `HtmlSanitizer`, multi-provider `WebhookSignerRegistry` (`registerStripe()` + `#[VerifyWebhook('stripe')]`) / `WebhookDispatcher`, and DNS-pinned SSRF-proof `SafeHttpClient`.

## Installation

```bash
composer require kongono/security
```

## Examples

```php
<?php

declare(strict_types=1);

use Kongono\Core\Cache\MemoryCache;
use Kongono\Security\Auth\{OneTimeCodeAuth, QrLoginAuth};
use Kongono\Security\Totp;

$cache = new MemoryCache();
$appKey = base64_encode(random_bytes(32));

// 1. 2FA TOTP + strict-CSP inline SVG QR code
$totp = new Totp(replayCache: $cache);
$secret = Totp::generateSecret();
$svg = $totp->provisioningQrSvg($secret, 'dev@example.com', 'My App');

// 2. Single-use Email/SMS OTP with automatic brute-force lockout
$otp = new OneTimeCodeAuth($appKey, $cache);
$issued = $otp->issue('dev@example.com', digits: 6, ttlSeconds: 600, maxAttempts: 5);
$verified = $otp->verify('dev@example.com', $issued['code']);

// 3. Cross-device cryptographic QR sign-in
$qr = new QrLoginAuth($appKey, $cache);
$challenge = $qr->begin('https://app.example.com/auth/qr/approve', requesterIp: '203.0.113.10');
```

## Documentation & License

- Full documentation: https://kongono.com/docs.html#security
- Monorepo & issues: https://github.com/kongono/framework
- License: MIT
