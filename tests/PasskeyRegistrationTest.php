<?php

declare(strict_types=1);

namespace Kongono\Security\Tests;

use Kongono\Core\Cache\MemoryCache;
use Kongono\Security\Auth\CborBytes;
use Kongono\Security\Auth\CborDecoder;
use Kongono\Security\Auth\PasskeyVerifier;
use Kongono\Security\SecurityException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

final class PasskeyRegistrationTest extends TestCase
{
    public function testEndToEndEs256RegistrationAndAssertionRoundTrip(): void
    {
        $cache = new MemoryCache();
        $passkeys = new PasskeyVerifier($cache);

        $options = $passkeys->createRegistrationOptions(
            rpId: 'kongono.dev',
            rpName: 'Kongono App',
            origin: 'https://kongono.dev',
            userId: 'user_42',
            userName: 'ada@kongono.dev',
            userDisplayName: 'Ada Lovelace',
            excludeCredentialIds: ['existing-cred-id'],
            userVerification: 'required',
            residentKey: 'required',
            authenticatorAttachment: 'platform',
            now: 10_000,
        );

        self::assertSame('kongono.dev', $options['rp']['id']);
        self::assertSame('Kongono App', $options['rp']['name']);
        self::assertSame(PasskeyVerifier::base64UrlEncode('user_42'), $options['user']['id']);
        self::assertSame('none', $options['attestation']);
        self::assertSame([['type' => 'public-key', 'id' => 'existing-cred-id']], $options['excludeCredentials']);
        self::assertTrue($options['authenticatorSelection']['requireResidentKey']);
        self::assertSame('platform', $options['authenticatorSelection']['authenticatorAttachment']);
        self::assertCount(3, $options['pubKeyCredParams']);

        // Generate a real ECDSA P-256 keypair and build a real WebAuthn CBOR attestationObject
        $privateKey = self::generateOpenSslKey([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $details = openssl_pkey_get_details($privateKey);
        self::assertIsArray($details);
        self::assertIsArray($details['ec'] ?? null);
        $x = str_pad((string) $details['ec']['x'], 32, "\x00", STR_PAD_LEFT);
        $y = str_pad((string) $details['ec']['y'], 32, "\x00", STR_PAD_LEFT);

        $coseKey = self::cborMap([
            [1, 2],    // kty: EC2
            [3, -7],   // alg: ES256
            [-1, 1],   // crv: P-256
            [-2, new CborBytes($x)],
            [-3, new CborBytes($y)],
        ]);

        $rawCredId = random_bytes(32);
        $aaguid = hex2bin('08987058cadc4b81b6e130de50dcbe96');
        self::assertIsString($aaguid);

        // Flags: UP (0x01) | UV (0x04) | BE (0x08) | AT (0x40) = 0x4D
        $authData = hash('sha256', 'kongono.dev', true)
            . chr(0x4D)
            . pack('N', 1)
            . $aaguid
            . pack('n', strlen($rawCredId))
            . $rawCredId
            . $coseKey;

        $attestationObject = self::cborMap([
            ['fmt', 'none'],
            ['attStmt', self::cborMapRaw([])],
            ['authData', new CborBytes($authData)],
        ]);

        $clientData = json_encode([
            'type' => 'webauthn.create',
            'challenge' => $options['challenge'],
            'origin' => 'https://kongono.dev',
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);

        $registered = $passkeys->verifyRegistration(
            expectedChallenge: $options['challenge'],
            clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($clientData),
            attestationObjectBase64Url: PasskeyVerifier::base64UrlEncode($attestationObject),
            requireUserVerification: true,
            now: 10_010,
            transports: ['internal', 'hybrid', 'invalid-transport', 'internal'],
        );

        self::assertSame(PasskeyVerifier::base64UrlEncode($rawCredId), $registered->credentialId);
        self::assertSame('ES256', $registered->algorithm);
        self::assertSame(1, $registered->signCount);
        self::assertSame('user_42', $registered->userId);
        self::assertSame('08987058-cadc-4b81-b6e1-30de50dcbe96', $registered->aaguid);
        self::assertTrue($registered->userPresent);
        self::assertTrue($registered->userVerified);
        self::assertTrue($registered->backupEligible);
        self::assertFalse($registered->backupState);
        self::assertSame('none', $registered->attestationFormat);
        self::assertSame(['internal', 'hybrid'], $registered->transports);
        self::assertStringContainsString('-----BEGIN PUBLIC KEY-----', $registered->publicKey);

        // Replaying the consumed registration challenge fails closed
        try {
            $passkeys->verifyRegistration(
                expectedChallenge: $options['challenge'],
                clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($clientData),
                attestationObjectBase64Url: PasskeyVerifier::base64UrlEncode($attestationObject),
                now: 10_015,
            );
            self::fail('Expected replayed registration challenge to fail.');
        } catch (SecurityException) {
            self::addToAssertionCount(1);
        }

        // Now perform a real WebAuthn login assertion using the extracted PEM key
        $authOptions = $passkeys->createAuthenticationOptions(
            rpId: 'kongono.dev',
            origin: 'https://kongono.dev',
            allowCredentialIds: [$registered->credentialId],
            userVerification: 'required',
            now: 10_020,
        );
        self::assertSame([['type' => 'public-key', 'id' => $registered->credentialId]], $authOptions['allowCredentials']);

        $assertClientData = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $authOptions['challenge'],
            'origin' => 'https://kongono.dev',
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);
        $assertAuthData = hash('sha256', 'kongono.dev', true) . chr(0x05) . pack('N', 2);
        $signedPayload = $assertAuthData . hash('sha256', $assertClientData, true);
        $signature = '';
        self::assertTrue(openssl_sign($signedPayload, $signature, $privateKey, OPENSSL_ALGO_SHA256));

        $assertion = $passkeys->verifyAssertion(
            expectedChallenge: $authOptions['challenge'],
            clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($assertClientData),
            authenticatorDataBase64Url: PasskeyVerifier::base64UrlEncode($assertAuthData),
            signatureBase64Url: PasskeyVerifier::base64UrlEncode($signature),
            publicKey: $registered->publicKey,
            algorithm: $registered->algorithm,
            previousSignCount: $registered->signCount,
            requireUserVerification: true,
            now: 10_025,
        );

        self::assertSame(2, $assertion['signCount']);
        self::assertTrue($assertion['userPresent']);
        self::assertTrue($assertion['userVerified']);
    }

    public function testEdDsaPackedSelfAttestationWithExtensionsAndAssertion(): void
    {
        $passkeys = new PasskeyVerifier(new MemoryCache());
        $options = $passkeys->createRegistrationOptions(
            rpId: 'passkeys.example',
            rpName: 'Passkey Demo',
            origin: 'https://passkeys.example',
            userId: 'usr_ed25519',
            userName: 'grace@passkeys.example',
            userDisplayName: 'Grace Hopper',
            now: 20_000,
        );

        $keypair = sodium_crypto_sign_keypair();
        $publicKeyRaw = sodium_crypto_sign_publickey($keypair);
        $secretKeyRaw = sodium_crypto_sign_secretkey($keypair);

        $coseKey = self::cborMap([
            [1, 1],    // kty: OKP
            [3, -8],   // alg: EdDSA
            [-1, 6],   // crv: Ed25519
            [-2, new CborBytes($publicKeyRaw)],
        ]);
        $extensions = self::cborMap([
            ['credProps', self::cborMapRaw([['rk', true]])],
        ]);
        $credId = random_bytes(24);
        // Flags: UP (0x01) | UV (0x04) | BE (0x08) | BS (0x10) | AT (0x40) | ED (0x80) = 0xDD
        $authData = hash('sha256', 'passkeys.example', true)
            . chr(0xDD)
            . pack('N', 0)
            . str_repeat("\x00", 16)
            . pack('n', strlen($credId))
            . $credId
            . $coseKey
            . $extensions;

        $clientData = json_encode([
            'type' => 'webauthn.create',
            'challenge' => $options['challenge'],
            'origin' => 'https://passkeys.example',
        ], JSON_THROW_ON_ERROR);

        $selfSig = sodium_crypto_sign_detached($authData . hash('sha256', $clientData, true), $secretKeyRaw);
        $attestationObject = self::cborMap([
            ['fmt', 'packed'],
            ['attStmt', self::cborMapRaw([
                ['alg', -8],
                ['sig', new CborBytes($selfSig)],
            ])],
            ['authData', new CborBytes($authData)],
        ]);

        $registered = $passkeys->verifyRegistration(
            expectedChallenge: $options['challenge'],
            clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($clientData),
            attestationObjectBase64Url: PasskeyVerifier::base64UrlEncode($attestationObject),
            requireUserVerification: true,
            now: 20_005,
        );

        self::assertSame('EdDSA', $registered->algorithm);
        self::assertSame(bin2hex($publicKeyRaw), $registered->publicKey);
        self::assertSame('packed', $registered->attestationFormat);
        self::assertTrue($registered->backupEligible);
        self::assertTrue($registered->backupState);
        self::assertSame('00000000-0000-0000-0000-000000000000', $registered->aaguid);

        // Verify assertion with the extracted Ed25519 key
        $auth = $passkeys->createAuthenticationOptions('passkeys.example', 'https://passkeys.example', now: 20_010);
        $assertClient = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $auth['challenge'],
            'origin' => 'https://passkeys.example',
        ], JSON_THROW_ON_ERROR);
        $assertAuth = hash('sha256', 'passkeys.example', true) . chr(0x05) . pack('N', 0);
        $assertSig = sodium_crypto_sign_detached($assertAuth . hash('sha256', $assertClient, true), $secretKeyRaw);

        $verified = $passkeys->verifyAssertion(
            expectedChallenge: $auth['challenge'],
            clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($assertClient),
            authenticatorDataBase64Url: PasskeyVerifier::base64UrlEncode($assertAuth),
            signatureBase64Url: PasskeyVerifier::base64UrlEncode($assertSig),
            publicKey: $registered->publicKey,
            algorithm: $registered->algorithm,
            previousSignCount: 0,
            requireUserVerification: true,
            now: 20_015,
        );
        self::assertTrue($verified['userVerified']);
    }

    public function testRs256RegistrationAndAssertionRoundTrip(): void
    {
        $passkeys = new PasskeyVerifier(new MemoryCache());
        $options = $passkeys->createRegistrationOptions(
            rpId: 'winhello.example',
            rpName: 'Enterprise App',
            origin: 'https://winhello.example',
            userId: 'usr_rsa',
            userName: 'tpm@winhello.example',
            userDisplayName: 'TPM User',
            now: 30_000,
        );

        $rsaKey = self::generateOpenSslKey([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        $details = openssl_pkey_get_details($rsaKey);
        self::assertIsArray($details);
        self::assertIsArray($details['rsa'] ?? null);
        $modulus = (string) $details['rsa']['n'];
        $exponent = (string) $details['rsa']['e'];

        $coseKey = self::cborMap([
            [1, 3],      // kty: RSA
            [3, -257],   // alg: RS256
            [-1, new CborBytes($modulus)],
            [-2, new CborBytes($exponent)],
        ]);
        $credId = random_bytes(16);
        $authData = hash('sha256', 'winhello.example', true)
            . chr(0x45)
            . pack('N', 3)
            . str_repeat("\x11", 16)
            . pack('n', strlen($credId))
            . $credId
            . $coseKey;

        $attestation = self::cborMap([
            ['fmt', 'none'],
            ['attStmt', self::cborMapRaw([])],
            ['authData', new CborBytes($authData)],
        ]);
        $clientData = json_encode([
            'type' => 'webauthn.create',
            'challenge' => $options['challenge'],
            'origin' => 'https://winhello.example',
        ], JSON_THROW_ON_ERROR);

        $registered = $passkeys->verifyRegistration(
            expectedChallenge: $options['challenge'],
            clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($clientData),
            attestationObjectBase64Url: PasskeyVerifier::base64UrlEncode($attestation),
            now: 30_005,
        );

        self::assertSame('RS256', $registered->algorithm);
        self::assertStringContainsString('-----BEGIN PUBLIC KEY-----', $registered->publicKey);

        $auth = $passkeys->createAuthenticationOptions('winhello.example', 'https://winhello.example', now: 30_010);
        $assertClient = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $auth['challenge'],
            'origin' => 'https://winhello.example',
        ], JSON_THROW_ON_ERROR);
        $assertAuth = hash('sha256', 'winhello.example', true) . chr(0x05) . pack('N', 4);
        $sig = '';
        self::assertTrue(openssl_sign($assertAuth . hash('sha256', $assertClient, true), $sig, $rsaKey, OPENSSL_ALGO_SHA256));

        $verified = $passkeys->verifyAssertion(
            expectedChallenge: $auth['challenge'],
            clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($assertClient),
            authenticatorDataBase64Url: PasskeyVerifier::base64UrlEncode($assertAuth),
            signatureBase64Url: PasskeyVerifier::base64UrlEncode($sig),
            publicKey: $registered->publicKey,
            algorithm: 'RS256',
            previousSignCount: 3,
            now: 30_015,
        );
        self::assertSame(4, $verified['signCount']);
    }

    public function testRegistrationSecurityHardeningRejectsCrossCeremonyForgeriesAndBadCbor(): void
    {
        $passkeys = new PasskeyVerifier(new MemoryCache());

        // 1. Cross-ceremony confusion: registration challenge rejected by verifyAssertion()
        $regOpts = $passkeys->createRegistrationOptions('kongono.dev', 'Kongono', 'https://kongono.dev', 'u1', 'a@b.c', 'A', now: 1000);
        try {
            $passkeys->verifyAssertion(
                expectedChallenge: $regOpts['challenge'],
                clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode('{}'),
                authenticatorDataBase64Url: PasskeyVerifier::base64UrlEncode(str_repeat("\x00", 37)),
                signatureBase64Url: PasskeyVerifier::base64UrlEncode('sig'),
                publicKey: str_repeat('a', 64),
                algorithm: 'EdDSA',
                now: 1005,
            );
            self::fail('Expected ceremony mismatch.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('ceremony mismatch', strtolower($e->getMessage()));
        }

        // 2. Cross-ceremony confusion: assertion challenge rejected by verifyRegistration()
        $authOpts = $passkeys->createAuthenticationOptions('kongono.dev', 'https://kongono.dev', now: 1000);
        try {
            $passkeys->verifyRegistration(
                expectedChallenge: $authOpts['challenge'],
                clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode('{}'),
                attestationObjectBase64Url: PasskeyVerifier::base64UrlEncode("\xa0"),
                now: 1005,
            );
            self::fail('Expected ceremony mismatch.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('ceremony mismatch', strtolower($e->getMessage()));
        }

        // 3. Forged packed self-attestation rejected
        $kp = sodium_crypto_sign_keypair();
        $cose = self::cborMap([[1, 1], [3, -8], [-1, 6], [-2, new CborBytes(sodium_crypto_sign_publickey($kp))]]);
        $credId = random_bytes(16);
        $authData = hash('sha256', 'kongono.dev', true) . chr(0x41) . pack('N', 0) . str_repeat("\x00", 16) . pack('n', 16) . $credId . $cose;
        $reg2 = $passkeys->createRegistrationOptions('kongono.dev', 'Kongono', 'https://kongono.dev', 'u1', 'a@b.c', 'A', now: 2000);
        $cd2 = json_encode(['type' => 'webauthn.create', 'challenge' => $reg2['challenge'], 'origin' => 'https://kongono.dev'], JSON_THROW_ON_ERROR);
        $badPacked = self::cborMap([
            ['fmt', 'packed'],
            ['attStmt', self::cborMapRaw([['alg', -8], ['sig', new CborBytes(str_repeat("\x42", 64))]])],
            ['authData', new CborBytes($authData)],
        ]);
        try {
            $passkeys->verifyRegistration(
                expectedChallenge: $reg2['challenge'],
                clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($cd2),
                attestationObjectBase64Url: PasskeyVerifier::base64UrlEncode($badPacked),
                now: 2005,
            );
            self::fail('Expected forged packed self-attestation to fail.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('self-attestation', strtolower($e->getMessage()));
        }

        // 4. Non-empty attStmt with fmt="none" rejected
        $reg3 = $passkeys->createRegistrationOptions('kongono.dev', 'Kongono', 'https://kongono.dev', 'u1', 'a@b.c', 'A', now: 2000);
        $cd3 = json_encode(['type' => 'webauthn.create', 'challenge' => $reg3['challenge'], 'origin' => 'https://kongono.dev'], JSON_THROW_ON_ERROR);
        $badNone = self::cborMap([
            ['fmt', 'none'],
            ['attStmt', self::cborMapRaw([['extra', 1]])],
            ['authData', new CborBytes($authData)],
        ]);
        try {
            $passkeys->verifyRegistration(
                expectedChallenge: $reg3['challenge'],
                clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($cd3),
                attestationObjectBase64Url: PasskeyVerifier::base64UrlEncode($badNone),
                now: 2005,
            );
            self::fail('Expected non-empty none attStmt to fail.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('empty attstmt', strtolower($e->getMessage()));
        }

        // 5. Off-curve P-256 point rejected by OpenSSL curve validation
        $badEcCose = self::cborMap([
            [1, 2],
            [3, -7],
            [-1, 1],
            [-2, new CborBytes(str_repeat("\x00", 32))],
            [-3, new CborBytes(str_repeat("\x00", 32))],
        ]);
        $badEcAuth = hash('sha256', 'kongono.dev', true) . chr(0x41) . pack('N', 0) . str_repeat("\x00", 16) . pack('n', 16) . $credId . $badEcCose;
        $reg4 = $passkeys->createRegistrationOptions('kongono.dev', 'Kongono', 'https://kongono.dev', 'u1', 'a@b.c', 'A', now: 2000);
        $cd4 = json_encode(['type' => 'webauthn.create', 'challenge' => $reg4['challenge'], 'origin' => 'https://kongono.dev'], JSON_THROW_ON_ERROR);
        $badEcAtt = self::cborMap([
            ['fmt', 'none'],
            ['attStmt', self::cborMapRaw([])],
            ['authData', new CborBytes($badEcAuth)],
        ]);
        try {
            $passkeys->verifyRegistration(
                expectedChallenge: $reg4['challenge'],
                clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($cd4),
                attestationObjectBase64Url: PasskeyVerifier::base64UrlEncode($badEcAtt),
                now: 2005,
            );
            self::fail('Expected off-curve P-256 key to fail.');
        } catch (SecurityException) {
            self::addToAssertionCount(1);
        }

        // 6. Weak RSA (< 2048-bit) key rejected
        $weakRsaCose = self::cborMap([
            [1, 3],
            [3, -257],
            [-1, new CborBytes(str_repeat("\xAA", 128))],
            [-2, new CborBytes("\x01\x00\x01")],
        ]);
        $weakRsaAuth = hash('sha256', 'kongono.dev', true) . chr(0x41) . pack('N', 0) . str_repeat("\x00", 16) . pack('n', 16) . $credId . $weakRsaCose;
        $reg5 = $passkeys->createRegistrationOptions('kongono.dev', 'Kongono', 'https://kongono.dev', 'u1', 'a@b.c', 'A', now: 2000);
        $cd5 = json_encode(['type' => 'webauthn.create', 'challenge' => $reg5['challenge'], 'origin' => 'https://kongono.dev'], JSON_THROW_ON_ERROR);
        $weakRsaAtt = self::cborMap([
            ['fmt', 'none'],
            ['attStmt', self::cborMapRaw([])],
            ['authData', new CborBytes($weakRsaAuth)],
        ]);
        try {
            $passkeys->verifyRegistration(
                expectedChallenge: $reg5['challenge'],
                clientDataJsonBase64Url: PasskeyVerifier::base64UrlEncode($cd5),
                attestationObjectBase64Url: PasskeyVerifier::base64UrlEncode($weakRsaAtt),
                now: 2005,
            );
            self::fail('Expected weak 1024-bit RSA key to fail.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('2048', $e->getMessage());
        }

        // 7. CborDecoder hardening: indefinite length, duplicate map keys, excessive depth, trailing bytes, bad UTF-8
        $badCborPayloads = [
            "\xbf\xff",                                 // indefinite-length map
            "\xa2\x01\x02\x01\x03",                     // duplicate integer key 1
            str_repeat("\x81", 20) . "\x00",            // nesting depth > 16
            "\x01\x02",                                 // trailing byte after uint 1
            "\x62\xff\xfe",                             // invalid UTF-8 text string
            "\x45abc",                                  // truncated 5-byte bstr
        ];
        foreach ($badCborPayloads as $payload) {
            try {
                CborDecoder::decode($payload);
                self::fail('Expected CborDecoder to reject malformed payload: ' . bin2hex($payload));
            } catch (SecurityException) {
                self::addToAssertionCount(1);
            }
        }
    }

    /**
     * Minimal test-only RFC 8949 CBOR encoder for constructing genuine WebAuthn test fixtures.
     *
     * @param list<array{0: int|string, 1: mixed}> $entries
     */
    private static function cborMap(array $entries): string
    {
        $out = self::cborHead(5, count($entries));
        foreach ($entries as [$k, $v]) {
            $out .= self::cborEncode($k);
            $out .= is_array($v) && isset($v['__raw']) && is_string($v['__raw']) ? $v['__raw'] : self::cborEncode($v);
        }

        return $out;
    }

    /**
     * @param list<array{0: int|string, 1: mixed}> $entries
     * @return array{__raw: string}
     */
    private static function cborMapRaw(array $entries): array
    {
        return ['__raw' => self::cborMap($entries)];
    }

    private static function cborEncode(mixed $value): string
    {
        if (is_int($value)) {
            return $value >= 0
                ? self::cborHead(0, $value)
                : self::cborHead(1, -1 - $value);
        }
        if ($value instanceof CborBytes) {
            return self::cborHead(2, strlen($value->bytes)) . $value->bytes;
        }
        if (is_string($value)) {
            return self::cborHead(3, strlen($value)) . $value;
        }
        if (is_bool($value)) {
            return $value ? "\xf5" : "\xf4";
        }
        if (null === $value) {
            return "\xf6";
        }

        return '';
    }

    private static function cborHead(int $major, int $value): string
    {
        $prefix = $major << 5;
        if ($value < 24) {
            return chr($prefix | $value);
        }
        if ($value <= 0xFF) {
            return chr($prefix | 24) . chr($value);
        }
        if ($value <= 0xFFFF) {
            return chr($prefix | 25) . pack('n', $value);
        }

        return chr($prefix | 26) . pack('N', $value);
    }

    /**
     * Cross-platform OpenSSL keypair helper (handles Windows PHP installs without OPENSSL_CONF set).
     *
     * @param array<string, mixed> $options
     */
    private static function generateOpenSslKey(array $options): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new($options);
        if (false !== $key) {
            return $key;
        }

        $candidates = [
            dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . 'extras' . DIRECTORY_SEPARATOR . 'ssl' . DIRECTORY_SEPARATOR . 'openssl.cnf',
            dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . 'openssl.cnf',
        ];
        foreach ($candidates as $cnf) {
            if (is_file($cnf)) {
                $key = openssl_pkey_new([...$options, 'config' => $cnf]);
                if (false !== $key) {
                    return $key;
                }
            }
        }

        $tmpCnf = tempnam(sys_get_temp_dir(), 'kgn_ssl_');
        self::assertIsString($tmpCnf);
        file_put_contents($tmpCnf, "[req]\ndistinguished_name = dn\n[dn]\n");
        try {
            $key = openssl_pkey_new([...$options, 'config' => $tmpCnf]);
            self::assertNotFalse($key, 'Failed to generate OpenSSL test keypair: ' . (openssl_error_string() ?: 'unknown error'));

            return $key;
        } finally {
            @unlink($tmpCnf);
        }
    }
}
