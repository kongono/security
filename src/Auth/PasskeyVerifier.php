<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Core\Cache\AtomicCacheInterface;
use Kongono\Core\Cache\CacheInterface;
use Kongono\Security\SecurityException;
use OpenSSLAsymmetricKey;

/**
 * Pure PHP 8.5 WebAuthn / FIDO2 Passkey registration and cryptographic assertion verifier.
 *
 * Supports end-to-end FaceID / TouchID / Windows Hello / YubiKey enrollment & login with zero third-party packages:
 *   - `createRegistrationOptions()` + `verifyRegistration()` for `navigator.credentials.create()` (`webauthn.create`)
 *   - `createAuthenticationOptions()` / `createChallenge()` + `verifyAssertion()` for `navigator.credentials.get()` (`webauthn.get`)
 *   - Domain-separated, atomic single-use challenges stored & consumed via `CacheInterface`
 *   - Pure-PHP RFC 8949 CBOR & COSE_Key decoding for ES256 (P-256), EdDSA (Ed25519), and RS256 (RSA >= 2048-bit)
 *   - Exact origin, SHA-256 `rpIdHash`, UP/UV/AT/BE/BS/ED flags, self-attestation (`packed`), and anti-cloning `signCount` checks
 */
final readonly class PasskeyVerifier
{
    /** @var list<string> */
    private const array SUPPORTED_ATTESTATION_FORMATS = [
        'none',
        'packed',
        'apple',
        'fido-u2f',
        'tpm',
        'android-key',
        'android-safetynet',
    ];

    /** @var list<string> */
    private const array VALID_USER_VERIFICATION = ['required', 'preferred', 'discouraged'];

    /** @var list<string> */
    private const array VALID_RESIDENT_KEY = ['required', 'preferred', 'discouraged'];

    /** @var list<string> */
    private const array VALID_ATTACHMENTS = ['platform', 'cross-platform'];

    /** @var list<string> */
    private const array VALID_TRANSPORTS = ['usb', 'nfc', 'ble', 'smart-card', 'hybrid', 'internal'];

    /** Fixed ASN.1 DER SPKI header for ECDSA P-256 (id-ecPublicKey + prime256v1) uncompressed 65-byte point. */
    private const string P256_SPKI_HEADER_HEX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    /** Fixed ASN.1 DER AlgorithmIdentifier for rsaEncryption (1.2.840.113549.1.1.1) + NULL. */
    private const string RSA_ALGORITHM_IDENTIFIER_HEX = '300d06092a864886f70d0101010500';

    public function __construct(
        private CacheInterface $cache,
        private string $cachePrefix = 'kongono:passkey:challenge:',
    ) {}

    /**
     * Issue JSON-ready W3C WebAuthn `PublicKeyCredentialCreationOptions` for `navigator.credentials.create()`.
     *
     * Stores a domain-separated one-time `'registration'` challenge bound to `$rpId`, `$origin`, and `$userId`.
     *
     * @param list<string> $excludeCredentialIds Existing base64url credential IDs already registered to this user
     * @return array{
     *     challenge: string,
     *     rp: array{id: string, name: string},
     *     user: array{id: string, name: string, displayName: string},
     *     pubKeyCredParams: list<array{type: string, alg: int}>,
     *     timeout: int,
     *     attestation: string,
     *     excludeCredentials: list<array{type: string, id: string}>,
     *     authenticatorSelection: array{
     *         residentKey: string,
     *         requireResidentKey: bool,
     *         userVerification: string,
     *         authenticatorAttachment?: string
     *     },
     *     expiresAt: int
     * }
     */
    public function createRegistrationOptions(
        string $rpId,
        string $rpName,
        string $origin,
        string $userId,
        string $userName,
        string $userDisplayName,
        array $excludeCredentialIds = [],
        string $userVerification = 'preferred',
        string $residentKey = 'preferred',
        ?string $authenticatorAttachment = null,
        int $ttlSeconds = 300,
        ?int $now = null,
    ): array {
        $cleanRpId = strtolower(trim($rpId));
        $cleanRpName = trim($rpName);
        $cleanOrigin = strtolower(rtrim(trim($origin), '/'));
        $cleanUserId = trim($userId);
        $cleanUserName = trim($userName);
        $cleanDisplayName = trim($userDisplayName);

        if ('' === $cleanRpId || '' === $cleanRpName || '' === $cleanOrigin) {
            throw new SecurityException('Passkey registration requires non-empty rpId, rpName, and origin.');
        }
        if ('' === $cleanUserId || strlen($cleanUserId) > 64 || '' === $cleanUserName || '' === $cleanDisplayName) {
            throw new SecurityException('Passkey registration requires a non-empty userId (<= 64 bytes), userName, and userDisplayName.');
        }
        if (!in_array($userVerification, self::VALID_USER_VERIFICATION, true)) {
            throw new SecurityException(sprintf('Invalid userVerification "%s".', $userVerification));
        }
        if (!in_array($residentKey, self::VALID_RESIDENT_KEY, true)) {
            throw new SecurityException(sprintf('Invalid residentKey "%s".', $residentKey));
        }
        if (null !== $authenticatorAttachment && !in_array($authenticatorAttachment, self::VALID_ATTACHMENTS, true)) {
            throw new SecurityException(sprintf('Invalid authenticatorAttachment "%s".', $authenticatorAttachment));
        }

        $ttl = max(30, $ttlSeconds);
        $challenge = self::base64UrlEncode(random_bytes(32));
        $expiresAt = ($now ?? time()) + $ttl;

        $this->cache->set(
            $this->challengeKey($challenge),
            json_encode([
                'kind' => 'registration',
                'rpId' => $cleanRpId,
                'origin' => $cleanOrigin,
                'userId' => $cleanUserId,
                'expiresAt' => $expiresAt,
            ], JSON_THROW_ON_ERROR),
            $ttl + 5,
        );

        $exclude = [];
        foreach ($excludeCredentialIds as $credId) {
            $trimmed = trim($credId);
            if ('' !== $trimmed) {
                $exclude[] = ['type' => 'public-key', 'id' => $trimmed];
            }
        }

        $selection = [
            'residentKey' => $residentKey,
            'requireResidentKey' => 'required' === $residentKey,
            'userVerification' => $userVerification,
        ];
        if (null !== $authenticatorAttachment) {
            $selection['authenticatorAttachment'] = $authenticatorAttachment;
        }

        return [
            'challenge' => $challenge,
            'rp' => [
                'id' => $cleanRpId,
                'name' => $cleanRpName,
            ],
            'user' => [
                'id' => self::base64UrlEncode($cleanUserId),
                'name' => $cleanUserName,
                'displayName' => $cleanDisplayName,
            ],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -7],   // ES256 (ECDSA P-256)
                ['type' => 'public-key', 'alg' => -8],   // EdDSA (Ed25519)
                ['type' => 'public-key', 'alg' => -257], // RS256 (RSASSA-PKCS1-v1_5 SHA-256)
            ],
            'timeout' => $ttl * 1000,
            'attestation' => 'none',
            'excludeCredentials' => $exclude,
            'authenticatorSelection' => $selection,
            'expiresAt' => $expiresAt,
        ];
    }

    /**
     * Verify a WebAuthn registration response (`navigator.credentials.create()`) per W3C WebAuthn §7.1.
     *
     * Decodes CBOR `attestationObject`, validates `webauthn.create` `clientDataJSON`, verifies `rpIdHash` and flags,
     * extracts and validates the COSE public key (ES256, EdDSA, or RS256), and verifies `packed` self-attestation when present.
     *
     * @param list<string> $allowedTopOrigins Explicit top-level origins allowed when `$allowCrossOrigin` is true
     * @param list<string> $transports        Optional transports reported by `response.getTransports()`
     */
    public function verifyRegistration(
        string $expectedChallenge,
        string $clientDataJsonBase64Url,
        string $attestationObjectBase64Url,
        bool $requireUserVerification = false,
        ?int $now = null,
        bool $allowCrossOrigin = false,
        array $allowedTopOrigins = [],
        array $transports = [],
    ): RegisteredPasskey {
        $meta = $this->consumeChallengeMetadata($expectedChallenge, 'registration', $now);

        $clientDataRaw = self::base64UrlDecode($clientDataJsonBase64Url);
        $this->validateClientData(
            clientDataRaw: $clientDataRaw,
            expectedType: 'webauthn.create',
            expectedChallenge: $expectedChallenge,
            expectedOrigin: $meta['origin'],
            allowCrossOrigin: $allowCrossOrigin,
            allowedTopOrigins: $allowedTopOrigins,
        );

        $attestationRaw = self::base64UrlDecode($attestationObjectBase64Url);
        $attestation = CborDecoder::decode($attestationRaw);
        if (!is_array($attestation)) {
            throw new SecurityException('Passkey attestationObject must decode to a CBOR map.');
        }

        $fmt = $attestation['fmt'] ?? null;
        $authDataObj = $attestation['authData'] ?? null;
        $attStmt = $attestation['attStmt'] ?? null;

        if (!is_string($fmt) || !in_array($fmt, self::SUPPORTED_ATTESTATION_FORMATS, true)) {
            throw new SecurityException('Unsupported or missing passkey attestation format.');
        }
        if (!$authDataObj instanceof CborBytes) {
            throw new SecurityException('Passkey attestationObject is missing binary authData.');
        }
        if (!is_array($attStmt)) {
            throw new SecurityException('Passkey attestationObject is missing attStmt map.');
        }

        $authData = $authDataObj->bytes;
        $authLen = strlen($authData);
        if ($authLen < 55) {
            throw new SecurityException('Passkey registration authenticatorData is truncated.');
        }

        $rpIdHash = substr($authData, 0, 32);
        $expectedRpIdHash = hash('sha256', $meta['rpId'], true);
        if (!hash_equals($expectedRpIdHash, $rpIdHash)) {
            throw new SecurityException('Passkey RP ID hash mismatch.');
        }

        $flags = ord($authData[32]);
        $userPresent = 0 !== ($flags & 0x01);
        $userVerified = 0 !== ($flags & 0x04);
        $backupEligible = 0 !== ($flags & 0x08);
        $backupState = 0 !== ($flags & 0x10);
        $attestedDataIncluded = 0 !== ($flags & 0x40);
        $extensionDataIncluded = 0 !== ($flags & 0x80);

        if (!$userPresent) {
            throw new SecurityException('Passkey User Present (UP) flag is not set.');
        }
        if ($requireUserVerification && !$userVerified) {
            throw new SecurityException('Passkey User Verified (UV) flag is required but not set.');
        }
        if ($backupState && !$backupEligible) {
            throw new SecurityException('Invalid passkey authenticatorData flags (BS set without BE).');
        }
        if (!$attestedDataIncluded) {
            throw new SecurityException('Passkey registration authenticatorData is missing attested credential data (AT flag).');
        }

        $unpackedCount = unpack('Ncount', substr($authData, 33, 4));
        $signCount = is_array($unpackedCount) && is_int($unpackedCount['count'] ?? null) ? $unpackedCount['count'] : 0;

        $aaguidBytes = substr($authData, 37, 16);
        $aaguid = self::formatAaguid($aaguidBytes);

        $unpackedCredLen = unpack('nlen', substr($authData, 53, 2));
        $credentialIdLen = is_array($unpackedCredLen) && is_int($unpackedCredLen['len'] ?? null) ? $unpackedCredLen['len'] : 0;
        if ($credentialIdLen < 1 || $credentialIdLen > 1023 || (55 + $credentialIdLen) >= $authLen) {
            throw new SecurityException('Passkey attested credential ID length is invalid or truncated.');
        }

        $rawCredentialId = substr($authData, 55, $credentialIdLen);
        $coseOffset = 55 + $credentialIdLen;

        $decodedKey = CborDecoder::decodeAt($authData, $coseOffset);
        $nextOffset = $decodedKey['nextOffset'];

        if (!$extensionDataIncluded && $nextOffset !== $authLen) {
            throw new SecurityException('Passkey registration authenticatorData contains trailing bytes without ED flag.');
        }
        if ($extensionDataIncluded) {
            if ($nextOffset >= $authLen) {
                throw new SecurityException('Passkey registration authenticatorData sets ED flag without extension payload.');
            }
            $decodedExt = CborDecoder::decodeAt($authData, $nextOffset);
            if (!is_array($decodedExt['value']) || $decodedExt['nextOffset'] !== $authLen) {
                throw new SecurityException('Passkey registration extension data is malformed or has trailing bytes.');
            }
        }

        $converted = self::coseKeyToPublicKey($decodedKey['value']);

        // Validate attestation statement invariants
        if ('none' === $fmt && [] !== $attStmt) {
            throw new SecurityException('Passkey attestation format "none" must have an empty attStmt.');
        }
        if ('packed' === $fmt && !isset($attStmt['x5c']) && !isset($attStmt['ecdaaKeyId'])) {
            $this->verifyPackedSelfAttestation($attStmt, $authData, $clientDataRaw, $converted['coseAlg'], $converted['algorithm'], $converted['publicKey']);
        }

        $normalizedTransports = [];
        foreach ($transports as $transport) {
            $clean = strtolower(trim($transport));
            if (in_array($clean, self::VALID_TRANSPORTS, true) && !in_array($clean, $normalizedTransports, true)) {
                $normalizedTransports[] = $clean;
            }
        }

        return new RegisteredPasskey(
            credentialId: self::base64UrlEncode($rawCredentialId),
            publicKey: $converted['publicKey'],
            algorithm: $converted['algorithm'],
            signCount: $signCount,
            userId: $meta['userId'] ?? '',
            aaguid: $aaguid,
            userPresent: $userPresent,
            userVerified: $userVerified,
            backupEligible: $backupEligible,
            backupState: $backupState,
            attestationFormat: $fmt,
            transports: $normalizedTransports,
        );
    }

    /**
     * Issue JSON-ready W3C WebAuthn `PublicKeyCredentialRequestOptions` for `navigator.credentials.get()`.
     *
     * @param list<string> $allowCredentialIds Optional base64url credential IDs (omit for discoverable/usernameless passkeys)
     * @return array{
     *     challenge: string,
     *     rpId: string,
     *     origin: string,
     *     timeout: int,
     *     userVerification: string,
     *     allowCredentials: list<array{type: string, id: string}>,
     *     expiresAt: int
     * }
     */
    public function createAuthenticationOptions(
        string $rpId,
        string $origin,
        array $allowCredentialIds = [],
        string $userVerification = 'preferred',
        int $ttlSeconds = 300,
        ?int $now = null,
    ): array {
        if (!in_array($userVerification, self::VALID_USER_VERIFICATION, true)) {
            throw new SecurityException(sprintf('Invalid userVerification "%s".', $userVerification));
        }

        $ttl = max(30, $ttlSeconds);
        $issued = $this->createChallenge($rpId, $origin, $ttl, $now);

        $allow = [];
        foreach ($allowCredentialIds as $credId) {
            $trimmed = trim($credId);
            if ('' !== $trimmed) {
                $allow[] = ['type' => 'public-key', 'id' => $trimmed];
            }
        }

        return [
            'challenge' => $issued['challenge'],
            'rpId' => $issued['rpId'],
            'origin' => $issued['origin'],
            'timeout' => $ttl * 1000,
            'userVerification' => $userVerification,
            'allowCredentials' => $allow,
            'expiresAt' => $issued['expiresAt'],
        ];
    }

    /**
     * Issue a one-time WebAuthn authentication challenge bound to `$rpId` and `$origin`.
     *
     * @return array{challenge: string, rpId: string, origin: string, expiresAt: int}
     */
    public function createChallenge(string $rpId, string $origin, int $ttlSeconds = 300, ?int $now = null): array
    {
        $cleanRpId = strtolower(trim($rpId));
        $cleanOrigin = strtolower(rtrim(trim($origin), '/'));
        if ('' === $cleanRpId || '' === $cleanOrigin) {
            throw new SecurityException('Passkey rpId and origin are required.');
        }

        $ttl = max(30, $ttlSeconds);
        $challenge = self::base64UrlEncode(random_bytes(32));
        $expiresAt = ($now ?? time()) + $ttl;

        $this->cache->set(
            $this->challengeKey($challenge),
            json_encode([
                'kind' => 'assertion',
                'rpId' => $cleanRpId,
                'origin' => $cleanOrigin,
                'expiresAt' => $expiresAt,
            ], JSON_THROW_ON_ERROR),
            $ttl + 5,
        );

        return [
            'challenge' => $challenge,
            'rpId' => $cleanRpId,
            'origin' => $cleanOrigin,
            'expiresAt' => $expiresAt,
        ];
    }

    /**
     * Verify a WebAuthn authentication assertion (`navigator.credentials.get()`).
     *
     * @param string       $algorithm         Supported: 'ES256', 'EdDSA', or 'RS256'
     * @param list<string> $allowedTopOrigins Explicit top-level origins allowed when $allowCrossOrigin is true
     * @return array{signCount: int, userPresent: bool, userVerified: bool}
     */
    public function verifyAssertion(
        string $expectedChallenge,
        string $clientDataJsonBase64Url,
        string $authenticatorDataBase64Url,
        string $signatureBase64Url,
        string $publicKey,
        string $algorithm = 'ES256',
        int $previousSignCount = 0,
        bool $requireUserVerification = false,
        ?int $now = null,
        bool $allowCrossOrigin = false,
        array $allowedTopOrigins = [],
    ): array {
        $meta = $this->consumeChallengeMetadata($expectedChallenge, 'assertion', $now);

        $clientDataRaw = self::base64UrlDecode($clientDataJsonBase64Url);
        $this->validateClientData(
            clientDataRaw: $clientDataRaw,
            expectedType: 'webauthn.get',
            expectedChallenge: $expectedChallenge,
            expectedOrigin: $meta['origin'],
            allowCrossOrigin: $allowCrossOrigin,
            allowedTopOrigins: $allowedTopOrigins,
        );

        $authData = self::base64UrlDecode($authenticatorDataBase64Url);
        if (strlen($authData) < 37) {
            throw new SecurityException('Passkey authenticatorData is truncated.');
        }

        $rpIdHash = substr($authData, 0, 32);
        $expectedRpIdHash = hash('sha256', $meta['rpId'], true);
        if (!hash_equals($expectedRpIdHash, $rpIdHash)) {
            throw new SecurityException('Passkey RP ID hash mismatch.');
        }

        $flags = ord($authData[32]);
        $userPresent = 0 !== ($flags & 0x01);
        $userVerified = 0 !== ($flags & 0x04);
        $backupEligible = 0 !== ($flags & 0x08);
        $backupState = 0 !== ($flags & 0x10);
        $attestedDataIncluded = 0 !== ($flags & 0x40);
        $extensionDataIncluded = 0 !== ($flags & 0x80);
        if (!$userPresent) {
            throw new SecurityException('Passkey User Present (UP) flag is not set.');
        }
        if ($requireUserVerification && !$userVerified) {
            throw new SecurityException('Passkey User Verified (UV) flag is required but not set.');
        }
        if ($backupState && !$backupEligible) {
            throw new SecurityException('Invalid passkey authenticatorData flags (BS set without BE).');
        }
        if ($attestedDataIncluded) {
            throw new SecurityException('Unexpected attested credential data flag (AT) in passkey assertion.');
        }
        if (!$extensionDataIncluded && 37 !== strlen($authData)) {
            throw new SecurityException('Passkey authenticatorData contains trailing bytes without ED flag.');
        }
        if ($extensionDataIncluded && strlen($authData) <= 37) {
            throw new SecurityException('Passkey authenticatorData sets ED flag without extension payload.');
        }

        $unpacked = unpack('Ncount', substr($authData, 33, 4));
        $signCount = is_array($unpacked) && is_int($unpacked['count'] ?? null) ? $unpacked['count'] : 0;
        // W3C WebAuthn §7.2 Step 21: reject if EITHER signCount or previousSignCount > 0 and signCount did not advance
        if (($signCount > 0 || $previousSignCount > 0) && $signCount <= $previousSignCount) {
            throw new SecurityException('Passkey signCount did not advance (possible cloned authenticator).');
        }

        $signature = self::base64UrlDecode($signatureBase64Url);
        $signedPayload = $authData . hash('sha256', $clientDataRaw, true);

        if (!$this->verifySignature($algorithm, $signedPayload, $signature, $publicKey)) {
            throw new SecurityException('Passkey cryptographic signature verification failed.');
        }

        return [
            'signCount' => $signCount,
            'userPresent' => $userPresent,
            'userVerified' => $userVerified,
        ];
    }

    public static function base64UrlEncode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $encoded): string
    {
        if ('' === $encoded || 1 !== preg_match('/\A[A-Za-z0-9_-]+={0,2}\z/', $encoded)) {
            throw new SecurityException('Invalid base64url payload.');
        }
        $unpadded = rtrim($encoded, '=');
        if (1 === (strlen($unpadded) % 4)) {
            throw new SecurityException('Invalid base64url payload length.');
        }
        $normalized = strtr($unpadded, '-_', '+/');
        $pad = strlen($normalized) % 4;
        if ($pad > 0) {
            $normalized .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($normalized, true);
        if (false === $decoded) {
            throw new SecurityException('Invalid base64url payload.');
        }

        return $decoded;
    }

    /**
     * @return array{rpId: string, origin: string, expiresAt: int, userId: ?string}
     */
    private function consumeChallengeMetadata(string $expectedChallenge, string $expectedKind, ?int $now): array
    {
        $cacheKey = $this->challengeKey($expectedChallenge);
        // Atomic single-use challenge consumption (prevents concurrent replay races)
        if ($this->cache instanceof AtomicCacheInterface) {
            $rawChallengeMeta = $this->cache->pull($cacheKey);
        } else {
            $rawChallengeMeta = $this->cache->get($cacheKey);
            $this->cache->delete($cacheKey);
        }
        if (!is_string($rawChallengeMeta) || '' === $rawChallengeMeta) {
            throw new SecurityException('Passkey challenge is unknown, expired, or already consumed.');
        }

        $meta = json_decode($rawChallengeMeta, true);
        if (!is_array($meta) || !is_string($meta['rpId'] ?? null) || !is_string($meta['origin'] ?? null) || !is_int($meta['expiresAt'] ?? null)) {
            throw new SecurityException('Stored passkey challenge metadata is invalid.');
        }

        $storedKind = is_string($meta['kind'] ?? null) ? $meta['kind'] : 'assertion';
        if ($storedKind !== $expectedKind) {
            throw new SecurityException(sprintf('Passkey challenge ceremony mismatch (expected %s, got %s).', $expectedKind, $storedKind));
        }

        if (($now ?? time()) >= $meta['expiresAt']) {
            throw new SecurityException('Passkey challenge has expired.');
        }

        $userId = is_string($meta['userId'] ?? null) ? $meta['userId'] : null;

        return [
            'rpId' => $meta['rpId'],
            'origin' => $meta['origin'],
            'expiresAt' => $meta['expiresAt'],
            'userId' => $userId,
        ];
    }

    /**
     * @param list<string> $allowedTopOrigins
     */
    private function validateClientData(
        string $clientDataRaw,
        string $expectedType,
        string $expectedChallenge,
        string $expectedOrigin,
        bool $allowCrossOrigin,
        array $allowedTopOrigins,
    ): void {
        $clientData = json_decode($clientDataRaw, true);
        if (!is_array($clientData)) {
            throw new SecurityException('Passkey clientDataJSON is not valid JSON.');
        }

        if (($clientData['type'] ?? null) !== $expectedType) {
            throw new SecurityException(sprintf('Passkey ceremony type must be "%s".', $expectedType));
        }

        $receivedChallenge = is_string($clientData['challenge'] ?? null) ? $clientData['challenge'] : '';
        if (!hash_equals($expectedChallenge, $receivedChallenge)) {
            throw new SecurityException('Passkey challenge mismatch.');
        }

        $receivedOrigin = is_string($clientData['origin'] ?? null) ? strtolower(rtrim($clientData['origin'], '/')) : '';
        if (!hash_equals(strtolower($expectedOrigin), $receivedOrigin)) {
            throw new SecurityException('Passkey origin mismatch.');
        }

        if (array_key_exists('crossOrigin', $clientData) && !is_bool($clientData['crossOrigin'])) {
            throw new SecurityException('Passkey crossOrigin flag must be a boolean.');
        }
        $isCrossOrigin = true === ($clientData['crossOrigin'] ?? false);
        if ($isCrossOrigin) {
            if (!$allowCrossOrigin) {
                $noun = 'webauthn.create' === $expectedType ? 'registrations' : 'assertions';
                throw new SecurityException(sprintf('Cross-origin passkey %s are denied by policy.', $noun));
            }
            $topOrigin = is_string($clientData['topOrigin'] ?? null) ? strtolower(rtrim($clientData['topOrigin'], '/')) : '';
            $matchedTopOrigin = false;
            foreach ($allowedTopOrigins as $allowedTop) {
                if ('' !== $topOrigin && hash_equals(strtolower(rtrim($allowedTop, '/')), $topOrigin)) {
                    $matchedTopOrigin = true;
                }
            }
            if (!$matchedTopOrigin) {
                throw new SecurityException('Cross-origin passkey topOrigin is missing or not allowlisted.');
            }
        }
    }

    /**
     * @param array<int|string, mixed> $attStmt
     */
    private function verifyPackedSelfAttestation(
        array $attStmt,
        string $authData,
        string $clientDataRaw,
        int $expectedCoseAlg,
        string $algorithm,
        string $publicKey,
    ): void {
        $stmtAlg = $attStmt['alg'] ?? null;
        $stmtSig = $attStmt['sig'] ?? null;
        if (!is_int($stmtAlg) || $stmtAlg !== $expectedCoseAlg || !$stmtSig instanceof CborBytes) {
            throw new SecurityException('Invalid packed self-attestation statement.');
        }

        $signedPayload = $authData . hash('sha256', $clientDataRaw, true);
        if (!$this->verifySignature($algorithm, $signedPayload, $stmtSig->bytes, $publicKey)) {
            throw new SecurityException('Packed self-attestation signature verification failed.');
        }
    }

    /**
     * Convert a decoded RFC 8152 COSE_Key map into a verified native PHP public key (PEM or Ed25519 hex).
     *
     * @return array{algorithm: string, coseAlg: int, publicKey: string}
     */
    private static function coseKeyToPublicKey(mixed $cose): array
    {
        if (!is_array($cose)) {
            throw new SecurityException('COSE public key must be a CBOR map.');
        }

        $kty = $cose[1] ?? null;
        $alg = $cose[3] ?? null;

        // ES256: EC2 (kty=2), alg=-7, crv=1 (P-256)
        if (2 === $kty && -7 === $alg) {
            if (1 !== ($cose[-1] ?? null)) {
                throw new SecurityException('ES256 COSE key must use P-256 curve (crv=1).');
            }
            $x = $cose[-2] ?? null;
            $y = $cose[-3] ?? null;
            if (!$x instanceof CborBytes || !$y instanceof CborBytes || 32 !== strlen($x->bytes) || 32 !== strlen($y->bytes)) {
                throw new SecurityException('ES256 COSE key requires 32-byte x and y coordinates.');
            }

            $header = hex2bin(self::P256_SPKI_HEADER_HEX);
            if (false === $header) {
                throw new SecurityException('Failed to construct P-256 SPKI header.');
            }
            $pem = self::derToPem($header . "\x04" . $x->bytes . $y->bytes);
            self::assertValidEs256Pem($pem);

            return ['algorithm' => 'ES256', 'coseAlg' => -7, 'publicKey' => $pem];
        }

        // EdDSA: OKP (kty=1), alg=-8, crv=6 (Ed25519)
        if (1 === $kty && -8 === $alg) {
            if (6 !== ($cose[-1] ?? null)) {
                throw new SecurityException('EdDSA COSE key must use Ed25519 curve (crv=6).');
            }
            $x = $cose[-2] ?? null;
            if (!$x instanceof CborBytes || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen($x->bytes)) {
                throw new SecurityException('EdDSA COSE key requires a 32-byte Ed25519 public key.');
            }

            return ['algorithm' => 'EdDSA', 'coseAlg' => -8, 'publicKey' => bin2hex($x->bytes)];
        }

        // RS256: RSA (kty=3), alg=-257, n >= 2048 bits, odd exponent e >= 3
        if (3 === $kty && -257 === $alg) {
            $nObj = $cose[-1] ?? null;
            $eObj = $cose[-2] ?? null;
            if (!$nObj instanceof CborBytes || !$eObj instanceof CborBytes) {
                throw new SecurityException('RS256 COSE key requires binary modulus (n) and exponent (e).');
            }

            $n = ltrim($nObj->bytes, "\x00");
            $e = ltrim($eObj->bytes, "\x00");
            if (strlen($n) < 256 || strlen($n) > 512) {
                throw new SecurityException('RS256 COSE key modulus must be between 2048 and 4096 bits.');
            }
            if ('' === $e || strlen($e) > 8 || 0 === (ord($e[strlen($e) - 1]) & 1) || "\x01" === $e) {
                throw new SecurityException('RS256 COSE key exponent is invalid.');
            }

            $algId = hex2bin(self::RSA_ALGORITHM_IDENTIFIER_HEX);
            if (false === $algId) {
                throw new SecurityException('Failed to construct RSA SPKI header.');
            }
            $rsaPublicKeyDer = self::derSequence(self::derInteger($n) . self::derInteger($e));
            $spkiDer = self::derSequence($algId . self::derBitString($rsaPublicKeyDer));
            $pem = self::derToPem($spkiDer);
            self::assertValidRs256Pem($pem);

            return ['algorithm' => 'RS256', 'coseAlg' => -257, 'publicKey' => $pem];
        }

        throw new SecurityException('Unsupported COSE public key type or algorithm (supported: ES256, EdDSA, RS256).');
    }

    private function verifySignature(string $algorithm, string $signedPayload, string $signature, string $publicKey): bool
    {
        return match ($algorithm) {
            'ES256' => $this->verifyEs256($signedPayload, $signature, $publicKey),
            'EdDSA' => $this->verifyEd25519($signedPayload, $signature, $publicKey),
            'RS256' => $this->verifyRs256($signedPayload, $signature, $publicKey),
            default => throw new SecurityException(sprintf('Unsupported passkey algorithm "%s".', $algorithm)),
        };
    }

    private function verifyEs256(string $signedPayload, string $signature, string $publicKeyPem): bool
    {
        $key = self::assertValidEs256Pem($publicKeyPem);

        return 1 === openssl_verify($signedPayload, $signature, $key, OPENSSL_ALGO_SHA256);
    }

    private function verifyRs256(string $signedPayload, string $signature, string $publicKeyPem): bool
    {
        $key = self::assertValidRs256Pem($publicKeyPem);

        return 1 === openssl_verify($signedPayload, $signature, $key, OPENSSL_ALGO_SHA256);
    }

    private function verifyEd25519(string $signedPayload, string $signature, string $publicKeyHexOrRaw): bool
    {
        if (SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES === strlen($publicKeyHexOrRaw)) {
            $rawKey = $publicKeyHexOrRaw;
        } elseif (64 === strlen($publicKeyHexOrRaw) && ctype_xdigit($publicKeyHexOrRaw)) {
            $rawKey = hex2bin($publicKeyHexOrRaw);
        } else {
            $rawKey = false;
        }
        if (!is_string($rawKey) || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen($rawKey)) {
            throw new SecurityException('Invalid Ed25519 public key (expected 32 raw bytes or 64 hex chars).');
        }
        if (SODIUM_CRYPTO_SIGN_BYTES !== strlen($signature)) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $signedPayload, $rawKey);
    }

    private static function assertValidEs256Pem(string $publicKeyPem): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if (false === $key) {
            throw new SecurityException('Invalid ES256 PEM public key.');
        }
        $details = openssl_pkey_get_details($key);
        if (
            false === $details
            || OPENSSL_KEYTYPE_EC !== ($details['type'] ?? null)
            || !is_array($details['ec'] ?? null)
            || 'prime256v1' !== ($details['ec']['curve_name'] ?? null)
        ) {
            throw new SecurityException('ES256 requires an ECDSA P-256 (prime256v1) public key.');
        }

        return $key;
    }

    private static function assertValidRs256Pem(string $publicKeyPem): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if (false === $key) {
            throw new SecurityException('Invalid RS256 PEM public key.');
        }
        $details = openssl_pkey_get_details($key);
        if (
            false === $details
            || OPENSSL_KEYTYPE_RSA !== ($details['type'] ?? null)
            || !is_int($details['bits'] ?? null)
            || $details['bits'] < 2048
        ) {
            throw new SecurityException('RS256 requires an RSA public key of at least 2048 bits.');
        }

        return $key;
    }

    private static function formatAaguid(string $bytes): string
    {
        $hex = bin2hex($bytes);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12),
        );
    }

    private static function derToPem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function derLength(int $length): string
    {
        if ($length < 0 || $length > 0xFFFF) {
            throw new SecurityException('DER length out of supported range.');
        }
        if ($length < 128) {
            return chr($length);
        }
        if ($length < 256) {
            return "\x81" . chr($length);
        }

        return "\x82" . pack('n', $length);
    }

    private static function derInteger(string $unsignedBigEndian): string
    {
        $body = 0 !== (ord($unsignedBigEndian[0]) & 0x80) ? "\x00" . $unsignedBigEndian : $unsignedBigEndian;

        return "\x02" . self::derLength(strlen($body)) . $body;
    }

    private static function derSequence(string $content): string
    {
        return "\x30" . self::derLength(strlen($content)) . $content;
    }

    private static function derBitString(string $content): string
    {
        return "\x03" . self::derLength(strlen($content) + 1) . "\x00" . $content;
    }

    private function challengeKey(string $challenge): string
    {
        return $this->cachePrefix . hash('sha256', $challenge);
    }
}
