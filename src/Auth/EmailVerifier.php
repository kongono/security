<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Security\SecurityException;
use Kongono\Security\SignedUrl;
use SensitiveParameter;

/**
 * Domain-separated, expiring email verification link issuer and verifier.
 *
 * Embeds only `uid` and a SHA-256 digest of the normalized email (`eh`) in the signed URL
 * so raw email addresses never leak into server access logs and changing a user's email
 * automatically invalidates previously issued verification links.
 */
final readonly class EmailVerifier
{
    private SignedUrl $signer;

    public function __construct(
        #[SensitiveParameter]
        string $secretKey,
    ) {
        $this->signer = new SignedUrl($secretKey, domain: 'kongono:email-verify:v1');
    }

    public function createVerificationLink(
        string $path,
        string $userId,
        string $email,
        int $ttlSeconds = 86_400,
        ?int $now = null,
    ): string {
        $cleanUid = trim($userId);
        $cleanEmail = strtolower(trim($email));
        if ('' === $cleanUid) {
            throw new SecurityException('Email verification requires a non-empty user ID.');
        }
        if ('' === $cleanEmail || false === filter_var($cleanEmail, FILTER_VALIDATE_EMAIL)) {
            throw new SecurityException('Email verification requires a valid email address.');
        }

        return $this->signer->temporary($path, max(60, $ttlSeconds), [
            'uid' => $cleanUid,
            'eh' => hash('sha256', $cleanEmail),
        ], $now);
    }

    public function verifyLink(
        string $signedPathWithQuery,
        string $expectedUserId,
        string $expectedEmail,
        ?int $now = null,
    ): bool {
        if (!$this->signer->verify($signedPathWithQuery, $now)) {
            return false;
        }

        $parts = parse_url($signedPathWithQuery);
        if (false === $parts || !isset($parts['query'])) {
            return false;
        }

        $params = SignedUrl::parseStrictQuery($parts['query']);
        if (null === $params) {
            return false;
        }

        $uid = $params['uid'] ?? null;
        $emailHash = $params['eh'] ?? null;
        if (!is_string($uid) || !is_string($emailHash)) {
            return false;
        }

        $expectedHash = hash('sha256', strtolower(trim($expectedEmail)));

        return hash_equals(trim($expectedUserId), $uid) && hash_equals($expectedHash, $emailHash);
    }
}
