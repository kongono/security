<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

/**
 * Typed wrapper for RFC 8949 CBOR byte strings (major type 2),
 * keeping binary payloads distinct from UTF-8 text strings (major type 3).
 */
final readonly class CborBytes
{
    public function __construct(
        public string $bytes,
    ) {}
}
