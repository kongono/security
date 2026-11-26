<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Security\SecurityException;

/**
 * Pure PHP 8.5 RFC 8949 definite-length CBOR decoder hardened for WebAuthn & COSE payloads.
 *
 * Security invariants:
 *   - Rejects indefinite-length items (disallowed in CTAP2 canonical CBOR)
 *   - Enforces strict nesting depth (max 16) and container size limits (anti-DoS)
 *   - Rejects duplicate map keys, truncated buffers, invalid UTF-8 text strings, and trailing bytes
 */
final readonly class CborDecoder
{
    private const int MAX_DEPTH = 16;
    private const int MAX_ITEMS = 1024;
    private const int MAX_PAYLOAD_BYTES = 65_536;

    /**
     * Decode a complete CBOR buffer and fail closed if trailing bytes remain.
     */
    public static function decode(string $binary): mixed
    {
        if ('' === $binary) {
            throw new SecurityException('CBOR payload cannot be empty.');
        }
        if (strlen($binary) > self::MAX_PAYLOAD_BYTES) {
            throw new SecurityException('CBOR payload exceeds maximum permitted size.');
        }

        $result = self::decodeAt($binary, 0);
        if ($result['nextOffset'] !== strlen($binary)) {
            throw new SecurityException('CBOR payload contains unexpected trailing bytes.');
        }

        return $result['value'];
    }

    /**
     * Decode a single CBOR item starting at `$offset` and return both the value and the next byte offset.
     *
     * @return array{value: mixed, nextOffset: int}
     */
    public static function decodeAt(string $binary, int $offset = 0): array
    {
        $len = strlen($binary);
        if ($offset < 0 || $offset >= $len) {
            throw new SecurityException('CBOR decode offset is out of bounds.');
        }
        if ($len > self::MAX_PAYLOAD_BYTES) {
            throw new SecurityException('CBOR payload exceeds maximum permitted size.');
        }

        $cursor = $offset;
        $value = self::decodeItem($binary, $len, $cursor, 0);

        return [
            'value' => $value,
            'nextOffset' => $cursor,
        ];
    }

    private static function decodeItem(string $data, int $len, int &$offset, int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            throw new SecurityException('CBOR nesting depth exceeds safety limit.');
        }
        if ($offset >= $len) {
            throw new SecurityException('Unexpected end of CBOR buffer.');
        }

        $initial = ord($data[$offset]);
        ++$offset;
        $major = ($initial >> 5) & 0x07;
        $additionalInfo = $initial & 0x1F;

        return match ($major) {
            0 => self::readUnsignedArgument($data, $len, $offset, $additionalInfo),
            1 => self::decodeNegativeInt(self::readUnsignedArgument($data, $len, $offset, $additionalInfo)),
            2 => new CborBytes(self::readExactBytes($data, $len, $offset, self::readUnsignedArgument($data, $len, $offset, $additionalInfo))),
            3 => self::decodeUtf8Text(self::readExactBytes($data, $len, $offset, self::readUnsignedArgument($data, $len, $offset, $additionalInfo))),
            4 => self::decodeArray($data, $len, $offset, self::readUnsignedArgument($data, $len, $offset, $additionalInfo), $depth + 1),
            5 => self::decodeMap($data, $len, $offset, self::readUnsignedArgument($data, $len, $offset, $additionalInfo), $depth + 1),
            7 => self::decodeSimpleOrFloat($data, $len, $offset, $additionalInfo),
            default => throw new SecurityException(sprintf('Unsupported CBOR major type %d.', $major)),
        };
    }

    private static function readUnsignedArgument(string $data, int $len, int &$offset, int $additionalInfo): int
    {
        if ($additionalInfo <= 23) {
            return $additionalInfo;
        }
        if (24 === $additionalInfo) {
            $raw = self::readExactBytes($data, $len, $offset, 1);

            return ord($raw[0]);
        }
        if (25 === $additionalInfo) {
            $raw = self::readExactBytes($data, $len, $offset, 2);
            $unpacked = unpack('nv', $raw);
            if (!is_array($unpacked) || !is_int($unpacked['v'] ?? null)) {
                throw new SecurityException('Failed to unpack 16-bit CBOR integer.');
            }

            return $unpacked['v'];
        }
        if (26 === $additionalInfo) {
            $raw = self::readExactBytes($data, $len, $offset, 4);
            $unpacked = unpack('Nv', $raw);
            if (!is_array($unpacked) || !is_int($unpacked['v'] ?? null)) {
                throw new SecurityException('Failed to unpack 32-bit CBOR integer.');
            }

            return $unpacked['v'];
        }
        if (27 === $additionalInfo) {
            $raw = self::readExactBytes($data, $len, $offset, 8);
            if (0 !== (ord($raw[0]) & 0x80)) {
                throw new SecurityException('64-bit unsigned CBOR integer exceeds signed integer range.');
            }
            $unpacked = unpack('Jv', $raw);
            if (!is_array($unpacked) || !is_int($unpacked['v'] ?? null)) {
                throw new SecurityException('Failed to unpack 64-bit CBOR integer.');
            }

            return $unpacked['v'];
        }

        throw new SecurityException('Indefinite-length or reserved CBOR encoding is not permitted.');
    }

    private static function decodeNegativeInt(int $unsigned): int
    {
        if (PHP_INT_MAX === $unsigned) {
            return PHP_INT_MIN;
        }

        return -1 - $unsigned;
    }

    private static function readExactBytes(string $data, int $len, int &$offset, int $count): string
    {
        if ($count < 0 || $count > ($len - $offset)) {
            throw new SecurityException('Truncated CBOR payload.');
        }

        $slice = substr($data, $offset, $count);
        $offset += $count;

        return $slice;
    }

    private static function decodeUtf8Text(string $raw): string
    {
        if (1 !== preg_match('//u', $raw)) {
            throw new SecurityException('CBOR text string contains invalid UTF-8.');
        }

        return $raw;
    }

    /** @return list<mixed> */
    private static function decodeArray(string $data, int $len, int &$offset, int $count, int $depth): array
    {
        if ($count > self::MAX_ITEMS) {
            throw new SecurityException('CBOR array exceeds maximum item count.');
        }

        $items = [];
        for ($i = 0; $i < $count; ++$i) {
            $items[] = self::decodeItem($data, $len, $offset, $depth);
        }

        return $items;
    }

    /** @return array<int|string, mixed> */
    private static function decodeMap(string $data, int $len, int &$offset, int $count, int $depth): array
    {
        if ($count > self::MAX_ITEMS) {
            throw new SecurityException('CBOR map exceeds maximum entry count.');
        }

        $map = [];
        $seen = [];
        for ($i = 0; $i < $count; ++$i) {
            $key = self::decodeItem($data, $len, $offset, $depth);
            if (!is_int($key) && !is_string($key)) {
                throw new SecurityException('CBOR map keys must be integers or UTF-8 text strings.');
            }
            $canonicalKey = (is_int($key) ? 'i:' : 's:') . $key;
            if (isset($seen[$canonicalKey]) || array_key_exists($key, $map)) {
                throw new SecurityException('Duplicate CBOR map key detected.');
            }
            $seen[$canonicalKey] = true;
            $map[$key] = self::decodeItem($data, $len, $offset, $depth);
        }

        return $map;
    }

    private static function decodeSimpleOrFloat(string $data, int $len, int &$offset, int $additionalInfo): bool|float|null
    {
        return match ($additionalInfo) {
            20 => false,
            21 => true,
            22, 23 => null,
            25 => self::decodeHalfFloat(self::readExactBytes($data, $len, $offset, 2)),
            26 => self::unpackFloat('G', self::readExactBytes($data, $len, $offset, 4)),
            27 => self::unpackFloat('E', self::readExactBytes($data, $len, $offset, 8)),
            default => throw new SecurityException(sprintf('Unsupported CBOR simple value %d.', $additionalInfo)),
        };
    }

    private static function decodeHalfFloat(string $bytes): float
    {
        $unpacked = unpack('nv', $bytes);
        $half = is_array($unpacked) && is_int($unpacked['v'] ?? null) ? $unpacked['v'] : 0;
        $sign = 0 !== ($half & 0x8000) ? -1.0 : 1.0;
        $exp = ($half >> 10) & 0x1F;
        $mant = $half & 0x03FF;

        if (0 === $exp) {
            return $sign * (2.0 ** -14) * ($mant / 1024.0);
        }
        if (31 === $exp) {
            return 0 === $mant ? ($sign * INF) : NAN;
        }

        return $sign * (2.0 ** ($exp - 15)) * (1.0 + ($mant / 1024.0));
    }

    private static function unpackFloat(string $format, string $bytes): float
    {
        $unpacked = unpack($format . 'v', $bytes);
        if (!is_array($unpacked) || !is_float($unpacked['v'] ?? null)) {
            throw new SecurityException('Failed to decode CBOR floating-point value.');
        }

        return $unpacked['v'];
    }
}
