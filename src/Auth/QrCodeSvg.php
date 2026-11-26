<?php

declare(strict_types=1);

namespace Kongono\Security\Auth;

use Kongono\Security\SecurityException;

/**
 * Pure PHP 8.5, zero-dependency ISO/IEC 18004 QR Code encoder & strict-CSP SVG renderer.
 *
 * Supports Byte-mode QR Code Versions 1–10 at Error Correction Level M (15%) and L (7%),
 * covering up to 271 UTF-8 bytes — ideal for RFC 6238 TOTP `otpauth://` URIs and
 * signed cryptographic cross-device login URLs (`QrLoginAuth`) with zero external CDNs or JS.
 */
final readonly class QrCodeSvg
{
    /**
     * ISO/IEC 18004 Table 9 parameters for Versions 1–10:
     * [ecCodewordsPerBlock, group1Blocks, group1DataCodewords, group2Blocks, group2DataCodewords].
     *
     * @var array<'L'|'M', array<int, array{0: int, 1: int, 2: int, 3: int, 4: int}>>
     */
    private const array VERSION_SPEC = [
        'M' => [
            1 => [10, 1, 16, 0, 0],
            2 => [16, 1, 28, 0, 0],
            3 => [26, 1, 44, 0, 0],
            4 => [18, 2, 32, 0, 0],
            5 => [24, 2, 43, 0, 0],
            6 => [16, 4, 27, 0, 0],
            7 => [18, 4, 31, 0, 0],
            8 => [22, 2, 38, 2, 39],
            9 => [22, 3, 36, 2, 37],
            10 => [26, 4, 43, 1, 44],
        ],
        'L' => [
            1 => [7, 1, 19, 0, 0],
            2 => [10, 1, 34, 0, 0],
            3 => [15, 1, 55, 0, 0],
            4 => [20, 1, 80, 0, 0],
            5 => [26, 1, 108, 0, 0],
            6 => [18, 2, 68, 0, 0],
            7 => [20, 2, 78, 0, 0],
            8 => [24, 2, 97, 0, 0],
            9 => [30, 2, 116, 0, 0],
            10 => [18, 2, 68, 2, 69],
        ],
    ];

    /**
     * ISO/IEC 18004 Table E.1 alignment pattern center coordinates (Versions 1–10).
     *
     * @var array<int, list<int>>
     */
    private const array ALIGNMENT_CENTERS = [
        1 => [],
        2 => [6, 18],
        3 => [6, 22],
        4 => [6, 26],
        5 => [6, 30],
        6 => [6, 34],
        7 => [6, 22, 38],
        8 => [6, 24, 42],
        9 => [6, 26, 46],
        10 => [6, 28, 50],
    ];

    /**
     * Render a strict-CSP inline `<svg>` QR code with 4-module quiet zone (zero inline styles/scripts).
     *
     * @param 'L'|'M' $ecLevel
     */
    public static function render(
        string $payload,
        int $size = 220,
        string $ecLevel = 'M',
        string $darkColor = '#09090b',
        string $lightColor = '#ffffff',
        string $ariaLabel = 'QR code',
    ): string {
        $matrix = self::encodeMatrix($payload, $ecLevel);
        $dim = count($matrix);
        $quiet = 4;
        $total = $dim + (2 * $quiet);
        $clampedSize = max(64, min(1024, $size));
        $safeDark = self::validateHexColor($darkColor, '#09090b');
        $safeLight = self::validateHexColor($lightColor, '#ffffff');
        $safeLabel = htmlspecialchars(trim($ariaLabel) !== '' ? trim($ariaLabel) : 'QR code', ENT_QUOTES, 'UTF-8');

        $pathParts = [];
        for ($r = 0; $r < $dim; ++$r) {
            $y = $r + $quiet;
            $c = 0;
            while ($c < $dim) {
                if (!$matrix[$r][$c]) {
                    ++$c;
                    continue;
                }
                $start = $c;
                while ($c < $dim && $matrix[$r][$c]) {
                    ++$c;
                }
                $runLen = $c - $start;
                $x = $start + $quiet;
                $pathParts[] = sprintf('M%d %dh%dv1h-%dz', $x, $y, $runLen, $runLen);
            }
        }

        $d = implode('', $pathParts);

        return sprintf(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="%s"/><path d="%s" fill="%s"/></svg>',
            $total,
            $total,
            $clampedSize,
            $clampedSize,
            $safeLabel,
            $total,
            $total,
            $safeLight,
            $d,
            $safeDark,
        );
    }

    /**
     * Encode `$payload` into a raw boolean QR module matrix (`true` = dark module, `false` = light module).
     *
     * @param 'L'|'M' $ecLevel
     * @return list<list<bool>>
     */
    public static function encodeMatrix(string $payload, string $ecLevel = 'M'): array
    {
        $len = strlen($payload);
        if (0 === $len) {
            throw new SecurityException('QR code payload cannot be empty.');
        }

        $level = 'L' === strtoupper($ecLevel) ? 'L' : 'M';
        $version = self::selectVersion($len, $level);
        $spec = self::VERSION_SPEC[$level][$version];

        $codewords = self::buildInterleavedCodewords($payload, $version, $spec);
        $size = (4 * $version) + 17;

        /** @var array<int, array<int, bool>> $modules */
        $modules = self::emptyGrid($size);
        /** @var array<int, array<int, bool>> $isFunction */
        $isFunction = self::emptyGrid($size);

        self::drawFunctionPatterns($modules, $isFunction, $version, $size);
        self::drawCodewords($modules, $isFunction, $codewords, $size);

        // Select the optimal mask pattern (0..7) minimizing ISO/IEC 18004 penalty score
        $bestPenalty = PHP_INT_MAX;
        $bestModules = $modules;

        for ($mask = 0; $mask < 8; ++$mask) {
            $candidate = self::applyMask($modules, $isFunction, $mask, $size);
            self::drawFormatBits($candidate, $level, $mask, $size);
            $penalty = self::penaltyScore($candidate, $size);
            if ($penalty < $bestPenalty) {
                $bestPenalty = $penalty;
                $bestModules = $candidate;
            }
        }

        $result = [];
        for ($r = 0; $r < $size; ++$r) {
            $row = [];
            for ($c = 0; $c < $size; ++$c) {
                $row[] = $bestModules[$r][$c];
            }
            $result[] = $row;
        }

        return $result;
    }

    /**
     * @return array<int, array<int, bool>>
     */
    private static function emptyGrid(int $size): array
    {
        $grid = [];
        for ($r = 0; $r < $size; ++$r) {
            $row = [];
            for ($c = 0; $c < $size; ++$c) {
                $row[$c] = false;
            }
            $grid[$r] = $row;
        }

        return $grid;
    }

    /**
     * @param 'L'|'M' $level
     */
    private static function selectVersion(int $byteLen, string $level): int
    {
        foreach (self::VERSION_SPEC[$level] as $version => [, $g1Blocks, $g1Data, $g2Blocks, $g2Data]) {
            $totalDataBytes = ($g1Blocks * $g1Data) + ($g2Blocks * $g2Data);
            $headerBits = 4 + ($version >= 10 ? 16 : 8);
            $maxBytes = intdiv(($totalDataBytes * 8) - $headerBits, 8);
            if ($byteLen <= $maxBytes) {
                return $version;
            }
        }

        throw new SecurityException(sprintf(
            'QR code payload (%d bytes) exceeds maximum supported capacity for EC level %s (Versions 1–10).',
            $byteLen,
            $level,
        ));
    }

    /**
     * @param array{0: int, 1: int, 2: int, 3: int, 4: int} $spec
     * @return list<int>
     */
    private static function buildInterleavedCodewords(string $payload, int $version, array $spec): array
    {
        [$ecLen, $g1Blocks, $g1Data, $g2Blocks, $g2Data] = $spec;
        $totalDataBytes = ($g1Blocks * $g1Data) + ($g2Blocks * $g2Data);
        $totalDataBits = $totalDataBytes * 8;

        /** @var list<int> $bits */
        $bits = [];
        // Byte mode indicator: 0100
        self::appendBits($bits, 0b0100, 4);
        // Character count indicator: 8 bits for V1-9, 16 bits for V10+
        self::appendBits($bits, strlen($payload), $version >= 10 ? 16 : 8);
        $len = strlen($payload);
        for ($i = 0; $i < $len; ++$i) {
            self::appendBits($bits, ord($payload[$i]), 8);
        }

        // Terminator (up to 4 zero bits)
        $terminator = min(4, $totalDataBits - count($bits));
        for ($i = 0; $i < $terminator; ++$i) {
            $bits[] = 0;
        }
        // Pad to byte boundary
        while (0 !== (count($bits) % 8)) {
            $bits[] = 0;
        }

        /** @var list<int> $dataBytes */
        $dataBytes = [];
        $bitCount = count($bits);
        for ($i = 0; $i < $bitCount; $i += 8) {
            $byte = 0;
            for ($b = 0; $b < 8; ++$b) {
                $byte = ($byte << 1) | $bits[$i + $b];
            }
            $dataBytes[] = $byte;
        }

        // Alternating pad codewords (0xEC, 0x11)
        $padToggle = 0;
        while (count($dataBytes) < $totalDataBytes) {
            $dataBytes[] = 0 === $padToggle ? 0xEC : 0x11;
            $padToggle ^= 1;
        }

        // Split into RS blocks and compute EC codewords per block
        $generator = self::rsGenerator($ecLen);
        /** @var list<list<int>> $dataBlocks */
        $dataBlocks = [];
        /** @var list<list<int>> $ecBlocks */
        $ecBlocks = [];
        $offset = 0;

        for ($b = 0; $b < $g1Blocks; ++$b) {
            $block = array_slice($dataBytes, $offset, $g1Data);
            $offset += $g1Data;
            $dataBlocks[] = $block;
            $ecBlocks[] = self::rsRemainder($block, $generator);
        }
        for ($b = 0; $b < $g2Blocks; ++$b) {
            $block = array_slice($dataBytes, $offset, $g2Data);
            $offset += $g2Data;
            $dataBlocks[] = $block;
            $ecBlocks[] = self::rsRemainder($block, $generator);
        }

        // Interleave data codewords, then EC codewords
        $maxDataLen = max($g1Data, $g2Data);
        $interleaved = [];
        for ($i = 0; $i < $maxDataLen; ++$i) {
            foreach ($dataBlocks as $block) {
                if (isset($block[$i])) {
                    $interleaved[] = $block[$i];
                }
            }
        }
        for ($i = 0; $i < $ecLen; ++$i) {
            foreach ($ecBlocks as $ec) {
                $interleaved[] = $ec[$i];
            }
        }

        return $interleaved;
    }

    /**
     * @param list<int> $bits
     */
    private static function appendBits(array &$bits, int $val, int $length): void
    {
        for ($i = $length - 1; $i >= 0; --$i) {
            $bits[] = ($val >> $i) & 1;
        }
    }

    /**
     * Compute Reed-Solomon generator polynomial coefficients (excluding leading x^degree term) over GF(256).
     *
     * @return list<int>
     */
    private static function rsGenerator(int $degree): array
    {
        $poly = array_fill(0, $degree, 0);
        $poly[$degree - 1] = 1;
        $root = 1;

        for ($i = 0; $i < $degree; ++$i) {
            for ($j = 0; $j < $degree; ++$j) {
                $poly[$j] = self::gfMultiply($poly[$j], $root);
                if ($j + 1 < $degree) {
                    $poly[$j] ^= $poly[$j + 1];
                }
            }
            $root = self::gfMultiply($root, 0x02);
        }

        return array_values($poly);
    }

    /**
     * @param list<int> $data
     * @param list<int> $generator
     * @return list<int>
     */
    private static function rsRemainder(array $data, array $generator): array
    {
        $deg = count($generator);
        $rem = array_fill(0, $deg, 0);

        foreach ($data as $byte) {
            $factor = $byte ^ array_shift($rem);
            $rem[] = 0;
            for ($i = 0; $i < $deg; ++$i) {
                $rem[$i] ^= self::gfMultiply($generator[$i], $factor);
            }
        }

        return array_values($rem);
    }

    /** Multiply two elements in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1 (0x11D). */
    private static function gfMultiply(int $x, int $y): int
    {
        $z = 0;
        for ($i = 7; $i >= 0; --$i) {
            $z = ($z << 1) ^ ((($z >> 7) & 1) * 0x11D);
            $z ^= ((($y >> $i) & 1) * $x);
        }

        return $z;
    }

    /**
     * @param array<int, array<int, bool>> $modules
     * @param array<int, array<int, bool>> $isFunction
     */
    private static function drawFunctionPatterns(array &$modules, array &$isFunction, int $version, int $size): void
    {
        // Timing patterns
        for ($i = 0; $i < $size; ++$i) {
            $dark = 0 === ($i % 2);
            self::setFunction($modules, $isFunction, 6, $i, $dark);
            self::setFunction($modules, $isFunction, $i, 6, $dark);
        }

        // Three 7x7 finder patterns with 1-module light separator
        self::drawFinder($modules, $isFunction, 3, 3, $size);
        self::drawFinder($modules, $isFunction, 3, $size - 4, $size);
        self::drawFinder($modules, $isFunction, $size - 4, 3, $size);

        // Alignment patterns (Versions 2+)
        $centers = self::ALIGNMENT_CENTERS[$version];
        $n = count($centers);
        for ($i = 0; $i < $n; ++$i) {
            for ($j = 0; $j < $n; ++$j) {
                if (
                    (0 === $i && 0 === $j)
                    || (0 === $i && $n - 1 === $j)
                    || ($n - 1 === $i && 0 === $j)
                ) {
                    continue;
                }
                self::drawAlignment($modules, $isFunction, $centers[$i], $centers[$j]);
            }
        }

        // Reserve format info areas (and fixed dark module at (size - 8, 8))
        for ($i = 0; $i <= 8; ++$i) {
            if (6 !== $i) {
                self::setFunction($modules, $isFunction, 8, $i, false);
                self::setFunction($modules, $isFunction, $i, 8, false);
            }
        }
        for ($i = $size - 8; $i < $size; ++$i) {
            self::setFunction($modules, $isFunction, 8, $i, false);
            self::setFunction($modules, $isFunction, $i, 8, false);
        }
        self::setFunction($modules, $isFunction, $size - 8, 8, true);

        // Version information (Versions 7+)
        if ($version >= 7) {
            $rem = $version;
            for ($i = 0; $i < 12; ++$i) {
                $rem = ($rem << 1) ^ ((($rem >> 11) & 1) * 0x1F25);
            }
            $bits = ($version << 12) | $rem;
            for ($i = 0; $i < 18; ++$i) {
                $dark = 1 === (($bits >> $i) & 1);
                $a = intdiv($i, 3);
                $b = $size - 11 + ($i % 3);
                self::setFunction($modules, $isFunction, $b, $a, $dark);
                self::setFunction($modules, $isFunction, $a, $b, $dark);
            }
        }
    }

    /**
     * @param array<int, array<int, bool>> $modules
     * @param array<int, array<int, bool>> $isFunction
     */
    private static function drawFinder(array &$modules, array &$isFunction, int $cy, int $cx, int $size): void
    {
        for ($dy = -4; $dy <= 4; ++$dy) {
            for ($dx = -4; $dx <= 4; ++$dx) {
                $y = $cy + $dy;
                $x = $cx + $dx;
                if ($y < 0 || $y >= $size || $x < 0 || $x >= $size) {
                    continue;
                }
                $dist = max(abs($dx), abs($dy));
                $dark = 2 !== $dist && 4 !== $dist;
                self::setFunction($modules, $isFunction, $y, $x, $dark);
            }
        }
    }

    /**
     * @param array<int, array<int, bool>> $modules
     * @param array<int, array<int, bool>> $isFunction
     */
    private static function drawAlignment(array &$modules, array &$isFunction, int $cy, int $cx): void
    {
        for ($dy = -2; $dy <= 2; ++$dy) {
            for ($dx = -2; $dx <= 2; ++$dx) {
                $dist = max(abs($dx), abs($dy));
                self::setFunction($modules, $isFunction, $cy + $dy, $cx + $dx, 1 !== $dist);
            }
        }
    }

    /**
     * @param array<int, array<int, bool>> $modules
     * @param array<int, array<int, bool>> $isFunction
     */
    private static function setFunction(array &$modules, array &$isFunction, int $row, int $col, bool $dark): void
    {
        $modules[$row][$col] = $dark;
        $isFunction[$row][$col] = true;
    }

    /**
     * @param array<int, array<int, bool>> $modules
     * @param array<int, array<int, bool>> $isFunction
     * @param list<int>                    $codewords
     */
    private static function drawCodewords(array &$modules, array &$isFunction, array $codewords, int $size): void
    {
        $bitIdx = 0;
        $totalBits = count($codewords) * 8;

        for ($right = $size - 1; $right >= 1; $right -= 2) {
            if (6 === $right) {
                $right = 5;
            }
            for ($vert = 0; $vert < $size; ++$vert) {
                $upward = 0 === ((($right + 1) & 2));
                $y = $upward ? ($size - 1 - $vert) : $vert;
                for ($j = 0; $j < 2; ++$j) {
                    $x = $right - $j;
                    if ($isFunction[$y][$x]) {
                        continue;
                    }
                    $dark = false;
                    if ($bitIdx < $totalBits) {
                        $byte = $codewords[$bitIdx >> 3];
                        $dark = 1 === (($byte >> (7 - ($bitIdx & 7))) & 1);
                        ++$bitIdx;
                    }
                    $modules[$y][$x] = $dark;
                }
            }
        }
    }

    /**
     * @param array<int, array<int, bool>> $modules
     * @param array<int, array<int, bool>> $isFunction
     * @return array<int, array<int, bool>>
     */
    private static function applyMask(array $modules, array $isFunction, int $mask, int $size): array
    {
        $out = $modules;
        for ($r = 0; $r < $size; ++$r) {
            for ($c = 0; $c < $size; ++$c) {
                if ($isFunction[$r][$c]) {
                    continue;
                }
                $invert = match ($mask) {
                    0 => 0 === (($r + $c) % 2),
                    1 => 0 === ($r % 2),
                    2 => 0 === ($c % 3),
                    3 => 0 === (($r + $c) % 3),
                    4 => 0 === ((intdiv($r, 2) + intdiv($c, 3)) % 2),
                    5 => 0 === ((($r * $c) % 2) + (($r * $c) % 3)),
                    6 => 0 === (((($r * $c) % 2) + (($r * $c) % 3)) % 2),
                    default => 0 === (((($r + $c) % 2) + (($r * $c) % 3)) % 2),
                };
                if ($invert) {
                    $out[$r][$c] = !$out[$r][$c];
                }
            }
        }

        return $out;
    }

    /**
     * @param array<int, array<int, bool>> $modules
     * @param 'L'|'M'                      $level
     */
    private static function drawFormatBits(array &$modules, string $level, int $mask, int $size): void
    {
        $ecBits = 'L' === $level ? 0b01 : 0b00;
        $data = ($ecBits << 3) | ($mask & 0x07);
        $rem = $data;
        for ($i = 0; $i < 10; ++$i) {
            $rem = ($rem << 1) ^ ((($rem >> 9) & 1) * 0x537);
        }
        $bits = (($data << 10) | $rem) ^ 0x5412;

        // Copy 1 (top-left)
        for ($i = 0; $i <= 5; ++$i) {
            $modules[8][$i] = 1 === (($bits >> (14 - $i)) & 1);
        }
        $modules[8][7] = 1 === (($bits >> 8) & 1);
        $modules[8][8] = 1 === (($bits >> 7) & 1);
        $modules[7][8] = 1 === (($bits >> 6) & 1);
        for ($i = 0; $i <= 5; ++$i) {
            $modules[5 - $i][8] = 1 === (($bits >> (5 - $i)) & 1);
        }

        // Copy 2 (bottom-left & top-right)
        for ($i = 0; $i < 7; ++$i) {
            $modules[$size - 1 - $i][8] = 1 === (($bits >> (14 - $i)) & 1);
        }
        for ($i = 0; $i < 8; ++$i) {
            $modules[8][$size - 8 + $i] = 1 === (($bits >> (7 - $i)) & 1);
        }
    }

    /**
     * Compute ISO/IEC 18004 mask evaluation penalty score (N1 + N2 + N3 + N4).
     *
     * @param array<int, array<int, bool>> $modules
     */
    private static function penaltyScore(array $modules, int $size): int
    {
        $score = 0;

        // N1: 5+ consecutive same-color modules in rows and columns
        for ($r = 0; $r < $size; ++$r) {
            $runColor = $modules[$r][0];
            $runLen = 1;
            for ($c = 1; $c < $size; ++$c) {
                if ($modules[$r][$c] === $runColor) {
                    ++$runLen;
                    if (5 === $runLen) {
                        $score += 3;
                    } elseif ($runLen > 5) {
                        ++$score;
                    }
                } else {
                    $runColor = $modules[$r][$c];
                    $runLen = 1;
                }
            }
        }
        for ($c = 0; $c < $size; ++$c) {
            $runColor = $modules[0][$c];
            $runLen = 1;
            for ($r = 1; $r < $size; ++$r) {
                if ($modules[$r][$c] === $runColor) {
                    ++$runLen;
                    if (5 === $runLen) {
                        $score += 3;
                    } elseif ($runLen > 5) {
                        ++$score;
                    }
                } else {
                    $runColor = $modules[$r][$c];
                    $runLen = 1;
                }
            }
        }

        // N2: 2x2 same-color blocks
        for ($r = 0; $r < $size - 1; ++$r) {
            for ($c = 0; $c < $size - 1; ++$c) {
                $v = $modules[$r][$c];
                if ($v === $modules[$r][$c + 1] && $v === $modules[$r + 1][$c] && $v === $modules[$r + 1][$c + 1]) {
                    $score += 3;
                }
            }
        }

        // N3: Finder-like 1:1:3:1:1 patterns with 4 light modules on either side
        $patA = [true, false, true, true, true, false, true, false, false, false, false];
        $patB = [false, false, false, false, true, false, true, true, true, false, true];
        for ($r = 0; $r < $size; ++$r) {
            for ($c = 0; $c <= $size - 11; ++$c) {
                $slice = array_slice($modules[$r], $c, 11);
                if ($slice === $patA || $slice === $patB) {
                    $score += 40;
                }
            }
        }
        for ($c = 0; $c < $size; ++$c) {
            for ($r = 0; $r <= $size - 11; ++$r) {
                $matchA = true;
                $matchB = true;
                for ($k = 0; $k < 11; ++$k) {
                    if ($modules[$r + $k][$c] !== $patA[$k]) {
                        $matchA = false;
                    }
                    if ($modules[$r + $k][$c] !== $patB[$k]) {
                        $matchB = false;
                    }
                }
                if ($matchA || $matchB) {
                    $score += 40;
                }
            }
        }

        // N4: Dark module ratio deviation from 50%
        $dark = 0;
        for ($r = 0; $r < $size; ++$r) {
            for ($c = 0; $c < $size; ++$c) {
                if ($modules[$r][$c]) {
                    ++$dark;
                }
            }
        }
        $total = $size * $size;
        $k = (int) floor((abs(($dark * 20) - ($total * 10)) + $total - 1) / $total) - 1;
        $score += max(0, $k) * 10;

        return $score;
    }

    private static function validateHexColor(string $color, string $fallback): string
    {
        $trimmed = trim($color);
        if (1 === preg_match('/\A#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?\z/', $trimmed)) {
            return $trimmed;
        }

        return $fallback;
    }
}
