<?php

declare(strict_types=1);

namespace Kongono\Security\Tests;

use Kongono\Core\Cache\MemoryCache;
use Kongono\Security\Auth\OneTimeCodeAuth;
use Kongono\Security\Auth\QrCodeSvg;
use Kongono\Security\Auth\QrLoginAuth;
use Kongono\Security\Principal;
use Kongono\Security\PrincipalKind;
use Kongono\Security\SecurityException;
use Kongono\Security\Totp;
use PHPUnit\Framework\TestCase;

final class QrAndOneTimeCodeAuthTest extends TestCase
{
    public function testQrCodeSvgRoundTripsIso18004AndReedSolomonAcrossVersions1To10(): void
    {
        $samples = [
            // Version 1-M (<= 14 bytes)
            ['hello kongono', 'M', 1],
            // Version 2-M (15..26 bytes)
            ['https://kongono.com/auth', 'M', 2],
            // Version 3-M (27..42 bytes)
            ['https://kongono.com/auth/qr/verify/123', 'M', 3],
            // Version 4-M (43..62 bytes, 2 RS blocks)
            ['https://kongono.com/qr?cid=0123456789abcdef0123456789abcdef', 'M', 4],
            // Version 5-M (63..84 bytes, 2 RS blocks)
            ['https://kongono.com/auth/qr?cid=0123456789abcdef0123456789abcdef&v=1', 'M', 5],
            // Version 6-M (85..106 bytes, 4 RS blocks)
            [str_repeat('KONGONO-V6', 10), 'M', 6],
            // Version 7-M (107..122 bytes, Golay version bits + 4 RS blocks)
            [str_repeat('KONGONO-QR-V7-', 8), 'M', 7],
            // Version 8-M (123..152 bytes, uneven group1 + group2 RS blocks: 2x38 + 2x39)
            [str_repeat('ABCDEFGHIJ', 14), 'M', 8],
            // Version 9-M (153..180 bytes, 3x36 + 2x37 RS blocks)
            [str_repeat('Q', 170), 'M', 9],
            // Version 10-M (181..213 bytes, 16-bit byte length header + 4x43 + 1x44 RS blocks)
            [str_repeat('Z', 200), 'M', 10],
            // Version 10-L (up to 271 bytes)
            [str_repeat('L', 265), 'L', 10],
        ];

        foreach ($samples as [$payload, $ecLevel, $expectedVersion]) {
            $matrix = QrCodeSvg::encodeMatrix($payload, $ecLevel);
            $expectedDim = (4 * $expectedVersion) + 17;
            self::assertCount($expectedDim, $matrix, "Matrix height mismatch for V{$expectedVersion}-{$ecLevel}");
            self::assertCount($expectedDim, $matrix[0], "Matrix width mismatch for V{$expectedVersion}-{$ecLevel}");

            $decoded = $this->decodeAndVerifyQrMatrix($matrix, $expectedVersion, $ecLevel);
            self::assertSame($payload, $decoded, "Decoded payload mismatch for V{$expectedVersion}-{$ecLevel}");
        }

        // Strict-CSP SVG sanitization & TOTP provisioningQrSvg round-trip
        $totp = new Totp();
        $secret = Totp::generateSecret();
        $uri = $totp->provisioningUri($secret, 'dev@kongono.com', 'Kongono Studio');
        $svg = $totp->provisioningQrSvg($secret, 'dev@kongono.com', 'Kongono Studio', size: 240);

        self::assertStringStartsWith('<svg xmlns="http://www.w3.org/2000/svg"', $svg);
        self::assertStringContainsString('width="240" height="240"', $svg);
        self::assertStringContainsString('shape-rendering="crispEdges"', $svg);
        self::assertStringNotContainsString('style=', $svg);
        self::assertStringNotContainsString('<script', $svg);

        $uriMatrix = QrCodeSvg::encodeMatrix($uri, 'M');
        $uriVersion = intdiv(count($uriMatrix) - 17, 4);
        self::assertSame($uri, $this->decodeAndVerifyQrMatrix($uriMatrix, $uriVersion, 'M'));

        // Unsafe color/label injection is neutralized
        $safeSvg = QrCodeSvg::render('test', darkColor: 'red" onload="alert(1)', lightColor: 'javascript:bad', ariaLabel: '<b>QR</b>');
        self::assertStringContainsString('fill="#09090b"', $safeSvg);
        self::assertStringContainsString('fill="#ffffff"', $safeSvg);
        self::assertStringContainsString('aria-label="&lt;b&gt;QR&lt;/b&gt;"', $safeSvg);
        self::assertStringNotContainsString('onload=', $safeSvg);
    }

    public function testQrLoginAuthFullLifecycleQrljackingDefenseAndReplayProtection(): void
    {
        $cache = new MemoryCache();
        $qrAuth = new QrLoginAuth(str_repeat('k', 32), $cache);
        $now = 1_760_000_000;

        // 1. Desktop creates cryptographic QR login challenge
        $started = $qrAuth->begin(
            approvePath: 'https://app.kongono.com/auth/qr/approve',
            requesterIp: '203.0.113.42',
            requesterUserAgent: 'Chrome 132 / Windows',
            ttlSeconds: 180,
            now: $now,
        );

        self::assertStringContainsString('<svg ', $started['qr_svg']);
        self::assertStringNotContainsString($started['poll_secret'], $started['qr_payload']);
        self::assertMatchesRegularExpression('/\A\d{3}-\d{3}\z/', $started['verification_code']);
        self::assertSame('pending', $qrAuth->pollStatus($started['challenge_id'], $started['poll_secret'], $now));

        // Verify the signed QR payload encodes cleanly into a valid ISO/IEC 18004 QR matrix
        $qrMatrix = QrCodeSvg::encodeMatrix($started['qr_payload'], 'M');
        $qrVer = intdiv(count($qrMatrix) - 17, 4);
        self::assertSame($started['qr_payload'], $this->decodeAndVerifyQrMatrix($qrMatrix, $qrVer, 'M'));

        // Attacker without desktop's poll_secret cannot inspect status or claim
        self::assertSame('expired', $qrAuth->pollStatus($started['challenge_id'], 'wrong-secret', $now));
        self::assertNull($qrAuth->claim($started['challenge_id'], 'wrong-secret', $now));

        // Tampered QR payload is rejected fail-closed
        try {
            $qrAuth->inspect($started['qr_payload'] . 'x', $now + 5);
            self::fail('Expected tampered QR signature to fail.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('signature is invalid', $e->getMessage());
        }

        // 2. Authenticated phone scans QR -> transitions to `scanned` & reveals verification code + device metadata
        $inspected = $qrAuth->inspect($started['qr_payload'], $now + 10);
        self::assertSame('scanned', $inspected['status']);
        self::assertSame($started['verification_code'], $inspected['verification_code']);
        self::assertSame('203.0.113.42', $inspected['requester_ip']);
        self::assertSame('Chrome 132 / Windows', $inspected['requester_user_agent']);
        self::assertSame('scanned', $qrAuth->pollStatus($started['challenge_id'], $started['poll_secret'], $now + 10));

        // 3. Wrong verification code (QRLjacking mitigation) fails closed without resolving challenge
        $principal = new Principal('usr_42', PrincipalKind::Human, ['notes.read', 'notes.write'], ['email' => 'dev@kongono.com']);
        try {
            $qrAuth->approve($started['qr_payload'], $principal, verificationCode: '000-000' === $started['verification_code'] ? '111-111' : '000-000', now: $now + 15);
            self::fail('Expected wrong verification code to be rejected.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('verification code mismatch', $e->getMessage());
        }
        self::assertSame('scanned', $qrAuth->pollStatus($started['challenge_id'], $started['poll_secret'], $now + 16));

        // 4. Phone approves with matching verification code -> desktop claims Principal strictly once
        $qrAuth->approve($started['qr_payload'], $principal, verificationCode: $started['verification_code'], now: $now + 20);
        self::assertSame('approved', $qrAuth->pollStatus($started['challenge_id'], $started['poll_secret'], $now + 21));

        // Wrong poll_secret still cannot claim approved challenge
        self::assertNull($qrAuth->claim($started['challenge_id'], 'wrong-secret', $now + 22));

        $claimed = $qrAuth->claim($started['challenge_id'], $started['poll_secret'], $now + 22);
        self::assertInstanceOf(Principal::class, $claimed);
        self::assertSame('usr_42', $claimed->id);
        self::assertSame(PrincipalKind::Human, $claimed->kind);
        self::assertSame(['notes.read', 'notes.write'], $claimed->capabilities);
        self::assertSame('dev@kongono.com', $claimed->attributes['email'] ?? null);

        // Replay claim returns null (atomic single-use)
        self::assertNull($qrAuth->claim($started['challenge_id'], $started['poll_secret'], $now + 23));
        self::assertSame('expired', $qrAuth->pollStatus($started['challenge_id'], $started['poll_secret'], $now + 23));

        // 5. Explicit rejection flow
        $declined = $qrAuth->begin('https://app.kongono.com/auth/qr/approve', now: $now);
        $qrAuth->reject($declined['qr_payload'], $now + 5);
        self::assertSame('rejected', $qrAuth->pollStatus($declined['challenge_id'], $declined['poll_secret'], $now + 6));
        self::assertNull($qrAuth->claim($declined['challenge_id'], $declined['poll_secret'], $now + 6));

        // 6. Expiry fails closed
        $expired = $qrAuth->begin('https://app.kongono.com/auth/qr/approve', ttlSeconds: 60, now: $now);
        self::assertSame('expired', $qrAuth->pollStatus($expired['challenge_id'], $expired['poll_secret'], $now + 61));
        try {
            $qrAuth->inspect($expired['qr_payload'], $now + 61);
            self::fail('Expected expired QR challenge to fail.');
        } catch (SecurityException $e) {
            self::assertStringContainsString('expired', $e->getMessage());
        }
    }

    public function testOneTimeCodeAuthSingleUseLockoutReplacementAndNoPlaintextStorage(): void
    {
        $cache = new MemoryCache();
        $otp = new OneTimeCodeAuth(str_repeat('s', 32), $cache);
        $now = 1_760_000_000;

        // 1. Issue 6-digit OTP and confirm plaintext code is NEVER stored in cache
        $issued = $otp->issue('Dev@Kongono.com', digits: 6, ttlSeconds: 300, maxAttempts: 3, claims: ['purpose' => 'login'], now: $now);
        self::assertMatchesRegularExpression('/\A\d{6}\z/', $issued['code']);
        $stored = $cache->get('kongono:otp:id:' . hash('sha256', 'dev@kongono.com'));
        self::assertIsArray($stored);
        self::assertStringNotContainsString($issued['code'], json_encode($stored, JSON_THROW_ON_ERROR));

        // 2. Verify formatted user input (`123-456`), case-insensitive identifier, and atomic single-use
        $formatted = substr($issued['code'], 0, 3) . '-' . substr($issued['code'], 3, 3);
        $ok = $otp->verify('dev@kongono.com', $formatted, $now + 10);
        self::assertIsArray($ok);
        self::assertSame('dev@kongono.com', $ok['identifier']);
        self::assertSame('login', $ok['claims']['purpose'] ?? null);

        // Replay of the exact same OTP fails closed
        self::assertNull($otp->verify('dev@kongono.com', $issued['code'], $now + 11));

        // 3. Brute-force lockout: 3 wrong guesses immediately invalidate the OTP so even the real code fails
        $lockTest = $otp->issue('+15550001234', digits: 6, ttlSeconds: 300, maxAttempts: 3, now: $now);
        $wrong = '000000' === $lockTest['code'] ? '111111' : '000000';
        self::assertNull($otp->verify('+15550001234', $wrong, $now + 1));
        self::assertNull($otp->verify('+15550001234', $wrong, $now + 2));
        self::assertNull($otp->verify('+15550001234', $wrong, $now + 3));
        // Even the real code now fails because attempts hit maxAttempts = 3
        self::assertNull($otp->verify('+15550001234', $lockTest['code'], $now + 4));

        // 4. Issuing a new OTP replaces any previous active OTP
        $first = $otp->issue('replace@kongono.com', now: $now);
        $second = $otp->issue('replace@kongono.com', now: $now + 1);
        if ($first['code'] !== $second['code']) {
            self::assertNull($otp->verify('replace@kongono.com', $first['code'], $now + 2));
        }
        self::assertIsArray($otp->verify('replace@kongono.com', $second['code'], $now + 3));

        // 5. Expiration & explicit invalidation fail closed
        $exp = $otp->issue('expire@kongono.com', ttlSeconds: 60, now: $now);
        self::assertNull($otp->verify('expire@kongono.com', $exp['code'], $now + 60));

        $inv = $otp->issue('inv@kongono.com', ttlSeconds: 300, now: $now);
        $otp->invalidate('inv@kongono.com');
        self::assertNull($otp->verify('inv@kongono.com', $inv['code'], $now + 5));
    }

    /**
     * Independent ISO/IEC 18004 QR decoder + Reed-Solomon GF(256) syndrome verifier.
     *
     * Proves mathematically that every matrix generated by `QrCodeSvg` has valid finder/timing/alignment/
     * format/version modules, zero RS syndrome errors across all blocks, and decodes bit-for-bit to the input.
     *
     * @param list<list<bool>> $matrix
     */
    private function decodeAndVerifyQrMatrix(array $matrix, int $version, string $expectedEc): string
    {
        $size = count($matrix);
        self::assertSame((4 * $version) + 17, $size);

        // 1. Verify fixed dark module & timing patterns
        self::assertTrue($matrix[$size - 8][8], 'Fixed dark module missing');
        for ($i = 8; $i < $size - 8; ++$i) {
            self::assertSame(0 === ($i % 2), $matrix[6][$i], "Horizontal timing mismatch at col {$i}");
            self::assertSame(0 === ($i % 2), $matrix[$i][6], "Vertical timing mismatch at row {$i}");
        }

        // 2. Read both 15-bit format info copies & verify BCH(15,5) remainder === 0
        $fmt1 = 0;
        for ($i = 0; $i <= 5; ++$i) {
            $fmt1 = ($fmt1 << 1) | ($matrix[8][$i] ? 1 : 0);
        }
        $fmt1 = ($fmt1 << 1) | ($matrix[8][7] ? 1 : 0);
        $fmt1 = ($fmt1 << 1) | ($matrix[8][8] ? 1 : 0);
        $fmt1 = ($fmt1 << 1) | ($matrix[7][8] ? 1 : 0);
        for ($i = 5; $i >= 0; --$i) {
            $fmt1 = ($fmt1 << 1) | ($matrix[$i][8] ? 1 : 0);
        }

        $fmt2 = 0;
        for ($i = 0; $i < 7; ++$i) {
            $fmt2 = ($fmt2 << 1) | ($matrix[$size - 1 - $i][8] ? 1 : 0);
        }
        for ($i = 0; $i < 8; ++$i) {
            $fmt2 = ($fmt2 << 1) | ($matrix[8][$size - 8 + $i] ? 1 : 0);
        }

        self::assertSame($fmt1, $fmt2, 'Format info copies 1 and 2 must be identical');
        $unmaskedFmt = $fmt1 ^ 0x5412;
        $bchCheck = $unmaskedFmt;
        for ($bit = 14; $bit >= 10; --$bit) {
            if (1 === (($bchCheck >> $bit) & 1)) {
                $bchCheck ^= (0x537 << ($bit - 10));
            }
        }
        self::assertSame(0, $bchCheck, 'Format info BCH(15,5) check failed');

        $ecBits = ($unmaskedFmt >> 13) & 0x03;
        $mask = ($unmaskedFmt >> 10) & 0x07;
        self::assertSame('L' === $expectedEc ? 0b01 : 0b00, $ecBits);

        // 3. Reconstruct function-module mask independently
        $isFn = array_fill(0, $size, array_fill(0, $size, false));
        for ($i = 0; $i < $size; ++$i) {
            $isFn[6][$i] = true;
            $isFn[$i][6] = true;
        }
        foreach ([[3, 3], [3, $size - 4], [$size - 4, 3]] as [$cy, $cx]) {
            for ($dy = -4; $dy <= 4; ++$dy) {
                for ($dx = -4; $dx <= 4; ++$dx) {
                    $y = $cy + $dy;
                    $x = $cx + $dx;
                    if ($y >= 0 && $y < $size && $x >= 0 && $x < $size) {
                        $isFn[$y][$x] = true;
                    }
                }
            }
        }
        $alignTable = [
            1 => [], 2 => [6, 18], 3 => [6, 22], 4 => [6, 26], 5 => [6, 30],
            6 => [6, 34], 7 => [6, 22, 38], 8 => [6, 24, 42], 9 => [6, 26, 46], 10 => [6, 28, 50],
        ];
        $centers = $alignTable[$version];
        $cn = count($centers);
        for ($i = 0; $i < $cn; ++$i) {
            for ($j = 0; $j < $cn; ++$j) {
                if ((0 === $i && 0 === $j) || (0 === $i && $cn - 1 === $j) || ($cn - 1 === $i && 0 === $j)) {
                    continue;
                }
                for ($dy = -2; $dy <= 2; ++$dy) {
                    for ($dx = -2; $dx <= 2; ++$dx) {
                        $isFn[$centers[$i] + $dy][$centers[$j] + $dx] = true;
                    }
                }
            }
        }
        for ($i = 0; $i <= 8; ++$i) {
            $isFn[8][$i] = true;
            $isFn[$i][8] = true;
        }
        for ($i = $size - 8; $i < $size; ++$i) {
            $isFn[8][$i] = true;
            $isFn[$i][8] = true;
        }
        if ($version >= 7) {
            $v1 = 0;
            $v2 = 0;
            for ($i = 17; $i >= 0; --$i) {
                $a = intdiv($i, 3);
                $b = $size - 11 + ($i % 3);
                $v1 = ($v1 << 1) | ($matrix[$b][$a] ? 1 : 0);
                $v2 = ($v2 << 1) | ($matrix[$a][$b] ? 1 : 0);
                $isFn[$b][$a] = true;
                $isFn[$a][$b] = true;
            }
            self::assertSame($v1, $v2, 'Version info blocks must match');
            self::assertSame($version, $v1 >> 12);
            $golay = $v1;
            for ($bit = 17; $bit >= 12; --$bit) {
                if (1 === (($golay >> $bit) & 1)) {
                    $golay ^= (0x1F25 << ($bit - 12));
                }
            }
            self::assertSame(0, $golay, 'Version info Golay(18,6) check failed');
        }

        // 4. Read & unmask zig-zag codeword stream
        /** @var list<int> $bits */
        $bits = [];
        for ($right = $size - 1; $right >= 1; $right -= 2) {
            if (6 === $right) {
                $right = 5;
            }
            for ($vert = 0; $vert < $size; ++$vert) {
                $upward = 0 === (($right + 1) & 2);
                $y = $upward ? ($size - 1 - $vert) : $vert;
                for ($j = 0; $j < 2; ++$j) {
                    $x = $right - $j;
                    if ($isFn[$y][$x]) {
                        continue;
                    }
                    $invert = match ($mask) {
                        0 => 0 === (($y + $x) % 2),
                        1 => 0 === ($y % 2),
                        2 => 0 === ($x % 3),
                        3 => 0 === (($y + $x) % 3),
                        4 => 0 === ((intdiv($y, 2) + intdiv($x, 3)) % 2),
                        5 => 0 === ((($y * $x) % 2) + (($y * $x) % 3)),
                        6 => 0 === (((($y * $x) % 2) + (($y * $x) % 3)) % 2),
                        default => 0 === (((($y + $x) % 2) + (($y * $x) % 3)) % 2),
                    };
                    $bit = $matrix[$y][$x] !== $invert ? 1 : 0;
                    $bits[] = $bit;
                }
            }
        }

        // 5. De-interleave RS blocks and verify zero syndrome for EVERY block over GF(2^8)
        $specs = [
            'M' => [
                1 => [10, 1, 16, 0, 0], 2 => [16, 1, 28, 0, 0], 3 => [26, 1, 44, 0, 0],
                4 => [18, 2, 32, 0, 0], 5 => [24, 2, 43, 0, 0], 6 => [16, 4, 27, 0, 0],
                7 => [18, 4, 31, 0, 0], 8 => [22, 2, 38, 2, 39], 9 => [22, 3, 36, 2, 37],
                10 => [26, 4, 43, 1, 44],
            ],
            'L' => [
                1 => [7, 1, 19, 0, 0], 2 => [10, 1, 34, 0, 0], 3 => [15, 1, 55, 0, 0],
                4 => [20, 1, 80, 0, 0], 5 => [26, 1, 108, 0, 0], 6 => [18, 2, 68, 0, 0],
                7 => [20, 2, 78, 0, 0], 8 => [24, 2, 97, 0, 0], 9 => [30, 2, 116, 0, 0],
                10 => [18, 2, 68, 2, 69],
            ],
        ];
        [$ecLen, $g1Blocks, $g1Data, $g2Blocks, $g2Data] = $specs[$expectedEc][$version];
        $totalBlocks = $g1Blocks + $g2Blocks;
        $totalCodewords = ($g1Blocks * ($g1Data + $ecLen)) + ($g2Blocks * ($g2Data + $ecLen));

        /** @var list<int> $cw */
        $cw = [];
        for ($i = 0; $i < $totalCodewords; ++$i) {
            $b = 0;
            for ($k = 0; $k < 8; ++$k) {
                $b = ($b << 1) | $bits[($i * 8) + $k];
            }
            $cw[] = $b;
        }

        /** @var list<list<int>> $dataBlocks */
        $dataBlocks = array_fill(0, $totalBlocks, []);
        /** @var list<list<int>> $ecBlocks */
        $ecBlocks = array_fill(0, $totalBlocks, []);
        $cursor = 0;
        $maxDataLen = max($g1Data, $g2Data);
        for ($i = 0; $i < $maxDataLen; ++$i) {
            for ($blk = 0; $blk < $totalBlocks; ++$blk) {
                $limit = $blk < $g1Blocks ? $g1Data : $g2Data;
                if ($i < $limit) {
                    $dataBlocks[$blk][] = $cw[$cursor++];
                }
            }
        }
        for ($i = 0; $i < $ecLen; ++$i) {
            for ($blk = 0; $blk < $totalBlocks; ++$blk) {
                $ecBlocks[$blk][] = $cw[$cursor++];
            }
        }

        // Verify RS polynomial evaluates to 0 at every root alpha^0 .. alpha^(ecLen - 1)
        foreach ($dataBlocks as $idx => $dBlock) {
            $full = array_merge($dBlock, $ecBlocks[$idx]);
            $alphaPow = 1;
            for ($r = 0; $r < $ecLen; ++$r) {
                $eval = 0;
                foreach ($full as $coef) {
                    $eval = $this->gfMul($eval, $alphaPow) ^ $coef;
                }
                self::assertSame(0, $eval, "RS syndrome non-zero for V{$version}-{$expectedEc} block {$idx} root {$r}");
                $alphaPow = $this->gfMul($alphaPow, 0x02);
            }
        }

        // 6. Reassemble data bitstream and decode Byte mode payload
        /** @var list<int> $dataBits */
        $dataBits = [];
        foreach ($dataBlocks as $dBlock) {
            foreach ($dBlock as $byte) {
                for ($k = 7; $k >= 0; --$k) {
                    $dataBits[] = ($byte >> $k) & 1;
                }
            }
        }

        $readBits = static function (int $count) use (&$dataBits): int {
            $v = 0;
            for ($i = 0; $i < $count; ++$i) {
                $v = ($v << 1) | (array_shift($dataBits) ?? 0);
            }

            return $v;
        };

        self::assertSame(0b0100, $readBits(4), 'Expected Byte mode indicator 0100');
        $charCount = $readBits($version >= 10 ? 16 : 8);
        $out = '';
        for ($i = 0; $i < $charCount; ++$i) {
            $out .= chr($readBits(8));
        }

        return $out;
    }

    private function gfMul(int $a, int $b): int
    {
        $res = 0;
        for ($i = 7; $i >= 0; --$i) {
            $res = ($res << 1) ^ ((($res >> 7) & 1) * 0x11D);
            $res ^= ((($b >> $i) & 1) * $a);
        }

        return $res;
    }
}
