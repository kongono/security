<?php

declare(strict_types=1);

namespace Kongono\Security\Egress;

use Closure;
use CurlHandle;
use Fiber;
use Kongono\Security\SecurityException;

/**
 * SSRF-hardened outbound HTTP client.
 *
 * Defends against SSRF & DNS rebinding by:
 *   1. Requiring HTTPS by default and enforcing optional host allowlists
 *   2. Resolving DNS explicitly and rejecting loopback/private/link-local/metadata IPs
 *   3. Pinning the validated IP via CURLOPT_RESOLVE while preserving TLS SNI & hostname verification
 *   4. Disabling redirects, proxies, netrc, and enforcing response byte caps
 */
final readonly class SafeHttpClient
{
    /**
     * @param list<string>                                $allowedHosts Optional exact hostname allowlist
     * @param (Closure(string): list<string>)|null        $dnsResolver  Optional custom DNS resolver for testing
     */
    public function __construct(
        private array $allowedHosts = [],
        private bool $allowPlainHttp = false,
        private bool $allowPrivateIps = false,
        private int $maxResponseBytes = 2_097_152,
        private ?Closure $dnsResolver = null,
    ) {}

    /**
     * Validate a target URL and resolve its admitted IP address (without performing network I/O).
     *
     * @return array{scheme: string, host: string, port: int, ip: string}
     */
    public function admitTarget(string $url): array
    {
        $parts = parse_url($url);
        if (false === $parts || !isset($parts['scheme'], $parts['host'])) {
            throw new SecurityException('Outbound URL must include valid scheme and host.');
        }

        $scheme = strtolower($parts['scheme']);
        if ('https' !== $scheme && !($this->allowPlainHttp && 'http' === $scheme)) {
            throw new SecurityException(sprintf('Outbound URL scheme "%s" is denied by egress policy.', $scheme));
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new SecurityException('Embedded credentials in outbound URLs are forbidden.');
        }

        $host = strtolower($parts['host']);
        $port = $parts['port'] ?? ('https' === $scheme ? 443 : 80);
        if ($port < 1) {
            throw new SecurityException(sprintf('Invalid outbound port %d.', $port));
        }

        if ([] !== $this->allowedHosts && !in_array($host, $this->allowedHosts, true)) {
            throw new SecurityException(sprintf('Outbound host "%s" is not in the explicit allowlist.', $host));
        }

        $ips = $this->resolveHost($host);
        if ([] === $ips) {
            throw new SecurityException(sprintf('Unable to resolve outbound host "%s".', $host));
        }

        // Fail closed if ANY resolved A/AAAA record points to a private/reserved address (blocks DNS rebinding)
        foreach ($ips as $ip) {
            if (!$this->isIpAdmitted($ip)) {
                throw new SecurityException(sprintf('Outbound host "%s" resolved to a private/reserved IP address (SSRF blocked).', $host));
            }
        }

        return ['scheme' => $scheme, 'host' => $host, 'port' => $port, 'ip' => $ips[0]];
    }

    /**
     * Perform an SSRF-safe HTTP request pinned to the admitted IP.
     *
     * @param array<string, string> $headers
     * @return array{status: int, body: string}
     */
    public function request(string $method, string $url, array $headers = [], ?string $body = null, int $timeoutSeconds = 15): array
    {
        $upperMethod = strtoupper(trim($method));
        if ('' === $upperMethod) {
            throw new SecurityException('Outbound HTTP method cannot be empty.');
        }

        $target = $this->admitTarget($url);

        $ch = curl_init($url);
        if (false === $ch) {
            throw new SecurityException('Unable to initialize cURL handle.');
        }

        $headerLines = $this->formatHeaders($headers);

        $pinIp = str_contains($target['ip'], ':') ? '[' . $target['ip'] . ']' : $target['ip'];
        $collected = '';
        $overflow = false;
        $maxBytes = $this->maxResponseBytes;
        $allowedProtos = $this->allowPlainHttp ? 'http,https' : 'https';

        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $upperMethod,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RESOLVE => [sprintf('%s:%d:%s', $target['host'], $target['port'], $pinIp)],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS_STR => $allowedProtos,
            CURLOPT_REDIR_PROTOCOLS_STR => $allowedProtos,
            CURLOPT_PROXY => '',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => min(10, max(1, $timeoutSeconds)),
            CURLOPT_TIMEOUT => max(1, $timeoutSeconds),
            CURLOPT_WRITEFUNCTION => static function (mixed $_ch, string $chunk) use (&$collected, &$overflow, $maxBytes): int {
                if (strlen($collected) + strlen($chunk) > $maxBytes) {
                    $overflow = true;

                    return 0;
                }
                $collected .= $chunk;

                return strlen($chunk);
            },
        ]);

        if (null !== $body) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $ok = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);

        if ($overflow) {
            throw new SecurityException(sprintf('Outbound response exceeded maximum bound of %d bytes.', $this->maxResponseBytes));
        }
        if (false === $ok) {
            throw new SecurityException('Outbound HTTP transfer failed: ' . $error);
        }

        return ['status' => $status, 'body' => $collected];
    }

    /**
     * Execute multiple SSRF-safe HTTP requests concurrently via curl_multi,
     * pre-validating EVERY target URL and pinning every resolved IP before opening sockets.
     * Cooperatively yields if invoked inside a PHP Fiber.
     *
     * @template TKey of array-key
     * @param array<TKey, array{method?: string, url: string, headers?: array<string, string>, body?: ?string, timeout?: int}> $requests
     * @return array<TKey, array{status: int, body: string}>
     */
    public function requestMany(array $requests): array
    {
        if ([] === $requests) {
            return [];
        }

        // Fail closed upfront: admit every target URL & IP BEFORE launching any transfer
        /** @var array<TKey, array{method: non-empty-string, url: string, headers: array<string, string>, body: ?string, timeout: int, target: array{scheme: string, host: string, port: int, ip: string}}> $prepared */
        $prepared = [];
        foreach ($requests as $key => $req) {
            $upperMethod = strtoupper(trim($req['method'] ?? 'GET'));
            if ('' === $upperMethod) {
                throw new SecurityException('Outbound HTTP method cannot be empty.');
            }
            $prepared[$key] = [
                'method' => $upperMethod,
                'url' => $req['url'],
                'headers' => $req['headers'] ?? [],
                'body' => $req['body'] ?? null,
                'timeout' => $req['timeout'] ?? 15,
                'target' => $this->admitTarget($req['url']),
            ];
        }

        $multi = curl_multi_init();
        /** @var array<TKey, CurlHandle> $handles */
        $handles = [];
        /** @var array<TKey, string> $buffers */
        $buffers = [];
        /** @var array<TKey, bool> $overflows */
        $overflows = [];
        $maxBytes = $this->maxResponseBytes;

        try {
            foreach ($prepared as $key => $item) {
                $ch = curl_init($item['url']);
                if (false === $ch) {
                    throw new SecurityException('Unable to initialize cURL handle.');
                }

                $headerLines = $this->formatHeaders($item['headers']);

                $pinIp = str_contains($item['target']['ip'], ':') ? '[' . $item['target']['ip'] . ']' : $item['target']['ip'];
                $buffers[$key] = '';
                $overflows[$key] = false;
                $allowedProtos = $this->allowPlainHttp ? 'http,https' : 'https';

                curl_setopt_array($ch, [
                    CURLOPT_CUSTOMREQUEST => $item['method'],
                    CURLOPT_HTTPHEADER => $headerLines,
                    CURLOPT_RESOLVE => [sprintf('%s:%d:%s', $item['target']['host'], $item['target']['port'], $pinIp)],
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_PROTOCOLS_STR => $allowedProtos,
                    CURLOPT_REDIR_PROTOCOLS_STR => $allowedProtos,
                    CURLOPT_PROXY => '',
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2,
                    CURLOPT_CONNECTTIMEOUT => min(10, max(1, $item['timeout'])),
                    CURLOPT_TIMEOUT => max(1, $item['timeout']),
                    CURLOPT_WRITEFUNCTION => static function (mixed $_ch, string $chunk) use (&$buffers, &$overflows, $key, $maxBytes): int {
                        if (strlen($buffers[$key]) + strlen($chunk) > $maxBytes) {
                            $overflows[$key] = true;

                            return 0;
                        }
                        $buffers[$key] .= $chunk;

                        return strlen($chunk);
                    },
                ]);

                if (null !== $item['body']) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $item['body']);
                }

                $handles[$key] = $ch;
                curl_multi_add_handle($multi, $ch);
            }

            do {
                $status = curl_multi_exec($multi, $active);
                if (null !== Fiber::getCurrent()) {
                    Fiber::suspend();
                } elseif ($active > 0 && CURLM_OK === $status) {
                    curl_multi_select($multi, 0.05);
                }
            } while ($active > 0 && (CURLM_OK === $status || CURLM_CALL_MULTI_PERFORM === $status));

            /** @var array<TKey, array{status: int, body: string}> $results */
            $results = [];
            foreach ($handles as $key => $ch) {
                if ($overflows[$key]) {
                    throw new SecurityException(sprintf('Outbound response exceeded maximum bound of %d bytes.', $this->maxResponseBytes));
                }
                $error = curl_error($ch);
                if ('' !== $error) {
                    throw new SecurityException('Outbound HTTP transfer failed: ' . $error);
                }
                $results[$key] = [
                    'status' => curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
                    'body' => $buffers[$key],
                ];
            }

            return $results;
        } finally {
            foreach ($handles as $ch) {
                curl_multi_remove_handle($multi, $ch);
            }
            curl_multi_close($multi);
        }
    }

    public function isIpAdmitted(string $ip): bool
    {
        if (false === filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        if ($this->allowPrivateIps) {
            return true;
        }

        $packed = @inet_pton($ip);
        if (false === $packed) {
            return false;
        }

        // Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d / ::ffff:xxxx:xxxx) and 6to4 (2002::/16) / Teredo / NAT64
        if (16 === strlen($packed)) {
            if (str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")) {
                $mappedV4 = @inet_ntop(substr($packed, 12, 4));

                return is_string($mappedV4) && $this->isIpAdmitted($mappedV4);
            }
            // Reject ::, ::1, fc00::/7 (ULA), fe80::/10 (link-local), ff00::/8 (multicast), 100::/64, 64:ff9b::/96 (NAT64)
            $b0 = ord($packed[0]);
            $b1 = ord($packed[1]);
            if (
                $packed === str_repeat("\x00", 16)
                || $packed === str_repeat("\x00", 15) . "\x01"
                || 0xfc === ($b0 & 0xfe)
                || (0xfe === $b0 && 0x80 === ($b1 & 0xc0))
                || 0xff === $b0
                || str_starts_with($packed, "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00")
            ) {
                return false;
            }
        } elseif (4 === strlen($packed)) {
            $o0 = ord($packed[0]);
            $o1 = ord($packed[1]);
            // Block 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10 (CGNAT), 127.0.0.0/8, 169.254.0.0/16 (IMDS),
            // 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 (multicast), 240.0.0.0/4 (reserved)
            if (
                0 === $o0
                || 10 === $o0
                || (100 === $o0 && $o1 >= 64 && $o1 <= 127)
                || 127 === $o0
                || (169 === $o0 && 254 === $o1)
                || (172 === $o0 && $o1 >= 16 && $o1 <= 31)
                || (192 === $o0 && 168 === $o1)
                || $o0 >= 224
            ) {
                return false;
            }
        }

        return false !== filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    /** @return list<string> */
    private function resolveHost(string $host): array
    {
        $trimmed = trim($host, '[]');
        if (false !== filter_var($trimmed, FILTER_VALIDATE_IP)) {
            return [$trimmed];
        }

        if (null !== $this->dnsResolver) {
            return ($this->dnsResolver)($host);
        }

        $ips = [];
        $v4 = gethostbynamel($host);
        if (is_array($v4)) {
            array_push($ips, ...$v4);
        }

        if (function_exists('dns_get_record')) {
            $aaaa = @dns_get_record($host, DNS_AAAA);
            if (is_array($aaaa)) {
                foreach ($aaaa as $rec) {
                    if (is_string($rec['ipv6'] ?? null)) {
                        $ips[] = $rec['ipv6'];
                    }
                }
            }
        }

        return array_values(array_unique($ips));
    }

    /**
     * @param array<string, string> $headers
     * @return list<string>
     */
    private function formatHeaders(array $headers): array
    {
        $lines = [];
        foreach ($headers as $name => $value) {
            if (1 !== preg_match('/\A[a-zA-Z0-9!#$%&\'*+.^_`|~-]+\z/', $name) || false !== strpbrk($value, "\r\n\0")) {
                throw new SecurityException(sprintf('Unsafe outbound HTTP header "%s" rejected.', $name));
            }
            $lines[] = $name . ': ' . $value;
        }

        return $lines;
    }
}
