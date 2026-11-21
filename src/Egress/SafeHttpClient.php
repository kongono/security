<?php

declare(strict_types=1);

namespace Kongono\Security\Egress;

use Closure;
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

        $admittedIp = null;
        foreach ($ips as $ip) {
            if ($this->isIpAdmitted($ip)) {
                $admittedIp = $ip;
                break;
            }
        }

        if (null === $admittedIp) {
            throw new SecurityException(sprintf('Outbound host "%s" resolved only to private/reserved IP addresses (SSRF blocked).', $host));
        }

        return ['scheme' => $scheme, 'host' => $host, 'port' => $port, 'ip' => $admittedIp];
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

        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        $pinIp = str_contains($target['ip'], ':') ? '[' . $target['ip'] . ']' : $target['ip'];
        $collected = '';
        $overflow = false;
        $maxBytes = $this->maxResponseBytes;

        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $upperMethod,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RESOLVE => [sprintf('%s:%d:%s', $target['host'], $target['port'], $pinIp)],
            CURLOPT_FOLLOWLOCATION => false,
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

    public function isIpAdmitted(string $ip): bool
    {
        if (false === filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        if ($this->allowPrivateIps) {
            return true;
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

        $records = gethostbynamel($host);

        return is_array($records) ? $records : [];
    }
}
