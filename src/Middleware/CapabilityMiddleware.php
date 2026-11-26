<?php

declare(strict_types=1);

namespace Kongono\Security\Middleware;

use Closure;
use Kongono\Core\Capabilities\EgressGuardableInterface;
use Kongono\Core\Capabilities\ExecutionCapabilities;
use Kongono\Core\Capabilities\QueryGuardableInterface;
use Kongono\Core\Container;
use Kongono\Security\Egress\SafeHttpClient;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Enforces least-privilege per-route capability sandboxes (`#[ReadOnlyDb]`, `#[NoOutboundHttp]`,
 * `#[MaxQueries]`, `#[MaxAiCost]`) at the database driver & outbound HTTP layers with deterministic
 * cleanup in `finally` (100% safe for FrankenPHP / RoadRunner persistent workers).
 */
final readonly class CapabilityMiddleware implements MiddlewareInterface
{
    public function __construct(
        private Container $container,
        private ExecutionCapabilities $capabilities,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $existing = $request->getAttribute(ExecutionCapabilities::class);
        $active = $existing instanceof ExecutionCapabilities
            ? $existing->merge($this->capabilities)
            : $this->capabilities->fresh();

        /** @var list<Closure(): void> $cleanups */
        $cleanups = [];

        try {
            // Attach scoped pre-execution DB SQL guard on every distinct guardable DB binding
            if ($active->readOnlyDb || null !== $active->maxQueries) {
                /** @var list<object> $guardedConnections */
                $guardedConnections = [];
                foreach ([
                    'Kongono\\Database\\ConnectionInterface',
                    'Kongono\\Database\\PdoConnection',
                    'Kongono\\Database\\ReadWriteConnection',
                    QueryGuardableInterface::class,
                ] as $id) {
                    if (!$this->container->hasBinding($id)) {
                        continue;
                    }
                    $conn = $this->container->get($id);
                    if ($conn instanceof QueryGuardableInterface && !in_array($conn, $guardedConnections, true)) {
                        $guardedConnections[] = $conn;
                        $cleanups[] = $conn->guardBeforeQuery(static function (string $sql) use ($active): void {
                            $active->assertDbQueryAllowed($sql);
                        });
                    }
                }
            }

            // Attach scoped pre-request egress guard when SafeHttpClient or EgressGuardableInterface is bound
            if ($active->noOutboundHttp) {
                /** @var list<object> $guardedClients */
                $guardedClients = [];
                foreach ([
                    SafeHttpClient::class,
                    EgressGuardableInterface::class,
                    'Kongono\\Ai\\Transport\\HttpTransportInterface',
                    'Kongono\\Ai\\Transport\\StreamingHttpTransportInterface',
                    'Kongono\\Ai\\Transport\\CurlTransport',
                ] as $id) {
                    if (!$this->container->hasBinding($id)) {
                        continue;
                    }
                    $client = $this->container->get($id);
                    if ($client instanceof EgressGuardableInterface && !in_array($client, $guardedClients, true)) {
                        $guardedClients[] = $client;
                        $cleanups[] = $client->guardBeforeRequest(static function (string $url) use ($active): void {
                            $active->assertOutboundHttpAllowed($url);
                        });
                    }
                }
            }

            return ExecutionCapabilities::withActive(
                $active,
                static fn(): ResponseInterface => $handler->handle($request->withAttribute(ExecutionCapabilities::class, $active)),
            );
        } finally {
            for ($i = count($cleanups) - 1; $i >= 0; --$i) {
                ($cleanups[$i])();
            }
        }
    }
}
