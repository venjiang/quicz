<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
  <img alt="quicz" src="assets/logo-light.svg" width="200">
</picture>

# quicz

English | [简体中文](README_zh-CN.md)

A QUIC / HTTP/3 implementation in pure Zig.

> **Current state:** Transport + application layer production-ready (36 features, 1883 tests,
> three-implementation interop verified). Full HTTP/3, QPACK, WebTransport, and HTTP Datagrams.
> Public APIs may still evolve.

---

## Features

- **QUIC v1 & v2** (RFC 9000 / RFC 9369) — handshake, streams, flow control, connection migration, path validation, Retry, stateless reset, key update, version negotiation, DATAGRAM, multipath, ECN, PMTUD, GSO/GRO
- **TLS 1.3** (RFC 8446 / RFC 9001) — pure Zig, no C dependencies. ECDSA P-256, X25519, AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, 0-RTT, session resumption
- **Loss Detection & Congestion Control** (RFC 9002 / RFC 9438) — NewReno, CUBIC, packet pacing
   - **HTTP/3** (RFC 9114) — full connection management, SETTINGS, GOAWAY, stream state machine, QPACK static + dynamic table, production async runtime drivers
- **WebTransport** (draft-ietf-webtrans-http3) — full session management, uni/bidi framing, CLOSE capsule, datagrams
- **qlog** (draft-ietf-quic-qlog) — QUIC event logging
- **External interop** — verified against quic-go (Go), quiche (Rust), s2n-quic (Rust): handshake + transfer

## Using as a Library

Add to your `build.zig.zon`:

```bash
zig fetch --save git+https://github.com/venjiang/quicz
```

Then in your `build.zig`:

```zig
const quicz_dep = b.dependency("quicz", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("quicz", quicz_dep.module("quicz"));
```

### I/O runtime (async, `std.Io`)

`quicz.runtime` provides an event-driven server/client on Zig 0.16 `std.Io`
(threaded). The server spawns an independent handler task per connection
(std.http model); the client drives an async session.

```zig
const std = @import("std");
const quicz = @import("quicz");
const Server = quicz.runtime.server.Server;
const Client = quicz.runtime.client.Client;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Server: serve(handler) spawns a driving task + per-connection handlers.
    var server = try Server.init(allocator, io, .{
        .port = 4433,
        .alpn = &.{"hq-interop"},
        .cert_der = &cert_der,
        .private_key = &key,
    });
    defer server.deinit();
    try server.serve(&echoHandler); // fn(ServerConnection) std.Io.Cancelable!void

    // Client: connect, send, receive via async session.
    var client = try Client.init(allocator, io, .{
        .server_port = 4433,
        .server_name = "localhost",
        .alpn = &.{"hq-interop"},
    });
    defer client.deinit();
    const ok = try client.runEchoSession("hello");
}
```

Server handler signature: `fn (ServerConnection) std.Io.Cancelable!void`.
Per-connection `ServerConnection.acceptStream()` returns a `Stream` with
`receive(buf)` / `send(data, fin)`. See `examples/io_echo.zig` and
`examples/multi_conn_test.zig`.

### Low-level API (direct connection control)

For applications that need fine-grained control over packet processing,
TLS backend driving, or custom endpoint routing:

```zig
const quicz = @import("quicz");

// Packet-level connection state machine
var conn = try quicz.Connection.init(allocator, .client, .{
    .initial_max_data = 65_536,
    .initial_max_streams_bidi = 16,
});
defer conn.deinit();

// TLS 1.3 handshake state machine (pure Zig)
const tls13 = quicz.tls13;

// TLS-backed transport wrappers
const Tls13ClientEndpoint = quicz.Tls13ClientEndpoint;
const Tls13ServerTransport = quicz.Tls13ServerTransport;

// Endpoint routing, CID registry, timers
const EndpointConnectionLifecycle = quicz.EndpointConnectionLifecycle;

// Packet protection: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
const protection = quicz.protection;

// Congestion control: NewReno, CUBIC
const cubic = quicz.cubic;

// HTTP/3, QPACK, WebTransport
const h3 = quicz.h3;
const qpack = quicz.qpack;
const webtransport = quicz.webtransport;

// qlog event logging
const qlog = quicz.qlog;
```

The runtime interop server (`interop_runtime_server.zig`) and client
(`interop_runtime_client.zig`) demonstrate the production runtime API:
`Server.serve(handler)` for multi-connection echo, `Client.connect()` for
handshake and stream I/O. External echo clients (quiche/s2n-quic/quinn/quic-go)
connect to the runtime server for reverse-direction interop.

## Performance

Benchmark results (Apple M-series, macOS loopback, ReleaseFast):

| Metric | Result |
|---|---|
| Stream Upload (real handshake) | **~430-510 MB/s** |
| Echo Latency (1 KB RTT) | **P50=20μs, P99=93μs** |
| Multi-Stream (4x) | **~300-560 MB/s** |
| Loss Recovery (1% loss) | **~450 MB/s** (loopback) |
| Loss Recovery (5% loss) | **~300 MB/s** (loopback) |

Comparison with other QUIC implementations:

| Implementation | Language | Throughput | Latency P50 |
|---|---|---|---|
| msquic | C | 1.5-2.5 GB/s (Linux XDP) | ~5-15μs |
| **quicz** | **Zig** | **~0.5 GB/s (macOS)** | **~20μs** |
| s2n-quic | Rust | ~800 MB/s (Linux GSO) | ~20-40μs |
| quic-go | Go | 400-600 MB/s (Linux GSO) | ~50-100μs |
| quiche | Rust | 300-500 MB/s | ~30-80μs |

Run benchmarks: `zig build run-quic-bench`

Full details: [docs/en/benchmark.md](docs/en/benchmark.md)

## Building

Requires **Zig 0.16.0**.

```bash
zig build                                    # build library
zig build test --summary all                 # 1883 unit tests
zig build run-tls13-udp-loopback             # TLS 1.3 UDP loopback
zig build run-h3-loopback                    # HTTP/3 + QPACK dynamic over UDP
zig build run-h3-runtime-loopback            # HTTP/3 + QPACK on the std.Io runtime
zig build run-h3-server                      # HTTP/3 server on the std.Io runtime (curl-testable)
zig build run-interop-client-standalone      # interop self-test
zig fmt --check build.zig src examples       # format check
```

## Interop Testing

quicz passes a full bidirectional interop matrix (7/7) against four major
implementations. All tests use certificate-verified TLS 1.3. Certificates are
a proper CA (`testdata/quicz-echo-ca.pem`) + CA-signed leaf
(`testdata/cert.pem`), so strict webpki-based clients (s2n-quic, rustls/quinn)
accept the trust chain.

**HTTP/3 application-layer interop** is verified both directions against a real
third-party H3 stack (go quic-go `http3`), exercising the RFC 9204 QPACK
static table, the 4-bit literal-name prefix, and the dynamic-table control
flow over real sockets:

| Direction | Peer | Scenario |
|---|---|---|
| Forward (go http3 client → quicz server) | quic-go http3.Transport | GET /, GET /stream (65536 B), POST /echo |
| Reverse (quicz h3 client → go server) | quic-go http3.Server | GET /, GET /headers, POST /echo |

| Direction | Peer | Result |
|---|---|---|
| Forward (quicz client → server) | quic-go | echo_bytes=19, cert verified |
| Forward (quicz client → server) | quiche | echo_bytes=19, cert verified |
| Forward (quicz client → server) | s2n-quic | echo_bytes=19, cert verified |
| Reverse (client → quicz server) | quic-go | echo_streams=2, echo_bytes=10 |
| Reverse (client → quicz server) | quinn | echo_streams=2, echo_bytes=10 |
| Reverse (client → quicz server) | quiche | echo_streams=2, echo_bytes=10 |
| Reverse (client → quicz server) | s2n-quic | echo_streams=2, echo_bytes=10 |

```bash
# Start the quicz runtime server
zig build && zig-out/bin/quicz-interop-runtime-server 4433 cert.pem key.pem

# Forward: quicz client → external server
zig-out/bin/quicz-interop-runtime-client 127.0.0.1 4433 quicz-echo-ca.pem localhost

# Reverse matrix (external clients → quicz server), all four peers
examples/interop/run_reverse_interop.sh all 4433
```

## Security

[`THREAT_MODEL.md`](THREAT_MODEL.md) documents the trust boundary and the
defenses against in-scope attacks (amplification, packet injection, stateless
reset token guessing, version downgrade, hostile transport parameters, Retry
token forgery), each with code and test references.

## Project Structure

| Path | Description |
|---|---|
| `src/quic/api.zig` | **High-level API** — Endpoint / Connection / Stream |
| `src/runtime/` | I/O runtime - async server/client (`std.Io`) |
| `src/quic/connection.zig` | Connection state machine (11K lines) |
| `src/quic/endpoint.zig` | Endpoint routing, CID registry, ECN policy |
| `src/quic/endpoint_lifecycle.zig` | Connection lifecycle management |
| `src/quic/tls13_client_endpoint.zig` | Client endpoint (handshake + stream I/O) |
| `src/quic/tls13_server_endpoint.zig` | Server endpoint (multi-connection routing) |
| `src/quic/udp_event_loop.zig` | UDP socket I/O (IPv4 + IPv6 dual-stack) |
| `src/tls/tls13.zig` | Pure Zig TLS 1.3 (9.4K lines, 222 tests) |
| `src/tls/pq_kex.zig` | X25519Kyber768 hybrid KEM primitives (standalone; not yet wired into the TLS 1.3 handshake) |
| `src/tls/pem.zig` | PEM (RFC 7468) decoding + SEC1/PKCS#8 P-256 private key parsing |
| `src/quic/protection.zig` | Packet protection (AES-GCM, ChaCha20-Poly1305) |
| `src/quic/recovery.zig` | Loss detection and recovery (RFC 9002) |
| `src/quic/cubic.zig` | Congestion controller (NewReno + CUBIC) |
| `src/h3/` | HTTP/3, QPACK, WebTransport |
| `src/qlog/` | qlog event logging |
| `examples/` | Runnable examples and interop probes |
| `docs/en/` / `docs/zh-CN/` | Design docs and task matrix |

## Documentation

- [P2P Connectivity Spike](docs/en/p2p-connectivity-spike.md) — experimental iOS ABI, STUN codec, and adaptive path selection; not yet production NAT traversal.
- [Getting Started](docs/en/getting-started.md) — build H3 servers/clients, custom stream protocols, and advanced patterns.
- [API Layers](docs/en/api-layers.md) — high/low API map + comparison to s2n-quic / quic-go / quinn / quiche / msquic / quic-zig.
- [API Reference](docs/en/api-reference.md) — full signature reference for `runtime.*`, H3, and `Connection`.
- [Benchmark](docs/en/benchmark.md) / [Production Tuning](docs/en/production_tuning.md) — measured performance and deployment guidance.
- [Deployment](docs/en/deployment.md) — certificates, scaling, monitoring, and troubleshooting for production.
- [Network Benchmarking](docs/en/network-benchmark.md) — cross-host / lossy-path benchmarking with `tc netem`.
- [Architecture](docs/en/architecture.md) — internal design and module layout.

## License

MIT. See [LICENSE](LICENSE).
