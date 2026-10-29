# Deployment Guide

This guide covers running quicz in production: the HTTP/3 server path, TLS
certificates, horizontal scaling, monitoring, known limits, and troubleshooting.
It assumes the library builds cleanly and the examples in
[getting-started.md](getting-started.md) run.

## 1. Runtime entry points

The production path is `runtime.Server` on `std.Io.Threaded`.

- **HTTP/3** — `server.serveH3(options, handleRequest)` runs the transport,
  endpoint, connection lifecycle, and H3/QPACK driver in one process. This is
  the recommended entry point for a service.
- **Custom streams** — `server.serve(handler)` gives per-connection access to
  bidirectional streams (`ServerConnection.acceptStream` + `Stream.receive/send`)
  for non-HTTP protocols.

```zig
var server = try Server.init(allocator, io, .{
    .port = 4433,
    .alpn = &.{"h3"},
    .cert_der = cert_der,
    .private_key = private_key,
    .bind_addr = .{0, 0, 0, 0}, // accept remote clients
    // .max_connections = 4096, // default; your expected peak + headroom
});
defer server.deinit();
try server.serveH3(.{}, handleRequest);
```

## 2. TLS certificates

- **Linux x86_64** — use an **RSA** certificate. Zig 0.16 `std.crypto` has a
  P-256/P-384/Ed25519 signature-verification codegen bug on x86_64, so ECDSA
  certificates fail verification there. RSA-PSS SHA256/384/512 with standard
  TLS 1.3 parameters (MGF1 = hash, salt = hash) verifies correctly.
- **aarch64 Linux and macOS** — ECDSA P-256 works fine.
- The certificate is a DER-encoded X.509 leaf; the private key is the raw
  P-256 scalar (32 bytes) for ECDSA. Generate with `openssl` and load the DER
  bytes (see the `examples/interop/testdata/` generator in
  `run_external_interop.sh`).

## 3. Ports and binding

- `Server.Config.bind_addr` defaults to `127.0.0.1`. Set `.{0,0,0,0}` to
  accept remote clients (cross-host deployments).
- QUIC is UDP. Open the UDP port in the firewall/load balancer; do not map it
  through a TCP reverse proxy.

## 4. Horizontal scaling

Each `Server` runs one drive task that processes all accepted connections
serially (the same single-threaded event-loop model as s2n-quic / quiche /
quic-zig). To scale aggregate throughput across cores, run **multiple Server
instances**:

- On distinct UDP ports, fronted by a load balancer that hashes the client
  connection ID (or source IP) to a fixed backend, **or**
- On the same port with `SO_REUSEPORT` (requires manual socket setup; Zig
  `std.Io.net.IpAddress.bind` does not set REUSEPORT today).

Load-balance by connection ID so a connection sticks to one backend (QUIC
connections must not migrate between backends without connection migration).

## 5. Monitoring

- `Server.metricsSnapshot()` aggregates per-connection stats across all live
  connections in one call: stream bytes sent/received, in-flight bytes, smoothed
  RTT/RTTVAR, congestion window, and cumulative packet loss / retransmissions
  (`Connection.connectionStats()` gives the same shape per connection). Expose
  it from a metrics endpoint and alert on loss rate or RTT spikes.
- The runtime logs connection accept/close and drive errors via `std.log`
  (`quicz_runtime` scope). `error.UnknownConnectionId` on a closing connection
  is benign retransmission to a reclaimed connection, not a fault.

## 6. Known limits

- **Outbound packet size** — `send_mtu` (default 1350, standard MTU) caps
  outbound QUIC packets while the receive path keeps an 8192-byte allowance.
  Do not raise it in production: jumbo datagrams are IP-fragmented on real
  networks and (on loopback) inflate RTT samples into a congestion/pacing
  feedback loop that can stall a connection. See production_tuning.md.
- **Linux x86_64 std.crypto bug** — use RSA certificates (see §2).
- **Long high-throughput loopback/container runs** — sustained transfer
  (> ~90 s) on a loopback or container network can progressively slow as socket
  queuing inflates RTT samples and the pacer follows. This is a platform
  characteristic of lossless high-throughput paths, not a logic bug; real
  networks (normal RTT) are unaffected. Short CI stability runs (60 s) stay below
  the affected range.

## 7. Troubleshooting

- **Handshake fails against a strict client**: verify the certificate chain is
  complete (CA + leaf, not a truncated DER) and the ALPN matches. quicz
  tolerates unsupported TLS key-share groups and early_data without PSK
  (RFC 8446 §4.2.8 / RFC 9001 §4.5), so those are not the cause.
- **Connection stalls after sustained transfer**: check per-connection RTT and
  loss via `connectionStats`; if RTT climbs on a loopback/container path, see
  §6 (platform characteristic). On a real network, raise `max_idle_timeout_ms`
  to match your keep-alive requirement.
- **Interop against a third-party H3 client fails**: quicz implements the RFC 9204
  QPACK static table and the 4-bit literal-name prefix; a wrong table or prefix
  was the cause of earlier interop failures and is covered by the CI
  HTTP/3-interop step.
- **`AddressInUse` in the interop matrix**: leftover server processes hold the
  UDP port; the CI script sweeps them between cases.

## 8. Validation before deploy

- `zig build test --summary all` — 1883 unit tests.
- `zig build run-stability-bench -- 60000` — sustained transfer, no errors/leaks.
- `zig build run-h3-runtime-loopback -Doptimize=fast` — real handshake +
  H3/QPACK round trips.
- CI (`.github/workflows/ci.yml`) runs unit tests, the cross-implementation
  interop matrix (quic-go / quiche / s2n-quic, forward + reverse), HTTP/3
  interop both directions against go quic-go, fuzz regression, and a stability
  guard.