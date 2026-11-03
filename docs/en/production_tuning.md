# Production Tuning Guide

Updated: 2026-11-03.

This document covers recommended configuration for deploying quicz in
production environments. Connection-level parameters are set via
`ConnectionConfig` (`src/quic/connection_config.zig`); runtime deployment
recommendations are in the [Runtime Deployment](#runtime-deployment) section
below.

## Quick Reference

| Parameter | Default | Recommended (production) | Notes |
| --- | --- | --- | --- |
| `pto_jitter_percentage` | 0 | 20–30 | Prevents synchronized PTO timeouts across many concurrent connections. Range 0–50. Default 0 matches upstream QUIC stacks; enable for servers with 100+ concurrent connections. |
| `congestion_algorithm` | `.new_reno` | `.cubic` | CUBIC (RFC 9438) with HyStart++ provides better throughput on high-BDP paths. |
| `initial_rtt_ns` | 333 ms | Per-environment | Data center: 1–5 ms; WAN: 50–100 ms. Lower values speed up initial window growth. |
| `max_ack_delay_ns` | 25 ms | 25 ms | RFC 9000 default; do not change unless peer negotiates differently. |

## PTO Jitter

PTO jitter adds ±percentage random variation to the base Probe Timeout before
exponential backoff. This decorrelates timeout storms when many connections
share a path (e.g., behind a NAT or load balancer).

- **0% (default):** Deterministic PTO. Suitable for single connections, tests,
  and environments where timeout synchronization is not a concern.
- **20–30% (recommended for servers):** Sufficient to break synchronization
  without meaningfully delaying loss recovery.
- **50% (maximum):** Aggressive jitter; may delay loss recovery on lossy paths.

The result is always clamped to the RFC 9002 kGranularity floor (1 ms).

### Example

```zig
var conn = try Connection.init(allocator, .server, .{
    .congestion_algorithm = .cubic,
    .pto_jitter_percentage = 25,
    .initial_rtt_ns = 5_000_000, // 5ms for data center
});
```

## Congestion Control

### CUBIC + HyStart++ (recommended)

CUBIC (RFC 9438) is the default congestion control in most production QUIC
stacks. quicz implements CUBIC with:

- **HyStart++ slow start:** Monitors RTT increases to exit slow start early,
  avoiding bandwidth overshoot. Uses Conservative Slow Start (CSS) with
  ÷4 growth for up to 5 rounds before full exit.
- **Fast retransmission:** Immediate retransmit on congestion event without
  waiting for PTO.
- **App-limited detection (RFC 8312 §5.8):** Excludes application-limited
  periods from CUBIC epoch calculation. Uses 3×MTU threshold to avoid
  false positives on loopback.
- **PTO jitter:** Optional randomized PTO to decorrelate timeout storms.

### NewReno

NewReno (RFC 9002) is the default algorithm. Simpler but less efficient on
high-bandwidth, high-latency paths. Suitable for low-throughput control
channels or environments where CUBIC tuning is not needed.

## Initial RTT

The `initial_rtt_ns` parameter sets the RTT estimate before any measurement.
RFC 9002 defaults to 333 ms. Tuning this for your environment speeds up
initial window growth:

| Environment | Recommended `initial_rtt_ns` |
| --- | --- |
| Data center (same rack) | 100_000–500_000 (0.1–0.5 ms) |
| Data center (cross-rack) | 1_000_000–5_000_000 (1–5 ms) |
| Metro / CDN edge | 10_000_000–30_000_000 (10–30 ms) |
| WAN / intercontinental | 50_000_000–150_000_000 (50–150 ms) |
| Unknown / public internet | 333_000_000 (333 ms, default) |

## Runtime Deployment

The `runtime.Server` / `runtime.Client` (`std.Io.Threaded`) handle packet
I/O, routing, and stream delivery automatically. A few deployment notes:

- **Send batching is automatic on Linux**: `drainOutgoing` collects drained
  datagrams into an `OutgoingMessage[]` and uses `socket.sendMany`, which the
  Threaded backend implements with `sendmmsg`. macOS has no `sendmmsg` and
  keeps per-datagram sends. No configuration needed.
- **Receive buffers are pooled**: the recv task takes a 16-entry buffer pool
  instead of allocating per datagram; the pool falls back to the allocator
  when exhausted. Automatic.
- **SO_RCVBUF is raised to 4 MB** on the server and client sockets so client
  bursts do not overflow the kernel receive buffer before the drive task
  drains; loss recovery still covers residual drops.
- **Idle timeout**: `max_idle_timeout_ms` (default 30 s in the runtime) closes
  connections that stop sending; tune it to your keep-alive requirements.
- **Concurrency model**: each `Server` runs one drive task that processes all
  accepted connections serially (single-threaded event loop, same as
  s2n-quic / quiche / quic-zig). Per-connection multi-stream concurrency is
  already exploited (multi-stream throughput exceeds single-stream). To scale
  aggregate multi-connection throughput across cores, run multiple `Server`
  instances on distinct ports or behind a load balancer.
- **Outbound packet size cap** (`send_mtu`, default 1350): the runtime caps
  outbound QUIC packets at standard MTU while keeping an 8192-byte receive
  allowance for the datagram pool / recv buffer. Sending jumbo datagrams (up
  to the receive allowance) inflates RTT samples on sustained transfers and
  drives a congestion/pacer feedback loop that stalls the connection until
  idle timeout (reproduced at 256 streams / 64 MB per connection). Loopback
  benchmarks that want larger packets can raise `send_mtu` in
  `runtime/client.zig` / `runtime/server.zig` (4096 is a safe middle ground,
  ~6x the MTU throughput on loopback; jumbo packets are IP-fragmented on
  real networks, so keep 1350 for production).
- **Bind address**: `Server.Config.bind_addr` defaults to `127.0.0.1`; set
  `.{0,0,0,0}` to accept remote clients.
- **Certificates on Linux x86_64**: use an RSA certificate (Zig 0.16 `std.crypto`
  has a P-256/P-384/Ed25519 signature-verification codegen bug on x86_64);
  aarch64 and macOS use ECDSA fine.

## Validate Runtime Shutdown

Stream EOF does not establish connection closure. `Client.close()` queues
an asynchronous close request. The server can still have earlier datagrams
to process after the client task finishes.

Server handlers can use `ServerConnection.waitClosed()` to wait for a peer
close or another terminal transport state. Handler completion and runtime
state reclamation are separate conditions.

Run `zig build run-multi-conn-test` to validate the complete example. It
requires all four handlers to finish and the runtime connection-state map
to become empty. Its ten-second watchdog starts after all client tasks
finish. Each connection retains its own idle and close deadlines.

In a controlled negative run, omitting the normal clients' close requests
left three active connections and only one completed handler. The example
returned `ReclamationTimedOut`. This verifies rejection of that negative
case. The watchdog alone does not guarantee when every connection expires.

The former fixed 300ms delay could report `ConnectionLeak` while the drive
task still processed datagrams before a queued close. The example now
checks completion. Runtime close, recovery and idle policies are unchanged.

## Related Documents

- [Feature Comparison](feature_comparison.md) — capability matrix vs other QUIC stacks
- [Benchmark](benchmark.md) — throughput and latency numbers
- [Architecture](architecture.md) — module layout and design decisions
