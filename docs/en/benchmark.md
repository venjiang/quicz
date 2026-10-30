# quicz Performance Benchmarks

## Methodology

secnetperf-style micro-benchmarks measuring raw QUIC transport performance over loopback UDP.

- **Protocol**: QUIC v1, installed 1-RTT keys (bypasses TLS handshake, transport-only)
- **Socket**: loopback UDP, 8900-byte datagrams (macOS UDP limit 9000B)
- **I/O layer**: std.Io.Threaded (cross-platform, Linux auto-enables sendmmsg batching)
- **Build**: `zig build-exe -Ofast`
- **Platform**: Apple M-series macOS (native) + aarch64 Linux (native container); benchmarks are cross-platform (the `nanoTime()` helper has a Linux `clock_gettime` branch, and all bench artifacts build on Linux). Loopback UDP, ReleaseFast.
- **Congestion control**: CUBIC (RFC 8312/9438)
- **Pacer**: Token bucket, ns precision (loopback srtt ~1μs, no truncation)
- **Variance**: loopback throughput swings ±20% run-to-run (system load, CUBIC window dynamics, thermal state); figures below are point measurements — **trends and orders of magnitude matter more than absolutes**. Where multiple runs were taken, a range is given.

## Running

```bash
# Standardized suite: builds every benchmark (ReleaseFast), runs all six
# in fixed order, records platform/commit metadata plus full output under
# bench_results/<UTC timestamp>_<commit>.log. Committed result files are
# the comparable baseline; re-run after changes and diff the results.
scripts/run_bench_suite.sh
zig build bench-suite        # same order, no result recording

# Individual benchmarks
zig build run-quic-bench             # installed-keys micro-benchmark
zig build run-quic-bench-hs          # real-handshake throughput + latency
zig build run-quic-bench-simple      # single-threaded raw processing
zig build run-quic-bench-datagram    # RFC 9221 DATAGRAM throughput
zig build run-quic-bench-profile     # per-phase profiling
zig build run-congestion-bench       # NewReno vs CUBIC simulated loss
```

## In-memory Benchmark (single-thread, ReleaseFast)

| Metric | Value | Notes |
|---|---|---|
| Stream upload (16 MB) | **0.35 GB/s** | No UDP overhead, CUBIC, cwnd=272 KB |
| Echo P50 | **7.5 μs** | 1 KB full QUIC round-trip (in-memory) |
| Echo P99 | **47.7 μs** | Tail varies with OS scheduling |
| Echo P99.9 | **665.2 μs** | |
| 4-stream aggregate (4×4 MB) | **0.34 GB/s** | Shared cwnd |

### CPU Utilization (real-handshake bench full suite, /usr/bin/time -l)

| Metric | Value |
|---|---|
| Real time | 3.90s |
| User CPU | 3.21s (~82% of one core) |
| Sys CPU | 4.25s (~109%, multi-core accumulated) |
| Peak RSS | ~2.4 GB (bench arena accumulated across iterations, not production per-connection) |

High sys CPU comes from per-packet UDP sendto/recvfrom syscalls; throughput is ACK-clock and shared-I/O-path limited (no scaling with concurrent connections), not pure CPU compute.

## Throughput (single stream, loopback, real handshake)

| Metric | Value | Notes |
|---|---|---|
| Single-stream throughput | **~310-440 MB/s** (3 runs: 313/318/440; ±20% run-to-run) | Real TLS 1.3 handshake, quic-go style 5-iter mean per run |
| Handshake time | ~0.6–1.0 ms/iter | TLS 1.3, transport parameters negotiated (RFC 9000 §7.4) |
| Transfer | 64 MB/iter | 8900 B datagram, CUBIC, 100μs receiveTimeout (64 MB lets CUBIC pass slow start into steady state, reducing variance) |

> Methodology (`examples/quic_bench_hs.zig`): each iteration creates a fresh connection and performs a real TLS 1.3 handshake (RFC 9000 §7 / RFC 9001 §4, same flow as `examples/interop_client.zig`), measures the end-to-end time to transfer 16 MB until the peer receives it all, and reports mean/stddev across iterations (quic-go `BenchmarkTransfer` model).
> The real handshake ensures transport parameters are negotiated correctly; the installed-keys bypass skips the handshake and thus that negotiation (RFC 9000 §7.4), so it is only used for point latency micro-benchmarks, not throughput.
> The transfer loop services the loss detection timer per RFC 9002 §6.2 (`serviceLossDetectionTimer`, PTO retransmission) to avoid stalling on delayed ACKs. Single-stream variance comes from CUBIC window dynamics on loopback (~1μs RTT); multi-stream aggregate is more stable.

## Echo Latency (1 KB round-trip, real handshake)

| Percentile | Latency |
|---|---|
| P50 | **21.7 μs** |
| P99 | **77.3 μs** |
| P99.9 | **175.9 μs** |

5000 iterations, 1 KB full QUIC round-trip after a real handshake (encrypt+send+receive+decrypt+echo).

## Multi-stream Throughput (4 concurrent streams, real handshake)

| Metric | Value | Notes |
|---|---|---|
| 4-stream aggregate | **~304 MB/s** (stddev 4.5%) | Real handshake, 64 MB, quic-go style 5 iterations |

## Loss Recovery (real handshake + simulated loss)

| Loss rate | Throughput | Notes |
|---|---|---|
| 1% (loopback) | 452 MB/s | CUBIC fast recovery |
| 5% (loopback) | 303 MB/s | |
| 1% (100μs RTT) | 126 MB/s | |
| 5% (100μs RTT) | 120 MB/s | |

> Echo/multi-stream/loss above are all measured with the real-handshake bench (`quic_bench_hs.zig`).

## Cross-platform Architecture

- **No custom Linux GSO layer**: Zig `std.Io.Threaded` already has `sendmmsg` batching on Linux (`Threaded.zig:1971`); the runtime `drainOutgoing` collects drained datagrams into an `OutgoingMessage[]` and calls `socket.sendMany`, so Linux sends each batch with one `sendmmsg` syscall. macOS has no `sendmmsg` (and std's batching path is slower there), so it keeps per-datagram sends.
- **std.Io defaults to io_uring on Linux** (`Io.zig:32`); Threaded is the explicitly chosen backend
- **Receive buffers pooled**: the runtime recv task takes a buffer from a 16-entry pool instead of allocating per datagram, and the drive task returns it by pointer — two allocator calls removed per datagram on the hot path.
- **nanoTime cross-platform**: comptime conditional, macOS `mach_absolute_time` / Linux `clock_gettime(MONOTONIC)`

### Linux numbers (native aarch64 container, ReleaseFast)

Containers share the host CPU and loopback goes through the Docker virtual
NIC, so these are **environment-bound ceilings, not quicz limits** — the
DATAGRAM bench (no flow control) also tops out near them:

| Metric | macOS (native) | aarch64 Linux container |
|---|---|---|
| Single-stream (real handshake) | **426–507 MB/s** | ~51 MB/s (docker veth UDP ~60 MB/s ceiling) |
| DATAGRAM | **199 MB/s** | ~64 MB/s |
| Echo latency P50 | 20.1 μs | 31.6 μs |

These numbers establish the container ceiling, not a statement about the
library's headroom on a dedicated host.

## Handshake & Connection Baselines (real handshake)

| Baseline | Value | Notes |
|---|---|---|
| Handshake latency | **P50 515.2 μs / P99 654.5 μs** | Full TLS 1.3 handshake, 200 iters |
| Handshake throughput | **~1253 conn/s** | New connection rate, 100 iters |
| Stream open rate | **~149M/s** | openStream on one connection, 100k iters |

> All measured with the real-handshake bench (`quic_bench_hs.zig`); handshake throughput is single-threaded serial.

## Connection Scaling Baseline (real handshake, multi-threaded)

| Baseline | Value | Notes |
|---|---|---|
| Concurrent aggregate (4 conns, thread-per-connection, per-connection std.Io) | ~285 MB/s | I/O partitioning |
| Concurrent aggregate (4 conns, **std.Io Group.concurrent async**, shared std.Io) | ~408 MB/s (1.43x thread-per-conn, same run) | Higher thread efficiency (fewer threads, same connections) |

> **Key finding (cf. msquic `docs/Execution.md`)**: msquic uses one worker thread per processor with connections partitioned across threads by RSS; each connection is single-threaded but distinct connections run in parallel. quicz measurements: (1) sharing a single std.Io serializes concurrent connections (no scaling); (2) per-connection std.Io (I/O partitioning) scales to ~1.2x; (3) **std.Io Group.concurrent async multiplexing is more thread-efficient than thread-per-connection (~1.43x in the same run)** — fewer threads run the same connections. But none of the three scales linearly, because throughput is limited by single-core packet-processing CPU (server capacity ~900 MB/s), not the I/O model; true linear scaling needs msquic-style multi-core parallel packet processing. quic-go (goroutine per connection) and quinn (tokio task per connection) follow the same principle. Absolute values vary with system load/temperature.

## Comparison with Other QUIC Implementations

### Test Condition Differences

Benchmark conditions vary significantly across implementations. Direct number comparisons require caution:

| Factor | Impact |
|---|---|
| GSO/GRO (Linux) | 3-10x throughput, batch syscalls |
| XDP (Linux kernel bypass) | 2-5x throughput, bypasses kernel network stack |
| loopback vs physical network | loopback has no loss/jitter, RTT ~1μs |
| single-thread vs multi-thread | multi-core scales linearly |
| Platform (macOS vs Linux) | macOS lacks GSO/XDP, higher syscall overhead |

### Single-Stream Throughput

> **Units and conditions**: most external figures below are goodput on KIT 2025's **10 Gbit/s physical testbed**, in **Mbit/s** (megabits); quicz reports **MB/s** (megabytes, 1 MB/s = 8 Mbit/s). Condition differences (physical link vs loopback, MTU, GSO, platform) are large — compare numbers with care.

| Implementation | Language | Goodput | Conditions | Source |
|---|---|---|---|---|
| ngtcp2 (C, fastest pairing) | C | **4172 Mbit/s (~521 MB/s)** | 10Gb physical testbed, ngtcp2×ngtcp2 | KIT 2025 |
| lsquic | C | ~2486 Mbit/s (~311 MB/s) | 10Gb physical testbed | KIT 2025 |
| quic-go | Go | 1220–2233 Mbit/s (~152–279 MB/s) | 10Gb physical testbed (pairing-dependent) | KIT 2025 |
| quiche | Rust | ~1220–1335 Mbit/s (~152–167 MB/s) | 10Gb physical testbed (pairing-dependent) | KIT 2025 |
| picoquic | C | ~1346–1451 Mbit/s (~168–181 MB/s) | 10Gb physical testbed | KIT 2025 |
| msquic | C | ~1 Gbps | macOS loopback | secnetperf |
| **quicz** | **Zig** | **~310-440 MB/s (~2480-3520 Mbit/s)** | **macOS loopback, real handshake, 8.9KB datagram, no GSO** | **This benchmark** |

**Key findings (all sourced)**:
- KIT 2025 measures 10Gb physical testbed goodput in the range **1220–4172 Mbit/s (~152–521 MB/s)**; **MTU 1500→9000 lets some implementations saturate 10 Gbit/s**.
- The KIT paper states explicitly: **throughput limitations stem primarily from single-core performance constraints** (consistent with quicz being constrained by the ACK clock / shared I/O path on a single core).
- quicz ~310-440 MB/s ≈ **2480-3520 Mbit/s**, within the KIT range; conditions differ (macOS loopback no-GSO vs 10Gb physical link), but the magnitude is comparable to mainstream implementations.
- quic-go #3670 user-measured ~1100 Mbit/s (~137 MB/s, Ubuntu two hosts, 10Gb physical link, not loopback).

## Echo Latency (small request round-trip)

| Implementation | Language | P50 | P99 | Conditions | Source |
|---|---|---|---|---|---|
| msquic | C | ~5-15 μs | ~30-50 μs | Linux, io_uring | secnetperf |
| s2n-quic | Rust | ~20-40 μs | ~80-150 μs | Linux, epoll | community bench |
| quic-go | Go | ~50-100 μs | ~200-500 μs | Linux | community bench |
| quiche | Rust | ~30-80 μs | ~100-200 μs | Linux, single-thread | community bench |
| quinn | Rust | ~50-100 μs | ~200-400 μs | Linux, tokio | ETH thesis |
| **quicz** | **Zig** | **21.7 μs** | **77.3 μs** | **macOS, loopback, std.Io, 100μs timeout** | **This benchmark** |

### Loss Recovery

| Implementation | 0% loss | 1% loss | 5% loss | Algorithm | Source |
|---|---|---|---|---|---|
| msquic | ~3 Gbps | ~70-80% retention | ~40-50% retention | CUBIC/BBR2 | ETH 2024 thesis |
| quic-go | ~1.1 Gbps | ~60-70% retention | ~30-40% retention | CUBIC | community bench |
| quinn | ~300-500 MB/s | msquic leads 50%+ | — | CUBIC | ETH 2024 thesis |
| **quicz** | **~310-440 MB/s** | **452 MB/s (1%)** | **303 MB/s (5%)** | **CUBIC** | **This benchmark (real handshake)** |

### Multi-Stream Scaling

| Implementation | 4-stream aggregate | Scalability | Source |
|---|---|---|---|
| msquic | ~2-4 Gbps | Near-linear (per-stream worker threads) | msquic dashboard |
| quic-go | ~600-900 MB/s | Good (per-stream goroutine) | community bench |
| s2n-quic | ~800 MB/s-1.2 GB/s | Good (async I/O) | TQUIC benchmark |
| quinn | single-core limited | Limited | KIT 2025 |
| **quicz** | **~304 MB/s** | **Shared cwnd (single cwnd per connection, RFC 9000)** | **This benchmark (real handshake)** |

### quicz Performance Bottleneck Analysis (measured)

The real-handshake bench (`quic_bench_hs.zig`) measures **~310-440 MB/s** single-stream on macOS loopback across runs (intra-run stddev up to 19.2%). The following are verified by measurement:

1. **Handshake is not a bottleneck**: a real TLS 1.3 handshake takes ~0.6–1.0 ms/iter, negligible vs the ~40 ms 16 MB transfer; transport parameters are negotiated correctly (RFC 9000 §7.4).
2. **Per-packet processing CPU is not the bottleneck**: AES-128-GCM measures 3.5–3.7 GB/s (ARM PMULL hardware accelerated), ~4.9 μs encrypt+decrypt per packet; server per-packet processing capacity is ~900 MB/s, above the measured ~313 MB/s (headroom). Throughput is limited by the ACK clock and the shared I/O path (no scaling even with multi-threaded concurrent connections).
3. **UDP syscalls are not dominant**: raw UDP loopback `sendto` measures ~3.5–4.7 μs/packet (3 runs: 3.48 / 3.61 / 4.67 μs).
4. **GSO/GRO platform difference**: Linux GSO batch sending yields 3–10x throughput; macOS has no equivalent (no `UDP_SEGMENT`/`sendmmsg`). This is a platform limitation, not a quicz defect. On Linux, `std.Io.Threaded` already provides `sendmmsg`.

### quicz Latency Advantage

quicz Echo P50=21.7 μs under loopback conditions is competitive with most implementations:
- Lower than s2n-quic ~20-40 μs (Linux epoll)
- Lower than quic-go ~50-100 μs
- Close to msquic ~5-15 μs (io_uring)

This benefits from pure Zig with no GC pauses, no runtime scheduling overhead, and ns-precision pacer.

## Notes

- Direct comparison is difficult due to different measurement methods, platforms, and configurations.
- quicz uses an in-memory connection model (no kernel bypass); loopback UDP overhead applies.
- Go/Rust implementations on Linux benefit from zero-copy sendmsg and GSO.
- quicz currently reaches ~310-440 MB/s single-stream on macOS loopback (real handshake, quic-go style multi-iteration; ±20% run-to-run, 8.9KB datagram, 100μs timeout).
- Throughput is limited by the ACK clock and the shared I/O path (server capacity ~900 MB/s with headroom; no scaling with concurrent connections); per-packet AES-128-GCM is hardware accelerated (~4.9 μs) and UDP syscalls are not the bottleneck.

## Planned Benchmarks

- [x] Multi-stream (4 streams, in-memory + UDP threaded)
- [x] Loss recovery (1%/5%, loopback + 100us RTT)
- [x] DATAGRAM throughput (RFC 9221, max_datagram_frame_size negotiated via real handshake): **141.79 MB/s** (1200B payload, loopback)
- [x] CPU utilization (/usr/bin/time -l, real-handshake bench full suite: ~49% user, ~65% sys of one core)
- [x] External interop (quic-go): handshake + cert verify + ALPN + 2-stream echo PASS
- [x] External interop (s2n-quic): handshake + cert verify + ALPN + 2-stream echo PASS
- [x] External interop (quiche): handshake + cert verify + ALPN + 2-stream echo PASS
- [x] Non-blocking receive (Duration(0) verified working)
- [x] Handshake latency (real TLS 1.3): P50 515.2 μs / P99 654.5 μs
- [x] Handshake throughput (new connection rate): ~1253 conn/s (single-threaded serial)
- [x] Stream open rate (stream churn): ~149M/s

## Known Limitations

Zig 0.16 `std.Io.Threaded` uses `poll(timeout_ms=0)` for non-blocking receive with `Duration(0)`.
Benchmark uses a 100μs `receiveTimeout`; `nanoTime()` is nanosecond-precision (macOS `mach_absolute_time` / Linux `clock_gettime(MONOTONIC)`).
Throughput is limited by the ACK clock and the shared I/O path (server per-packet processing capacity ~900 MB/s, with headroom; concurrent connections give no scaling); per-packet AES-128-GCM is hardware accelerated (~4.9 μs) and UDP `sendto` ~3.5–4.7 μs/packet, neither a bottleneck. ~313 MB/s is near the practical limit on macOS loopback; Linux gains batch sending via std.Io.Threaded sendmmsg.

## References

- [TQUIC Benchmark](https://tquic.net/docs/further_readings/benchmark/) — Tencent multi-condition QUIC benchmark
- [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) — Interop + pcap throughput
- [KIT Performance Landscape (2025)](https://doc.tm.kit.edu/2025-Examining-the-Heterogeneous-Throughput-Performance-Landscape-of-QUIC-Implementations-Koenig-et-al.pdf) — Academic multi-implementation comparison
- [secnetperf](https://github.com/microsoft/msquic/tree/main/src/perf) — Microsoft QUIC performance tool
