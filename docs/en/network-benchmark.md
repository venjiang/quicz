# quicz Real-Network Benchmarking

Guidance for benchmarking quicz over a real network (cross-host, lossy,
congested) rather than the loopback measurements in `benchmark.md`. These
runs require two Linux hosts (one acting as traffic shaper) and are executed
outside this repo's local loopback environment.

## Tools

| Tool | Purpose |
|---|---|
| `examples/multi_client_bench.zig` (`run-multi-client-bench`) | N concurrent clients vs one server: handshake latency + aggregate throughput |
| `examples/quic_bench_hs.zig` (`run-quic-bench-hs`) | Real-handshake throughput + echo latency |
| `tc` / `netem` (Linux) | Emulate packet loss, delay, jitter, bandwidth |
| `iperf3` | Sanity-check raw TCP/UDP link capacity for fair comparison |

Build everything in ReleaseFast — the Debug build is a measurement artifact
(compiler codegen, not library logic):

```bash
zig build -Doptimize=fast
# or per target
zig build run-multi-client-bench -Doptimize=fast
```

## 1. Cross-host: client on host A, server on host B

The server listens on loopback by default. To accept remote clients, bind all
interfaces:

```zig
var server = try Server.init(allocator, io, .{
    .port = 4433,
    .alpn = &.{"hq-interop"},
    .cert_der = &certificate_der,
    .private_key = &server_private_key,
    .bind_addr = .{0, 0, 0, 0},   // listen on all interfaces
});
```

On **host B** (server):

```bash
zig build run-io-echo -Doptimize=fast   # or run-h3-server for H3
```

On **host A** (client), point `Client.Config.server_host` at B's IP and
`server_port` at 4433. Patch `examples/multi_client_bench.zig` or use a small
client that connects to the remote address:

```zig
var client = try Client.init(allocator, io, .{
    .server_host = .{ 10, 0, 0, 2 },   // host B
    .server_port = 4433,
    .server_name = "host-b",
    .alpn = &.{"hq-interop"},
});
```

> **Linux x86_64**: use an **RSA certificate** (Zig 0.16 `std.crypto` has a
> known codegen bug for P-256/P-384/Ed25519 signature verification on
> x86_64). An OpenSSL-generated RSA cert verifies correctly.

## 2. Docker cross-host validation (validated 2026-08-08)

Two quicz Linux containers on the same Docker bridge network act as separate
hosts (distinct network namespaces, real non-loopback packet path). Run the
benchmark split across them:

```bash
# host build: cross-compile the x86_64 binary (or compile inside the container)
zig build-exe -target x86_64-linux-musl --dep quicz \
    -Mroot=examples/multi_client_bench.zig -Mquicz=src/lib.zig \
    -Ofast -lc --name qmc-bench-x64

# two containers on one bridge network
docker run -d --name bench-server --network bridge --entrypoint sleep <quicz-linux-img> infinity
docker run -d --name bench-client --network bridge --entrypoint sleep <quicz-linux-img> infinity
docker cp qmc-bench-x64 bench-server:/root/ && docker cp qmc-bench-x64 bench-client:/root/

# server container (listens on 0.0.0.0); client container connects to server IP
docker exec -d bench-server /root/qmc-bench-x64 server
docker exec bench-client /root/qmc-bench-x64 client <bench-server-IP>
```

Validated result (2 containers, Linux x86_64, ReleaseFast, ECDSA cert):

```
multi-client bench: ok=8/8 avg_connect=320 ms  aggregate=1.1 Mbit/s (host=192.168.215.2)
```

8/8 concurrent cross-host handshakes + echo succeed. The low aggregate
reflects the container bridge network (small cwnd × the handshake RTT, plus
docker's software forwarding), not a quicz protocol defect. Note: the ECDSA
P-256 test certificate works on Linux x86_64 ReleaseFast for the runtime
handshake path.

## 3. Emulating loss / delay / congestion with netem

Validated in Docker containers (Linux x86_64, `--cap-add NET_ADMIN` +
`apt-get install iproute2`) by shaping the client egress:

```bash
# 1% loss: quicz recovers — 8/8 concurrent cross-host handshakes complete
tc qdisc add dev eth0 root netem loss 1%
/root/qmc-bench-x64 client 192.168.215.2
# ok=8/8 avg_connect=279ms aggregate=0.7 Mbit/s

# 5% loss + 20ms delay: the demo's 8 concurrent clients partially time out
# (no per-client handshake deadline in the benchmark), so some fail.
# Run a single client, or lower loss, for a cleaner high-loss recovery check.
tc qdisc add dev eth0 root netem loss 5% delay 20ms
```

`error.UnknownConnectionId` log lines under loss are server-side retransmissions
toward a reaped/unknown connection; the connection still completes. Recovery
(PTO retransmission) is exercised and works at 1% loss; the 5% case is bounded
by the benchmark's lack of a handshake timeout rather than a protocol defect.


On a Linux host, shape the network path between the two hosts. `netem` is a
`tc` qdisc on the egress interface:

```bash
# 10 ms one-way delay, 1% loss, 4 MB/s bandwidth
tc qdisc add dev eth0 root netem delay 10ms loss 1% rate 4mbit

# reset
tc qdisc del dev eth0 root
```

Apply the same rule on both hosts for symmetric shaping, or only on one for
an asymmetric path.

### Loss vs recovery

QUIC's loss recovery (PTO, congestion control) is the behavior under test.
Run the echo-latency benchmark at several loss rates and observe how P50/P99
grow and how throughput degrades:

```bash
for loss in 0 0.5 1 3 5; do
    tc qdisc add dev eth0 root netem loss "${loss}%"
    zig build run-quic-bench-hs -Doptimize=fast 2>&1 | tee /tmp/hs_loss${loss}.log
    tc qdisc del dev eth0 root
done
```

### Delay-bound RTT

With a fixed delay, the aggregate throughput is bounded by
`cwnd / RTT`. Raising `initial_max_data` / `initial_max_stream_data` (the
server/client transport params) and allowing the congestion window to grow is
what you tune here.

## 4. Multi-client concurrency (cross-host)

`multi_client_bench` already measures N concurrent handshakes + aggregate
throughput. Run it across hosts to include real RTT:

```bash
# host B: run the server portion (patch the example to bind 0.0.0.0)
# host A: 16 clients, real network
zig build run-multi-client-bench -Doptimize=fast
```

Expected output (ReleaseFast, loopback reference):

```
multi-client bench: ok=8/8 avg_connect=3 ms  aggregate=628.6 Mbit/s
```

Across a real network, `avg_connect` becomes RTT-bound (≈ 1.5× RTT for the
handshake) and aggregate throughput reflects the path's `cwnd/RTT` limits.

## 5. Recording results

Log each run with platform + commit metadata, mirroring the loopback suite's
`bench_results/<UTC timestamp>_<commit>.log` convention:

```bash
BENCH_DIR=bench_results/$(date -u +%Y%m%dT%H%M%SZ)_$(git rev-parse --short HEAD)
mkdir -p "$BENCH_DIR"
# capture: host specs, tc shape, quicz version, raw output
```

## 6. Checklist before trusting a number

1. Build `-Doptimize=fast` (never Debug).
2. Sanity-check the raw path with `iperf3`; quicz should land within a
   reasonable factor of the link's UDP/TCP ceiling per connection.
3. On Linux x86_64 use an RSA certificate.
4. Disable competing traffic; pin CPUs if comparing across runs.
5. Report loss/delay/RTT explicitly — "throughput" is meaningless without the
   path attributes.