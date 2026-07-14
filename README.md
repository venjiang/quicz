# quicz

English | [简体中文](README_zh-CN.md)

`quicz` is an experimental IETF QUIC transport implementation in
[Zig](https://ziglang.org/). It targets a usable QUIC v1 transport rather than
every optional QUIC extension.

## Status and scope

The current core includes pure-Zig TLS 1.3, QUIC packet protection, streams,
flow control, Retry, connection-ID routing, path validation, loss recovery,
and a NewReno baseline. Real UDP loopback, separate-process Zig, and
certificate-verified Go/Rust/quic-go interoperability probes cover the primary
handshake and FIN-terminated stream-echo path.

It is still experimental. Production endpoint capacity policy, broader
interoperability, and several RFC edge cases remain in progress. HTTP/3/QPACK,
QUIC DATAGRAM, full QUIC v2/compatible-version behavior, multipath, qlog,
PMTU, GSO/GRO, and advanced congestion controllers are outside the first
transport milestone.

The authoritative status and evidence are in the
[transport task matrix](docs/en/quic_transport_tasks.md).

## Quick start: use the library

Use Zig **0.16.0**. Add `quicz` to an application's `build.zig.zon` (a local
checkout is useful while the package is experimental):

```zig
.dependencies = .{
    .quicz = .{ .path = "../quicz" },
},
```

Then expose the dependency to the executable in `build.zig`:

```zig
const quicz_dep = b.dependency("quicz", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("quicz", quicz_dep.module("quicz"));
```

The smallest state-and-frame use looks like this:

```zig
const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    var connection = try quicz.Connection.init(std.heap.page_allocator, .client, .{
        .initial_max_data = 65_536,
        .initial_max_stream_data = 65_536,
        .initial_max_streams_bidi = 16,
    });
    defer connection.deinit();

    const stream_id = try connection.openStream();
    try connection.sendOnStream(stream_id, "hello", true);

    var frame_buffer: [1350]u8 = undefined;
    const frame_payload = (try connection.pollTx(0, &frame_buffer)) orelse
        return error.NoPendingFrame;
    _ = frame_payload;
}
```

`pollTx` returns pending QUIC frame payload for the connection state machine;
it is not a protected UDP datagram. For a TLS-owned, protected UDP transport
loop, start from [`tls13_udp_loopback.zig`](examples/tls13_udp_loopback.zig)
or the separate-process echo programs described below.

## Build and run

```sh
zig build
zig build test --summary all
zig build run-tls13-udp-loopback
zig build run-tls13-process-interop
```

The UDP loopback verifies the pure-Zig TLS handshake and stream path.
The process probe runs independent Zig client and server processes over
loopback UDP. See [the examples guide](examples/README.md) for a curated
catalogue, intent, and commands; `zig build --help` lists every build step.

## Go and Rust interoperability examples

Build the project, then start the local Zig echo server:

```sh
zig-out/bin/quicz-tls13-process-echo-server 127.0.0.1 4443 2 concurrent-retry
```

Run either independently implemented client with the local test CA:

```sh
(cd examples/interop/go_echo_client && go run . -addr 127.0.0.1:4443 -ca ../testdata/quicz-echo-ca.pem -server-name localhost)
(cd examples/interop/rust_echo_client && cargo run -- 127.0.0.1:4443 ../testdata/quicz-echo-ca.pem localhost)
```

Both clients keep certificate verification enabled and report success only
after the `hq-interop` stream echo and peer FIN. The included PEM is a local
test trust anchor, not a deployment credential. The full setup, including the
external Zig client, is in [the examples guide](examples/README.md).

## Development map

| Need | Start here |
| --- | --- |
| Public connection API | [`src/lib.zig`](src/lib.zig) |
| TLS 1.3 implementation | [`src/quic/tls13.zig`](src/quic/tls13.zig) |
| Endpoint routing and timers | [`src/quic/endpoint_lifecycle.zig`](src/quic/endpoint_lifecycle.zig) |
| Runnable probes | [`examples/`](examples/) |
| Protocol status and acceptance evidence | [`docs/en/quic_transport_tasks.md`](docs/en/quic_transport_tasks.md) |
| Architecture and terminology | [`docs/en/architecture.md`](docs/en/architecture.md) |

The API is evolving. `Connection` is the primary public handle; detailed
lifecycle helpers are intentionally documented in the architecture and task
matrix rather than enumerated here.

## License

MIT. See [LICENSE](LICENSE).
