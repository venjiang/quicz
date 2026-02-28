# quicz

A QUIC implementation in [Zig](https://ziglang.org/) aiming to follow the IETF QUIC standard defined at <https://quicwg.org/>.

> Status: **experimental / WIP**.  
> Goal: eventually support a fully-functional QUIC transport (RFC 9000 family), starting from a minimal but correct subset.

## Features (planned roadmap)

- [ ] QUIC packet and header parsing/serialization
- [ ] Long header: Initial / Handshake / 0-RTT / Retry packets
- [ ] Short header 1-RTT packets
- [ ] Basic stream management (bi/uni-directional)
- [ ] Flow control
- [ ] Loss detection & recovery (RFC 9002)
- [ ] Congestion control (NewReno / Cubic)
- [ ] TLS 1.3 handshake integration (RFC 9001)
- [ ] Connection migration, stateless reset, PATH_CHALLENGE/RESPONSE
- [ ] HTTP/3 support (future)

See [`docs/spec.md`](docs/spec.md) for the implementation scope and mapping to the official QUIC documents.

## Build

You need a recent Zig version (0.13+ recommended).

```bash
zig build
```

This builds:

- Static library: `libquicz.a`
- Example binaries:
  - `zig-out/bin/quicz-echo-server`
  - `zig-out/bin/quicz-echo-client`

## Using quicz as a library

High-level API (subject to evolution):

```zig
const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var stdout = std.io.getStdOut().writer();

    var conn = try quicz.QuicConnection.init(
        gpa,
        .client,
        .{
            .max_datagram_size = 1350,
            .initial_rtt_ms = 333,
        },
    );
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello, quicz"[0..], true);

    // Typically you integrate quicz with your UDP socket event loop:
    // - call conn.pollTx(...) to get datagrams to send
    // - feed received datagrams into conn.processDatagram(...)
    // - read application data via conn.recvOnStream(...)
    _ = stdout;
}
```

See [`examples/echo_server.zig`](examples/echo_server.zig) and
[`examples/echo_client.zig`](examples/echo_client.zig) for a minimal echo example.

## Examples

### Start the echo server

```bash
zig build run-server
```

This starts a QUIC echo server listening on `0.0.0.0:4443`.

### Run the echo client

In another terminal:

```bash
zig build run-client
```

You should see something like:

```text
Opened stream 0
Got echo: hello from quicz client
```

(While the QUIC implementation is still evolving, these examples may behave more like a “QUIC-shaped” protocol than a fully compliant QUIC stack.)

## License

MIT
