# quicz

English | [简体中文](README_zh-CN.md)

A QUIC implementation in [Zig](https://ziglang.org/) aiming to follow the IETF QUIC standard defined at <https://quicwg.org/>.

> Status: **experimental / WIP**.  
> Goal: eventually support a fully-functional QUIC transport (RFC 9000 family and QUIC v2 RFC 9369), starting from a minimal but correct subset.

## Features and Roadmap

### Implemented / In Progress

- [x] Project skeleton with Zig build integration and in-memory example echo client/server
- [x] Basic API surface for `QuicConnection` (initial draft)
- [x] QUIC variable-length integer (varint) encode/decode helpers
- [x] Minimal QUIC packet headers (long/short) parsing and serialization
- [x] Basic frame model (STREAM/CRYPTO/PADDING/PING/ACK with ranges/RESET_STREAM/STOP_SENDING/MAX_* and CONNECTION_CLOSE subset)
- [x] Minimal in-memory connection and stream queue/receive flow with basic connection/stream flow control and close-state handling
- [x] Simplified loss recovery and congestion-control state with automatic ACK generation and ACK-driven sent-packet tracking
- [ ] Full connection state machine and distinct packet number spaces
- [ ] Full RFC 9002 loss detection & congestion control with loss timers and packet threshold loss detection
- [ ] TLS 1.3 integration for QUIC (RFC 9001)
- [ ] QUIC v2 (RFC 9369) version support

### Planned Milestones

1. **Minimal QUIC v1 subset**
   - Single-path, IPv4 only
   - Fixed QUIC v1 version (0x00000001)
   - Initial/Handshake/1-RTT packet support
   - Basic STREAM/ACK/PADDING/CONNECTION_CLOSE frames
2. **TLS 1.3 + full handshake**
   - Proper CRYPTO frames
   - Key derivation and packet protection
3. **Loss detection & congestion control**
   - RFC 9002-based algorithms (initially NewReno-style)
4. **QUIC v2 and advanced features**
   - QUIC v2 version (0x6b3343cf)
   - Path migration, PATH_CHALLENGE/RESPONSE, stateless reset

For more detailed design and per-feature notes, see the [`docs/en/`](docs/en/) directory.

## Build

You need Zig **0.16.0**. The build currently enforces this exact tested
version so Zig standard-library changes do not silently alter behavior.

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

    var conn = try quicz.QuicConnection.init(
        gpa,
        .client,
        .{
            .max_datagram_size = 1350,
            .initial_rtt_ms = 333,
            .initial_max_data = 65_536,
            .initial_max_stream_data = 65_536,
        },
    );
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello, quicz"[0..], true);

    // Current skeleton behavior:
    // - call conn.pollTx(...) to get unencrypted frame payload bytes;
    //   it may emit ACK-only payloads or coalesce a pending ACK with STREAM data
    // - feed peer payload bytes into conn.processDatagram(...)
    // - read application data via conn.recvOnStream(...)
    // ACK frames and MAX_DATA/MAX_STREAM_DATA frames update in-memory recovery
    // and flow-control state; packetization is still outside this API.
    // Full UDP packetization, TLS, and packet protection are still pending.
}
```

See [`examples/echo_server.zig`](examples/echo_server.zig) and
[`examples/echo_client.zig`](examples/echo_client.zig) for minimal in-memory
examples. They exercise the current frame-payload API and are not yet
interoperable QUIC-over-UDP programs.

## 中文说明（Chinese Overview）

本项目提供中英文两套文档：

- 英文：作为默认和权威说明，位于 `README.md` 与 `docs/en/` 目录
- 中文：作为镜像说明，位于 `README_zh-CN.md` 与 `docs/zh-CN/` 目录

`quicz` 是一个使用 Zig 实现的 QUIC 协议栈，目标对齐 IETF QUIC 标准：

- 主要参考：RFC 9000（QUIC v1 传输）、RFC 9001（QUIC + TLS 1.3）、RFC 9002（丢包检测与拥塞控制）、RFC 9369（QUIC v2）。
- 功能、特性与进度以英文文档为准，中文文档尽量保持同步、等价描述。

更多中文设计说明与开发日志，请查看 `docs/zh-CN/` 目录。

## License

MIT
