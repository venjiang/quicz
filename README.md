# quicz

English | [简体中文](README_zh-CN.md)

A QUIC implementation in [Zig](https://ziglang.org/) aiming to follow the IETF QUIC standard defined at <https://quicwg.org/>.

> Status: **experimental / WIP**.  
> Goal: eventually support a fully-functional QUIC transport (RFC 9000 family and QUIC v2 RFC 9369), starting from a minimal but correct subset.

## Features and Roadmap

### Implemented / In Progress

- [x] Buildable Zig package with `QuicConnection`, frame-payload examples, and runnable loopback examples.
- [x] Core codec coverage for varints, packet headers, packet numbers, frames, transport parameters, transport errors, Version Negotiation, Retry, stateless reset, and QUIC v2 packet/key/token primitives.
- [x] Experimental in-memory transport state for streams, CRYPTO byte streams, flow control, connection IDs, Retry/tokens, path validation, close/idle timers, packet number spaces, and rollback on invalid frame payloads.
- [x] Packet protection helpers for QUIC v1/v2 Initial keys, Retry integrity, protected long/short packets, configured v2 protected long-packet/Retry wire versions, installed-key mock TLS handoff, and key update state.
- [x] Simplified RFC 9002-style ACK, loss, PTO, NewReno congestion, ECN, retransmission, and endpoint recovery-timer models with socket-backed UDP loopback coverage.
- [x] In-memory endpoint routing/lifecycle helpers for DCID and IPv4 UDP tuple routing, Version Negotiation, zero-length CID routing, preferred/replacement CID routing, route retirement, stateless reset emission, and protected UDP loopbacks.
- [ ] Complete connection state machine and TLS-owned protected-packet packet number space routing.
- [ ] Full RFC 9002 loss detection and congestion control with socket-owned protected-packet loss/PTO lifecycle integration and remaining NewReno edge cases.
- [ ] TLS 1.3 integration for QUIC (RFC 9001)
- [ ] QUIC v2 (RFC 9369) version support

### Planned Milestones

1. **Minimal QUIC v1 subset**
   - Single-path, IPv4 only
   - Fixed QUIC v1 version (0x00000001)
   - Initial/Handshake/0-RTT/1-RTT packet support
   - Basic STREAM/ACK/PADDING/CONNECTION_CLOSE frames
2. **TLS 1.3 + full handshake**
   - TLS handshake integration over CRYPTO frames
   - Key derivation and packet protection
3. **Loss detection & congestion control**
   - RFC 9002-based algorithms (initially NewReno-style)
4. **QUIC v2 and advanced features**
   - QUIC v2 version (0x6b3343cf), with Initial key derivation, long-header type bits, configured protected long-packet and Retry version use, Retry integrity, token version separation, and RFC 9368 version information present; remaining v2 behavior pending
   - Path migration, richer path validation policy, stateless reset

For the verifiable transport implementation task plan, see
[`docs/en/quic_transport_tasks.md`](docs/en/quic_transport_tasks.md).
For more detailed design and per-feature notes, see the [`docs/en/`](docs/en/) directory.

## Quick Start

You need Zig **0.16.0**. The build currently enforces this exact tested
version so Zig standard-library changes do not silently alter behavior.

```bash
zig build
zig build test
zig build run-codec
zig build run-initial-keys
```

`zig build` builds the static library at `zig-out/lib/libquicz.a` and all
example binaries under `zig-out/bin/`. The examples are deterministic protocol
exercises, not interoperable QUIC-over-UDP programs yet.

## Build

```bash
zig build
zig build test --summary all
```

## Using quicz as a library

High-level API shape, subject to evolution:

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
            .initial_max_streams_bidi = 64,
            .initial_max_streams_uni = 64,
        },
    );
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendCrypto("client-hello-bytes"[0..]);
    try conn.sendPing();
    try conn.sendOnStream(stream_id, "hello, quicz"[0..], true);

    const tx = try conn.pollTx(0);
    defer if (tx) |bytes| gpa.free(bytes);
}
```

The current `pollTx()` / `processDatagram()` path moves unencrypted frame
payload bytes. Protected packet helpers, endpoint routing, recovery timers, and
mock TLS handoff are available for deterministic protocol tests; full TLS-owned
UDP packetization is still pending.

## Examples

| Example | What it demonstrates | Run | Source |
| --- | --- | --- | --- |
| Echo server | Minimal frame-payload echo server skeleton. | `zig build run-server` | [examples/echo_server.zig](examples/echo_server.zig) |
| Echo client | Minimal frame-payload echo client skeleton. | `zig build run-client` | [examples/echo_client.zig](examples/echo_client.zig) |
| Codec roundtrip | Varints, packet headers, version negotiation, frames, transport parameters, and error codecs. | `zig build run-codec` | [examples/codec_roundtrip.zig](examples/codec_roundtrip.zig) |
| Transport parameters | Transport-parameter export, parsing, application, and close-on-error behavior. | `zig build run-transport-parameters` | [examples/transport_parameters.zig](examples/transport_parameters.zig) |
| Flow control | Connection, stream, stream-count, and BLOCKED/MAX frame behavior. | `zig build run-flow-control` | [examples/flow_control.zig](examples/flow_control.zig) |
| Unidirectional streams | Local and peer unidirectional stream opening and validation. | `zig build run-uni-stream` | [examples/uni_stream.zig](examples/uni_stream.zig) |
| Stream reset | RESET_STREAM send/receive behavior and retransmission boundaries. | `zig build run-stream-reset` | [examples/stream_reset.zig](examples/stream_reset.zig) |
| STOP_SENDING | STOP_SENDING receive handling and RESET_STREAM response. | `zig build run-stop-sending` | [examples/stop_sending.zig](examples/stop_sending.zig) |
| CRYPTO streams | Per-space CRYPTO buffering, mock backend handoff, and protected CRYPTO flow. | `zig build run-crypto-stream` | [examples/crypto_stream.zig](examples/crypto_stream.zig) |
| Graceful close | Local/peer close, draining behavior, and close-triggered validation. | `zig build run-graceful-close` | [examples/graceful_close.zig](examples/graceful_close.zig) |
| Idle timeout | Modeled idle timeout export, refresh, and close behavior. | `zig build run-idle-timeout` | [examples/idle_timeout.zig](examples/idle_timeout.zig) |
| Packet spaces | Initial, Handshake, 0-RTT, and Application packet-number-space behavior. | `zig build run-packet-spaces` | [examples/packet_spaces.zig](examples/packet_spaces.zig) |
| ECN validation | ACK_ECN validation and CE-driven congestion response. | `zig build run-ecn-validation` | [examples/ecn_validation.zig](examples/ecn_validation.zig) |
| Loss recovery | ACK-driven loss, RTT sampling, NewReno, and persistent congestion. | `zig build run-loss-recovery` | [examples/loss_recovery.zig](examples/loss_recovery.zig) |
| PTO recovery | PTO timers, probe selection, backoff, and anti-amplification gating. | `zig build run-pto-recovery` | [examples/pto_recovery.zig](examples/pto_recovery.zig) |
| Endpoint recovery timers | Endpoint-owned recovery timer scheduling across connection handles. | `zig build run-endpoint-recovery-timers` | [examples/endpoint_recovery_timers.zig](examples/endpoint_recovery_timers.zig) |
| Path validation | PATH_CHALLENGE/PATH_RESPONSE retry and route update modeling. | `zig build run-path-validation` | [examples/path_validation.zig](examples/path_validation.zig) |
| Address validation | HMAC address-validation tokens, version binding, secret rotation, and replay snapshots. | `zig build run-address-validation` | [examples/address_validation.zig](examples/address_validation.zig) |
| Retry token | Retry datagram processing, token reuse, and Retry CID validation. | `zig build run-retry-token` | [examples/retry_token.zig](examples/retry_token.zig) |
| Connection IDs | NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, and route replacement state. | `zig build run-connection-ids` | [examples/connection_ids.zig](examples/connection_ids.zig) |
| Stateless reset | Reset token matching and inactive-CID reset construction. | `zig build run-stateless-reset` | [examples/stateless_reset.zig](examples/stateless_reset.zig) |
| Initial keys | QUIC v1/v2 Initial key derivation and configured v2 Initial packetization. | `zig build run-initial-keys` | [examples/initial_keys.zig](examples/initial_keys.zig) |
| Endpoint routing | In-memory DCID, tuple, Version Negotiation, Retry, and reset routing. | `zig build run-endpoint-routing` | [examples/endpoint_routing.zig](examples/endpoint_routing.zig) |
| UDP endpoint loopback | Socket-backed endpoint routing with Version Negotiation and Initial classification. | `zig build run-udp-endpoint-loopback` | [examples/udp_endpoint_loopback.zig](examples/udp_endpoint_loopback.zig) |
| UDP zero-CID loopback | Zero-length CID tuple routing over loopback UDP. | `zig build run-udp-zero-cid-loopback` | [examples/udp_zero_cid_loopback.zig](examples/udp_zero_cid_loopback.zig) |
| UDP preferred address loopback | Preferred-address route migration and active-migration-disabled handling. | `zig build run-udp-preferred-address-loopback` | [examples/udp_preferred_address_loopback.zig](examples/udp_preferred_address_loopback.zig) |
| UDP replacement CID loopback | Replacement CID registration, retire_prior_to handling, and reset-token retention. | `zig build run-udp-replacement-cid-loopback` | [examples/udp_replacement_cid_loopback.zig](examples/udp_replacement_cid_loopback.zig) |
| UDP connection IDs loopback | Protected NEW_CONNECTION_ID/RETIRE_CONNECTION_ID exchange through lifecycle routes. | `zig build run-udp-connection-ids-loopback` | [examples/udp_connection_ids_loopback.zig](examples/udp_connection_ids_loopback.zig) |
| UDP protected loopback | Caller-keyed protected Initial and 1-RTT routing over loopback UDP. | `zig build run-udp-protected-loopback` | [examples/udp_protected_loopback.zig](examples/udp_protected_loopback.zig) |
| UDP flow control loopback | Protected STREAM/BLOCKED/MAX flow-control exchange over loopback UDP. | `zig build run-udp-flow-control-loopback` | [examples/udp_flow_control_loopback.zig](examples/udp_flow_control_loopback.zig) |
| UDP spin bit loopback | Configurable single-path spin-bit signaling over protected short packets. | `zig build run-udp-spin-bit-loopback` | [examples/udp_spin_bit_loopback.zig](examples/udp_spin_bit_loopback.zig) |
| UDP ECN validation loopback | Modeled ECN state and ACK_ECN validation over loopback UDP. | `zig build run-udp-ecn-validation-loopback` | [examples/udp_ecn_validation_loopback.zig](examples/udp_ecn_validation_loopback.zig) |
| UDP loss recovery loopback | Protected ACK-driven packet loss and timer-driven cleanup over loopback UDP. | `zig build run-udp-loss-recovery-loopback` | [examples/udp_loss_recovery_loopback.zig](examples/udp_loss_recovery_loopback.zig) |
| UDP congestion recovery loopback | NewReno recovery-period and persistent-congestion behavior over loopback UDP. | `zig build run-udp-congestion-recovery-loopback` | [examples/udp_congestion_recovery_loopback.zig](examples/udp_congestion_recovery_loopback.zig) |
| UDP PTO recovery loopback | Endpoint lifecycle PTO probing and retransmission choices over loopback UDP. | `zig build run-udp-pto-recovery-loopback` | [examples/udp_pto_recovery_loopback.zig](examples/udp_pto_recovery_loopback.zig) |
| UDP STREAM retransmission loopback | ACK-loss-triggered STREAM retransmission through lifecycle routes. | `zig build run-udp-stream-retransmission-loopback` | [examples/udp_stream_retransmission_loopback.zig](examples/udp_stream_retransmission_loopback.zig) |
| UDP key update loopback | Installed-key key update, key phase advancement, and ACK gating. | `zig build run-udp-key-update-loopback` | [examples/udp_key_update_loopback.zig](examples/udp_key_update_loopback.zig) |
| UDP path validation loopback | PATH_CHALLENGE/PATH_RESPONSE route validation over a new peer port. | `zig build run-udp-path-validation-loopback` | [examples/udp_path_validation_loopback.zig](examples/udp_path_validation_loopback.zig) |
| UDP Retry loopback | Lifecycle-owned Retry delivery, token validation, and follow-up Initial routing. | `zig build run-udp-retry-loopback` | [examples/udp_retry_loopback.zig](examples/udp_retry_loopback.zig) |
| UDP close lifecycle loopback | Protected close delivery, route retirement, and stateless reset follow-up. | `zig build run-udp-close-lifecycle-loopback` | [examples/udp_close_lifecycle_loopback.zig](examples/udp_close_lifecycle_loopback.zig) |
| UDP stateless reset loopback | Socket-backed reset trigger delivery, reset emission, and client token match. | `zig build run-udp-stateless-reset-loopback` | [examples/udp_stateless_reset_loopback.zig](examples/udp_stateless_reset_loopback.zig) |

## Advanced Topics

- [Transport task matrix](docs/en/quic_transport_tasks.md): current RFC coverage, remaining work, and verification evidence.
- [Design notes](docs/en/spec.md): current architecture, protocol scope, and unsupported areas.
- Packet protection: QUIC v1/v2 Initial keys, Retry integrity, protected packet helpers, and key-update state.
- Endpoint lifecycle: DCID routing, route retirement, stateless reset lookup/emission, and endpoint recovery timers.
- Recovery and congestion: simplified RFC 9002 ACK/loss/PTO/NewReno/ECN model with deterministic tests.
- TLS status: mock `CryptoBackend` handoff is present; real TLS 1.3 transcript integration is still pending.

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
