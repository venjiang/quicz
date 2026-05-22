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
- [x] Minimal QUIC packet headers (long/short, including short-header spin-bit preservation), header-level packet number truncation/reconstruction, RFC 9000 long/short packet envelope parsing/serialization, packet number encoding selection/reconstruction, Retry packet codec, and RFC 8999 Version Negotiation packet parsing/serialization
- [x] RFC 9000 transport parameter typed codec with defaults, duplicate rejection, unknown-parameter ignore behavior, preferred_address support, and `QuicConnection` export/application helpers
- [x] RFC 9000 transport error code helpers, including fixed codes and CRYPTO_ERROR TLS alert mapping
- [x] RFC 9001 QUIC v1 Initial secret/key/IV/header-protection key derivation, AEAD_AES_128_GCM payload protection helpers, protected long-packet seal/open, Retry Integrity Tag verification, and AES header-protection mask application with Appendix A vectors
- [x] Basic frame model (STREAM/CRYPTO/PADDING/PING/ACK/ACK_ECN with ranges/RESET_STREAM/STOP_SENDING/MAX_*/BLOCKED/NEW_TOKEN/NEW_CONNECTION_ID/RETIRE_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/HANDSHAKE_DONE and CONNECTION_CLOSE subset)
- [x] Minimal in-memory connection and stream queue/receive flow with send-side PING plus STREAM and per-packet-number-space CRYPTO fragmentation, inbound CRYPTO buffering, out-of-order STREAM receive reassembly, local RESET_STREAM and STOP_SENDING emission, inbound RESET_STREAM and STOP_SENDING handling, PATH_CHALLENGE response queuing, outbound PATH_CHALLENGE tracking with PTO-based retry, failure counting, and matching PATH_RESPONSE validation, modeled server anti-amplification send limiting with explicit peer-address validation and Retry token consumption, peer-issued connection ID tracking with queued RETIRE_CONNECTION_ID, local NEW_CONNECTION_ID issuing with peer RETIRE handling, client-side NEW_TOKEN storage, HANDSHAKE_DONE receive validation and handshake confirmation, basic connection/stream/stream-count flow control with outbound BLOCKED reporting, receive-side MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS_BIDI/UNI refresh, peer BLOCKED observability and stale-limit MAX retransmission, strict stream direction validation, max_idle_timeout handling, and close-state handling
- [x] Simplified loss recovery and congestion-control state with automatic ACK generation, ACK range handling, unsent-packet ACK rejection, ACK-driven sent-packet tracking, ACK delay exponent / post-confirmation max_ack_delay handling, packet/time-threshold loss detection, deterministic loss-timeout hook, NewReno-style recovery period, persistent congestion response, and packet-number-space PTO PING hook
- [x] Experimental Initial/Handshake/Application packet number space model for frame-payload ACK/recovery isolation, RFC 9000 Initial/Handshake/0-RTT frame-type filtering, and modeled Initial/Handshake discard cleanup
- [x] Frame-payload ACK_ECN counter validation for modeled ECT(0)/ECT(1) sent packets
- [x] Stateless reset packet helper plus connection-level reset-token detection for peer-issued CIDs
- [ ] Full connection state machine and protected-packet packet number space routing
- [ ] Full RFC 9002 loss detection & congestion control with protected-packet loss/PTO timer scheduling, PTO recovery behavior, and remaining NewReno details
- [ ] TLS 1.3 integration for QUIC (RFC 9001)
- [ ] QUIC v2 (RFC 9369) version support

### Planned Milestones

1. **Minimal QUIC v1 subset**
   - Single-path, IPv4 only
   - Fixed QUIC v1 version (0x00000001)
   - Initial/Handshake/1-RTT packet support
   - Basic STREAM/ACK/PADDING/CONNECTION_CLOSE frames
2. **TLS 1.3 + full handshake**
   - TLS handshake integration over CRYPTO frames
   - Key derivation and packet protection
3. **Loss detection & congestion control**
   - RFC 9002-based algorithms (initially NewReno-style)
4. **QUIC v2 and advanced features**
   - QUIC v2 version (0x6b3343cf)
   - Path migration, richer path validation policy, stateless reset

For the verifiable transport implementation task plan, see
[`docs/en/quic_transport_tasks.md`](docs/en/quic_transport_tasks.md).
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
  - `zig-out/bin/quicz-codec-roundtrip`
  - `zig-out/bin/quicz-flow-control`
  - `zig-out/bin/quicz-uni-stream`
  - `zig-out/bin/quicz-stream-reset`
  - `zig-out/bin/quicz-stop-sending`
  - `zig-out/bin/quicz-crypto-stream`
  - `zig-out/bin/quicz-graceful-close`
  - `zig-out/bin/quicz-idle-timeout`
  - `zig-out/bin/quicz-packet-spaces`
  - `zig-out/bin/quicz-ecn-validation`
  - `zig-out/bin/quicz-loss-recovery`
  - `zig-out/bin/quicz-pto-recovery`
  - `zig-out/bin/quicz-path-validation`
  - `zig-out/bin/quicz-address-validation`
  - `zig-out/bin/quicz-retry-token`
  - `zig-out/bin/quicz-connection-ids`
  - `zig-out/bin/quicz-stateless-reset`
  - `zig-out/bin/quicz-initial-keys`

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
            .initial_max_streams_bidi = 64,
            .initial_max_streams_uni = 64,
        },
    );
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendCrypto("client-hello-bytes"[0..]);
    try conn.sendPing();
    try conn.sendOnStream(stream_id, "hello, quicz"[0..], true);

    // Current skeleton behavior:
    // - call conn.openStream() or conn.openUniStream() before sending on
    //   locally initiated bidirectional or unidirectional streams
    // - sendOnStream(...) accepts observed peer-initiated bidirectional streams
    //   for replies, but rejects unobserved peer streams, unopened local streams,
    //   and peer-initiated unidirectional stream IDs
    // - call conn.pollTx(...) to get unencrypted frame payload bytes;
    //   it may emit ACK-only, PING, CRYPTO, PATH_CHALLENGE, PATH_RESPONSE,
    //   MAX_DATA, MAX_STREAM_DATA, DATA_BLOCKED, STREAM_DATA_BLOCKED,
    //   STREAMS_BLOCKED, RESET_STREAM, STOP_SENDING, or STREAM payloads, and
    //   may coalesce a pending ACK when space allows
    // - feed peer payload bytes into conn.processDatagram(...), use
    //   conn.processDatagramInSpace(...) for explicit Initial/Handshake/
    //   Application packet number space ACK/recovery accounting, or use
    //   conn.processDatagramForPacketType(...) when 0-RTT/1-RTT frame-type
    //   validation must be distinguished inside Application packet space
    // - call conn.confirmHandshake() when an external TLS bridge confirms the
    //   handshake; client-side HANDSHAKE_DONE also marks the handshake confirmed
    // - use conn.sendCryptoInSpace(...), conn.pollTxInSpace(...), and
    //   conn.recvCryptoInSpace(...) to drive modeled Initial/Handshake CRYPTO
    //   byte streams for a future TLS bridge
    // - read default Application-space CRYPTO bytes via conn.recvCrypto(...)
    // - read application data via conn.recvOnStream(...); use
    //   recvStreamFinalSize(...) and recvStreamFinished(...) to observe FIN
    //   final size and completion after bytes are consumed; stream reads also
    //   refresh receive-side MAX_DATA and MAX_STREAM_DATA credit, and
    //   peer-initiated FIN completion refreshes MAX_STREAMS_BIDI/UNI credit
    // - call conn.resetStream(...) to abort an opened local send side or an
    //   observed peer-initiated bidirectional reply side
    // - call conn.stopSending(...) to ask the peer to stop sending on an opened
    //   local bidirectional stream or observed peer-initiated receive stream
    // sendCrypto(...) and sendOnStream(...) fragment larger writes to fit
    // max_datagram_size.
    // processDatagram(...) validates inbound bidirectional/unidirectional stream
    // counts, accepts peer-initiated unidirectional receive streams, rejects
    // unopened local bidirectional IDs and inbound local unidirectional IDs,
    // buffers out-of-order STREAM ranges until they become contiguous, and
    // rolls back partial state changes when a payload is invalid.
    // CRYPTO frames are received into contiguous per-packet-number-space
    // in-memory handshake buffers.
    // sendPing() queues an ack-eliciting PING frame. ACK, MAX_DATA,
    // MAX_STREAM_DATA, and MAX_STREAMS_BIDI/UNI frames update
    // in-memory recovery and flow-control state; packet-number-space helpers
    // keep Initial, Handshake, and Application ACK/recovery state isolated in
    // the frame-payload API and reject RFC 9000-forbidden Initial, Handshake,
    // and 0-RTT frame types; discardPacketNumberSpace() clears modeled Initial/Handshake
    // sent-packet, CRYPTO, ACK, loss, and PTO state after key discard;
    // ACKs can mark older unacknowledged packets lost
    // through packet/time-threshold loss detection; the recovery period
    // suppresses repeated loss reductions and ACK growth for packets sent
    // before recovery, while persistent congestion can reduce the congestion
    // window to the RFC 9002 minimum;
    // checkLossDetectionTimeouts() applies due time-threshold loss deadlines;
    // checkPtoTimeouts() queues packet-number-space PTO PING probes under a controlled clock; ACK_ECN uses the ACK
    // ranges for recovery and validates modeled ECT(0)/ECT(1) sent packets
    // against cumulative ECN counters per packet number space. RTT updates use
    // the peer ACK delay exponent and cap ACK delay by peer max_ack_delay after
    // handshake confirmation. MAX_STREAM_DATA
    // validates the stream state before updating send credit; inbound
    // PATH_CHALLENGE queues a matching PATH_RESPONSE; sendPathChallenge()
    // queues outbound PATH_CHALLENGE data, checkPathValidationTimeouts()
    // retries timed-out challenges up to a small retry budget, and
    // processDatagram() accepts only a matching PATH_RESPONSE; NEW_TOKEN is
    // accepted only by client connections
    // and stored for future address validation; HANDSHAKE_DONE is also
    // client-only; stopSending() queues STOP_SENDING for receive-capable streams;
    // server connections start with an unvalidated peer address; use
    // recordPeerAddressBytesReceived(...) to model received datagram bytes and
    // validatePeerAddress() once an external handshake/token/path check proves
    // address ownership. pollTx() and pollTxInSpace() then enforce the RFC 9000
    // 3x anti-amplification send budget until validation lifts it. Servers can
    // also model one-time Retry tokens with issueRetryToken(...) and
    // validateRetryToken(...), which consumes a matching token and validates
    // the peer address.
    // resetStream() and inbound STOP_SENDING close the matching send side and
    // queue RESET_STREAM; RESET_STREAM marks the receive side closed unless the
    // stream already finished with the same final size. NEW_CONNECTION_ID tracks
    // peer-issued connection IDs and retire_prior_to queues RETIRE_CONNECTION_ID;
    // issueConnectionId() queues local NEW_CONNECTION_ID frames and peer
    // RETIRE_CONNECTION_ID marks those local IDs retired.
    // detectStatelessReset(...) checks datagram tails against active peer
    // stateless reset tokens for future UDP packet handling.
    // localTransportParameters() exports configured local receive limits,
    // disable_active_migration, and a server stateless_reset_token, and
    // applyPeerTransportParameters() applies peer handshake limits to send-side
    // flow control, stream-count, ACK delay, outbound datagram sizing, and
    // peerActiveMigrationDisabled() / peerStatelessResetToken() observability.
    // DATA_BLOCKED, STREAM_DATA_BLOCKED, and STREAMS_BLOCKED_* are queued when
    // local sends are blocked by peer credit. recvOnStream() queues MAX_DATA
    // and MAX_STREAM_DATA as application reads free receive credit, and queues
    // MAX_STREAMS_BIDI/UNI when peer-initiated FIN streams are fully consumed. Inbound
    // BLOCKED frames update highest-observed peer blocked limits and requeue
    // current MAX_* frames when the peer reports an older receive limit. closeConnection() and
    // closeApplication() queue CONNECTION_CLOSE variants; pollTx() emits and
    // retransmits the close frame while the connection is closing. max_idle_timeout
    // is exported and applied through transport parameters; successful send/receive
    // activity refreshes idleTimeoutDeadlineMillis(), and checkIdleTimeouts()
    // closes active connections at the modeled idle deadline. connectionState()
    // exposes active/closing/draining/closed lifecycle state.
    // DCID routing is still outside this skeleton.
    // The connection layer can receive one protected Initial long packet through
    // processInitialProtectedDatagram(); protected transmit, coalescing, full UDP
    // packetization, TLS, and later encryption levels are still pending.
}
```

See [`examples/echo_server.zig`](examples/echo_server.zig),
[`examples/echo_client.zig`](examples/echo_client.zig),
[`examples/codec_roundtrip.zig`](examples/codec_roundtrip.zig),
[`examples/flow_control.zig`](examples/flow_control.zig),
[`examples/uni_stream.zig`](examples/uni_stream.zig),
[`examples/stream_reset.zig`](examples/stream_reset.zig),
[`examples/stop_sending.zig`](examples/stop_sending.zig),
[`examples/graceful_close.zig`](examples/graceful_close.zig),
[`examples/idle_timeout.zig`](examples/idle_timeout.zig),
[`examples/packet_spaces.zig`](examples/packet_spaces.zig),
[`examples/ecn_validation.zig`](examples/ecn_validation.zig),
[`examples/loss_recovery.zig`](examples/loss_recovery.zig),
[`examples/pto_recovery.zig`](examples/pto_recovery.zig),
[`examples/path_validation.zig`](examples/path_validation.zig),
[`examples/address_validation.zig`](examples/address_validation.zig),
[`examples/retry_token.zig`](examples/retry_token.zig),
[`examples/connection_ids.zig`](examples/connection_ids.zig),
[`examples/stateless_reset.zig`](examples/stateless_reset.zig), and
[`examples/initial_keys.zig`](examples/initial_keys.zig) for runnable
examples. They exercise the current frame-payload, codec, transport-parameter,
flow-control, unidirectional stream, stream-reset, STOP_SENDING, close-state,
idle-timeout,
packet-number-space discard and 0-RTT frame filtering, ECN-validation,
loss-recovery including ACK-delay, recovery-period, and persistent congestion handling,
PTO-recovery, path-validation, address-validation, Retry-token and integrity-tag,
connection-ID, stateless-reset, and Initial key/protected-packet/header-protection APIs
and are not yet interoperable QUIC-over-UDP programs.

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
