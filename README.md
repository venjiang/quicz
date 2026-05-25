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
- [x] Minimal QUIC packet headers (long/short, including RFC 9369 QUIC v2 long-header packet type bits, short-header spin-bit preservation, and protected short-packet spin-bit peeking), header-level packet number truncation/reconstruction, RFC 9000 long/short packet envelope parsing/serialization, packet number encoding selection/reconstruction, Retry packet codec, RFC 8999 Version Negotiation packet parsing/serialization, and client-side Version Negotiation validation/selection state with RFC 9368 downgrade-check handoff
- [x] RFC 9000 transport parameter typed codec with defaults, duplicate rejection, unknown-parameter ignore behavior, preferred_address support, RFC 9368 `version_information`, `QuicConnection` export/application helpers including post-VN server Version Information downgrade validation, and TLS extension byte encode/apply helpers
- [x] RFC 9000/RFC 9368 transport error code helpers, including fixed codes, VERSION_NEGOTIATION_ERROR, and CRYPTO_ERROR TLS alert mapping
- [x] RFC 9001 QUIC v1 and RFC 9369 QUIC v2 Initial secret/key/IV/header-protection key derivation, RFC 9001 `quic ku` key-update derivation, caller-owned and connection-installed short-packet key-phase state and selection with ACK-gated installed-key update initiation, mock backend Handshake/0-RTT/1-RTT traffic-secret handoff, explicit installed-key 0-RTT accept/reject and discard cleanup, 0-RTT key discard at modeled 1-RTT boundaries, AEAD_AES_128_GCM payload protection helpers, protected long/short-packet seal/open, v1/v2 Retry Integrity Tag verification, and AES header-protection mask application with Appendix A vectors
- [x] Basic frame model (STREAM/CRYPTO/PADDING/PING/ACK/ACK_ECN with ranges/RESET_STREAM/STOP_SENDING/MAX_*/BLOCKED/NEW_TOKEN/NEW_CONNECTION_ID/RETIRE_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/HANDSHAKE_DONE and CONNECTION_CLOSE subset), including shortest frame-type varint validation and unknown frame-type rejection
- [x] Minimal in-memory connection and stream queue/receive flow with send-side PING plus STREAM and per-packet-number-space CRYPTO fragmentation, protected Initial/Handshake CRYPTO/ACK/PING with first-client-Initial DCID length, server-Initial token validation, and RFC 9000 Initial UDP datagram 1200-byte expansion/discard checks, caller-keyed/installed-key 0-RTT STREAM/RESET_STREAM/STOP_SENDING long-packet bridging, installed-key protected Handshake long-packet CRYPTO/ACK/PING bridging, caller-keyed and connection-installed protected 1-RTT short-packet PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit and receive bridging with key-phase state helpers and configurable single-path spin-bit signaling, inbound out-of-order CRYPTO buffering with idempotent duplicate retransmission discard, pluggable `CryptoBackend` driving for per-space CRYPTO delivery/output queuing, transport-parameter byte handoff, mock Handshake/0-RTT/1-RTT traffic-secret handoff, and modeled handshake confirmation, out-of-order STREAM receive reassembly with idempotent duplicate retransmission discard, local RESET_STREAM and STOP_SENDING emission, inbound RESET_STREAM and STOP_SENDING handling, PATH_CHALLENGE response queuing, outbound PATH_CHALLENGE tracking with PTO-based retry, failure counting, matching PATH_RESPONSE validation, and endpoint route update after protected PATH_RESPONSE validation, modeled server anti-amplification send limiting with explicit peer-address validation, HMAC-SHA256 address-bound expiring address-validation tokens with originating-version and endpoint peer-address binding plus in-memory `AddressValidationPolicy` secret/replay snapshot export/restore and replay rejection, Retry token consumption, server-side Retry datagram issuance, client-side Retry datagram processing, and handshake CID transport-parameter validation/export, peer-issued connection ID tracking with queued RETIRE_CONNECTION_ID and stateless-reset-token uniqueness checks, local NEW_CONNECTION_ID issuing with peer RETIRE handling and stateless-reset-token uniqueness checks, server-side HANDSHAKE_DONE and NEW_TOKEN issuing, client-side NEW_TOKEN storage, HANDSHAKE_DONE receive validation, explicit handshake progress observability, handshake confirmation, RFC 9001 Initial discard after client Handshake send/server Handshake receive, and Handshake-space discard after valid client-side HANDSHAKE_DONE, server-side sendHandshakeDone, or backend-confirmed no-output Handshake drive, basic connection/stream/stream-count flow control with outbound BLOCKED reporting, receive-side MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS_BIDI/UNI refresh with optional target receive data and stream-count windows, peer BLOCKED observability with receive-side STREAM_DATA_BLOCKED state creation/validation, stale-limit MAX retransmission, configured receive-window growth, and stream-count-window growth, strict stream direction validation, max_idle_timeout handling, and close-state handling
- [x] Simplified loss recovery and congestion-control state with automatic ACK generation, ACK range handling, unsent-packet ACK rejection, ACK-driven sent-packet tracking, ACK delay exponent / post-confirmation max_ack_delay handling, packet/time-threshold loss detection, deterministic loss-timeout hook, NewReno-style recovery period, persistent congestion response, and packet-number-space PTO hook that prefers queued ack-eliciting data before PING probes
- [x] Experimental Initial/Handshake/Application packet number space model for frame-payload ACK/recovery isolation, RFC 9000 Initial/Handshake/0-RTT frame-type filtering, modeled RFC 9001 Initial discard, and Initial/Handshake discard cleanup
- [x] Frame-payload ACK_ECN counter validation for modeled ECT(0)/ECT(1) sent packets plus in-memory endpoint ECN state scoped by UDP path identity
- [x] Stateless reset packet helper with constant-time token matching plus connection-level reset-token detection and uniqueness checks for peer-issued CIDs
- [x] In-memory endpoint DCID/IPv4 UDP tuple router for long-header DCID peeking, unsupported-version RFC 8999 Version Negotiation response generation, client Initial Source CID route registration, supported-version unknown-DCID Initial accept classification, accepted Initial Original DCID/server Initial SCID route registration, short-header registered-CID matching, zero-length CID tuple routing, Retry Source CID route switching, caller-validated preferred-address migration commit, sequence/retire-prior-to route retirement, endpoint replacement-CID registration, stateless-reset-token uniqueness enforcement, caller-validated path updates, active-migration-disabled rejection, inactive-CID stateless reset token lookup, reset datagram construction, and route/version-negotiation/reset/drop/accept receive classification
- [ ] Full connection state machine and protected-packet packet number space routing
- [ ] Full RFC 9002 loss detection & congestion control with protected-packet loss/PTO timer scheduling, PTO recovery behavior, and remaining NewReno details
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
   - QUIC v2 version (0x6b3343cf), with Initial key derivation, long-header type bits, Retry integrity, token version separation, and RFC 9368 version information present; remaining v2 behavior pending
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
  - `zig-out/bin/quicz-endpoint-routing`

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
    //   STREAMS_BLOCKED, HANDSHAKE_DONE, NEW_TOKEN, RESET_STREAM,
    //   STOP_SENDING, or STREAM payloads, and may coalesce a pending ACK when
    //   space allows
    // - feed peer payload bytes into conn.processDatagram(...), use
    //   conn.processDatagramInSpace(...) for explicit Initial/Handshake/
    //   Application packet number space ACK/recovery accounting, or use
    //   conn.processDatagramForPacketType(...) when 0-RTT/1-RTT frame-type
    //   validation must be distinguished inside Application packet space
    // - drive a pluggable TLS/crypto backend with
    //   conn.driveCryptoBackendInSpace(...); the backend can receive local
    //   transport-parameter extension bytes, return peer transport-parameter
    //   bytes for validation/application, receive contiguous per-space CRYPTO
    //   bytes, return Handshake/0-RTT/1-RTT traffic secrets for installed-key
    //   packet helpers, queue outbound CRYPTO through the connection, and report
    //   handshake completion. If a Handshake-space backend drive confirms the
    //   handshake without queuing outbound CRYPTO, it discards Handshake
    //   packet-number-space state plus installed Handshake keys. Direct
    //   conn.confirmHandshake() remains available for explicit tests; server
    //   sendHandshakeDone() marks the handshake confirmed, discards the same
    //   Handshake state, and queues HANDSHAKE_DONE; client-side HANDSHAKE_DONE
    //   also marks the handshake confirmed after a valid payload and discards
    //   the same Handshake state, and conn.handshakeState() exposes
    //   Initial/Handshake/Confirmed progress
    // - use conn.sendCryptoInSpace(...), conn.pollTxInSpace(...), and
    //   conn.recvCryptoInSpace(...) directly when a test needs lower-level
    //   Initial/Handshake CRYPTO byte-stream control
    // - read default Application-space CRYPTO bytes via conn.recvCrypto(...);
    //   inbound CRYPTO can arrive out of order and identical retransmissions are
    //   ignored once bytes are already buffered
    // - read application data via conn.recvOnStream(...); use
    //   recvStreamFinalSize(...) and recvStreamFinished(...) to observe FIN
    //   final size and completion after bytes are consumed; inbound frames
    //   that open a higher-numbered receive stream also create lower-numbered
    //   streams of the same type; stream reads refresh receive-side MAX_DATA
    //   and MAX_STREAM_DATA credit, and
    //   peer-initiated FIN completion refreshes MAX_STREAMS_BIDI/UNI credit;
    //   after final size is known, STREAM_DATA_BLOCKED no longer refreshes
    //   MAX_STREAM_DATA for that stream
    // - call conn.resetStream(...) to abort an opened local send side or an
    //   observed peer-initiated bidirectional reply side; after inbound
    //   RESET_STREAM, later STREAM data within the known final size is ignored
    // - call conn.stopSending(...) to ask the peer to stop sending on an opened
    //   local bidirectional stream or observed peer-initiated receive stream;
    //   once final data has arrived, stopSending(...) reports StreamClosed
    // sendCrypto(...) and sendOnStream(...) fragment larger writes to fit
    // max_datagram_size.
    // processDatagram(...) validates inbound bidirectional/unidirectional stream
    // counts, accepts peer-initiated unidirectional receive streams, rejects
    // unopened local bidirectional IDs and inbound local unidirectional IDs,
    // buffers out-of-order STREAM ranges until they become contiguous, discards
    // identical duplicate STREAM retransmissions without growing flow control, and
    // rolls back partial state changes when a payload is invalid.
    // CRYPTO frames are received into contiguous per-packet-number-space
    // in-memory handshake buffers.
    // sendPing() queues an ack-eliciting PING frame. ACK, MAX_DATA,
    // MAX_STREAM_DATA, and MAX_STREAMS_BIDI/UNI frames update
    // in-memory recovery and flow-control state; packet-number-space helpers
    // keep Initial, Handshake, and Application ACK/recovery state isolated in
    // the frame-payload API and reject RFC 9000-forbidden Initial, Handshake,
    // and 0-RTT frame types; successful client Handshake packet sends and
    // server Handshake packet receives discard Initial state, and
    // discardPacketNumberSpace() clears modeled Initial/Handshake sent-packet,
    // CRYPTO, ACK, loss, PTO state, and installed Handshake keys after key
    // discard; discardZeroRttProtectionKeys() clears installed early-data keys,
    // and modeled 1-RTT boundaries now clear client 0-RTT keys on 1-RTT key
    // installation plus server 0-RTT keys after an accepted 1-RTT short packet;
    // ACKs can mark older unacknowledged packets lost
    // through packet/time-threshold loss detection; the recovery period
    // suppresses repeated loss reductions and ACK growth for packets sent
    // before recovery, while persistent congestion can reduce the congestion
    // window to the RFC 9002 minimum;
    // checkLossDetectionTimeouts() applies due time-threshold loss deadlines;
    // checkPtoTimeouts() prefers queued ack-eliciting data as PTO probes, otherwise queues packet-number-space PTO PING probes under a controlled clock; ACK_ECN uses the ACK
    // ranges for recovery and validates modeled ECT(0)/ECT(1) sent packets
    // against cumulative ECN counters per packet number space. RTT updates use
    // the peer ACK delay exponent and cap ACK delay by peer max_ack_delay after
    // handshake confirmation. MAX_STREAM_DATA
    // validates the stream state before updating send credit; inbound
    // PATH_CHALLENGE queues a matching PATH_RESPONSE; sendPathChallenge()
    // queues outbound PATH_CHALLENGE data, checkPathValidationTimeouts()
    // retries timed-out challenges up to a small retry budget, and
    // processDatagram() accepts only a matching PATH_RESPONSE; issueNewToken()
    // queues server-issued NEW_TOKEN values, which client connections receive
    // and store for future address validation; issueAddressValidationToken()
    // can create HMAC-SHA256 address-bound, originating-version-bound,
    // expiring Retry or NEW_TOKEN values;
    // endpoint.Udp4Tuple.peerAddressValidationBinding() provides the stable
    // remote IPv4/UDP binding to use as the token peer address;
    // endpoint.AddressValidationPolicy owns the in-memory active/previous
    // token secrets and replay filter for versioned issue/validate/replay rejection,
    // and can export/restore both its secret set and replay-filter snapshot
    // for external persistence or worker distribution.
    // HANDSHAKE_DONE is client-only on receive; stopSending() queues STOP_SENDING for receive-capable streams;
    // server connections start with an unvalidated peer address; use
    // recordPeerAddressBytesReceived(...) to model received datagram bytes and
    // validatePeerAddress() once an external handshake/token/path check proves
    // address ownership. pollTx() and pollTxInSpace() then enforce the RFC 9000
    // 3x anti-amplification send budget until validation lifts it. Servers can
    // also model Retry datagrams with issueRetryDatagram(...), one-time Retry
    // tokens with issueRetryToken(...) and validateRetryToken(...), or authenticated
    // address tokens with validateAddressValidationToken(...) or
    // validateAddressValidationTokenWithSecrets(...), which validates
    // the originating version and bound peer address, then consumes Retry tokens once. Clients can process a Retry datagram with
    // processRetryDatagram(...); the accepted latestRetryToken() is reused by
    // protected Initial packetization when no explicit Initial token is passed.
    // applyPeerTransportParameters(...) validates the server's
    // original_destination_connection_id and retry_source_connection_id against
    // originalDestinationConnectionId() and retrySourceConnectionId(), and
    // validates initial_source_connection_id against peerInitialSourceConnectionId().
    // localTransportParameters() exports initial_source_connection_id after this
    // endpoint sends its first protected Initial packet, and server connections
    // export original_destination_connection_id after opening the first client Initial.
    // resetStream() and inbound STOP_SENDING close the matching send side and
    // queue RESET_STREAM; on peer-initiated bidirectional streams, inbound
    // STOP_SENDING can open receive state before any STREAM data while leaving
    // that receive side open. RESET_STREAM marks the receive side closed unless
    // the stream already finished with the same final size. NEW_CONNECTION_ID tracks
    // peer-issued connection IDs and retire_prior_to queues RETIRE_CONNECTION_ID;
    // issueConnectionId() queues local NEW_CONNECTION_ID frames and peer
    // RETIRE_CONNECTION_ID marks those local IDs retired.
    // detectStatelessReset(...) checks datagram tails against active peer
    // stateless reset tokens for future UDP packet handling.
    // localTransportParameters() exports configured local receive limits,
    // ACK delay exponent/max_ack_delay, disable_active_migration, server
    // stateless_reset_token, and server preferred_address when configured, and
    // applyPeerTransportParameters() applies peer handshake limits to send-side
    // flow control, stream-count, ACK delay, outbound datagram sizing, and
    // peerActiveMigrationDisabled(), peerStatelessResetToken(), and
    // peerPreferredAddress() observability. encodeLocalTransportParameters()
    // and applyPeerTransportParameterBytes() expose the same data as TLS QUIC
    // extension bytes for future backend integration.
    // DATA_BLOCKED, STREAM_DATA_BLOCKED, and STREAMS_BLOCKED_* are queued when
    // local sends are blocked by peer credit. recvOnStream() queues MAX_DATA
    // and MAX_STREAM_DATA as application reads free receive credit, optionally
    // using configured target receive windows, and queues
    // MAX_STREAMS_BIDI/UNI when peer-initiated FIN streams are fully consumed. Inbound
    // BLOCKED frames update highest-observed peer blocked limits, validate
    // STREAM_DATA_BLOCKED receive-side stream IDs, create receive state before
    // STREAM data when valid, requeue current MAX_* frames when the peer reports
    // an older receive limit, and can grow MAX_DATA/MAX_STREAM_DATA from
    // configured receive windows when the peer reports the current receive limit;
    // receive_stream_count_window can similarly grow MAX_STREAMS_BIDI/UNI.
    // MAX_STREAM_DATA can open peer-initiated bidirectional send/receive state
    // before any STREAM data so replies can use the advertised credit, and is
    // ignored once the matching send side has sent FIN.
    // Queued STREAM_DATA_BLOCKED is suppressed before transmit if the send side
    // later finishes or resets.
    // closeConnection() and
    // closeApplication() queue CONNECTION_CLOSE variants; pollTx() emits and
    // retransmits the close frame while the connection is closing. peerClose()
    // exposes accepted peer close diagnostics while draining. max_idle_timeout
    // is exported and applied through transport parameters; successful send/receive
    // activity refreshes idleTimeoutDeadlineMillis(), and checkIdleTimeouts()
    // closes active connections at the modeled idle deadline. connectionState()
    // exposes active/closing/draining/closed lifecycle state.
    // DCID routing is still outside this skeleton.
    // The connection layer can send and receive Initial/Handshake CRYPTO through
    // protected long packets with pollProtectedLongCryptoDatagramInSpace() and
    // processProtectedLongDatagramInSpace(); pollProtectedLongDatagram() and
    // processProtectedLongDatagram() can coalesce and route protected
    // Initial/Handshake CRYPTO, ACK-only, PING packets, and caller-keyed or
    // installed-key 0-RTT STREAM/RESET_STREAM/STOP_SENDING packets; the
    // standalone 0-RTT helpers also have installed-key variants, while
    // pollProtectedHandshakeDatagramWithInstalledKeys() /
    // processProtectedHandshakeDatagramWithInstalledKeys() use
    // CryptoBackend-installed Handshake keys for Handshake CRYPTO/ACK/PING, and
    // pollProtectedShortDatagram() / processProtectedShortDatagram() and
    // pollProtectedShortDatagramWithInstalledKeys() /
    // processProtectedShortDatagramWithInstalledKeys() can send/receive
    // caller-keyed or connection-installed protected 1-RTT short
    // PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/
    // RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/
    // STOP_SENDING/CONNECTION_CLOSE packets. Config.enable_spin_bit turns on
    // the current single-path spin-bit model; nextOutgoingSpinBit() exposes the
    // next short-header value and resetSpinBitForPath() resets it after a path
    // or CID change.
    // Full UDP packetization, socket-owned endpoint routing, real TLS backend
    // secret production, real TLS-backed early-data secret ownership, and
    // TLS 0-RTT acceptance/replay policy are still pending.
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
[`examples/initial_keys.zig`](examples/initial_keys.zig), and
[`examples/endpoint_routing.zig`](examples/endpoint_routing.zig) for runnable
examples. They exercise the current frame-payload, codec including QUIC v2
long-header type-bit mapping, transport-parameter including RFC 9368 version information,
flow-control, unidirectional stream, stream-reset, STOP_SENDING, close-state,
idle-timeout, handshake-state,
packet-number-space discard and 0-RTT frame filtering, ECN-validation,
loss-recovery including ACK-delay, recovery-period, and persistent congestion handling,
PTO-recovery, path-validation, address-validation including token version binding, Retry-token processing and v1/v2 integrity-tag,
connection-ID, stateless-reset, v1/v2 Initial key, key-update/protected-packet/header-protection,
and endpoint-routing/client-Initial route registration/accepted-Initial route registration/Retry-DCID/preferred-address/stateless-reset-token lookup APIs and are not yet interoperable
QUIC-over-UDP programs.

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
