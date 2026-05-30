# quicz

English | [简体中文](README_zh-CN.md)

A QUIC implementation in [Zig](https://ziglang.org/) aiming to follow the IETF QUIC standard defined at <https://quicwg.org/>.

> Status: **experimental / WIP**.  
> Goal: eventually support a fully-functional QUIC transport (RFC 9000 family and QUIC v2 RFC 9369), starting from a minimal but correct subset.

## Features and Roadmap

### Implemented / In Progress

- [x] Buildable Zig package with `Connection`, frame-payload examples, and runnable loopback examples.
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

### Build and run examples

```bash
zig build
zig build test --summary all
zig build run-codec
zig build run-initial-keys
```

`zig build` builds the static library at `zig-out/lib/libquicz.a` and all
example binaries under `zig-out/bin/`. The examples are deterministic protocol
exercises, not interoperable QUIC-over-UDP programs yet.

### Use as a library

High-level API shape, subject to evolution:

```zig
const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var conn = try quicz.Connection.init(
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

`Connection` is the canonical public connection handle. `QuicConnection` remains
available as a compatibility alias for older callers while the API is
experimental.

## Examples

- [Echo server](examples/echo_server.zig): Minimal frame-payload echo server skeleton.
  Run with `zig build run-server`.
- [Echo client](examples/echo_client.zig): Minimal frame-payload echo client skeleton.
  Run with `zig build run-client`.
- [Codec roundtrip](examples/codec_roundtrip.zig): Varints, packet headers,
  version negotiation, frames, transport parameters, and error codecs. Run with
  `zig build run-codec`.
- [Transport parameters](examples/transport_parameters.zig): Transport-parameter
  export, parsing, application, and close-on-error behavior. Run with
  `zig build run-transport-parameters`.
- [Flow control](examples/flow_control.zig): Connection, stream, stream-count,
  and BLOCKED/MAX frame behavior. Run with `zig build run-flow-control`.
- [Unidirectional streams](examples/uni_stream.zig): Local and peer
  unidirectional stream opening and validation. Run with `zig build run-uni-stream`.
- [Stream reset](examples/stream_reset.zig): RESET_STREAM send/receive behavior
  and retransmission boundaries. Run with `zig build run-stream-reset`.
- [STOP_SENDING](examples/stop_sending.zig): STOP_SENDING receive handling and
  RESET_STREAM response. Run with `zig build run-stop-sending`.
- [CRYPTO streams](examples/crypto_stream.zig): Per-space CRYPTO buffering,
  mock backend handoff, protected backend transport-parameter auto-close, and
  protected CRYPTO flow. Run with `zig build run-crypto-stream`.
- [Graceful close](examples/graceful_close.zig): Local/peer close, protected
  long/short close, protected receive auto-close, lifecycle-routed protected
  auto-close, draining behavior, and close-triggered validation. Run with
  `zig build run-graceful-close`.
- [Idle timeout](examples/idle_timeout.zig): Modeled idle timeout export,
  refresh, and close behavior. Run with `zig build run-idle-timeout`.
- [Packet spaces](examples/packet_spaces.zig): Initial, Handshake, 0-RTT, and
  Application packet-number-space behavior. Run with `zig build run-packet-spaces`.
- [ECN validation](examples/ecn_validation.zig): ACK_ECN validation and
  CE-driven congestion response. Run with `zig build run-ecn-validation`.
- [Loss recovery](examples/loss_recovery.zig): ACK-driven loss, RTT sampling,
  NewReno, and persistent congestion. Run with `zig build run-loss-recovery`.
- [PTO recovery](examples/pto_recovery.zig): PTO timers, probe selection,
  backoff, and anti-amplification gating. Run with `zig build run-pto-recovery`.
- [Endpoint recovery timers](examples/endpoint_recovery_timers.zig):
  Endpoint-owned recovery timer scheduling and routed protected receive refresh
  across connection handles. Run with `zig build run-endpoint-recovery-timers`.
- [Path validation](examples/path_validation.zig): PATH_CHALLENGE/PATH_RESPONSE
  retry and route update modeling. Run with `zig build run-path-validation`.
- [Address validation](examples/address_validation.zig): HMAC address-validation
  tokens, version binding, secret rotation, replay snapshots, and
  lifecycle-routed HANDSHAKE_DONE/NEW_TOKEN delivery. Run with
  `zig build run-address-validation`.
- [UDP address validation loopback](examples/udp_address_validation_loopback.zig):
  Socket-backed lifecycle-routed HANDSHAKE_DONE/NEW_TOKEN delivery, NEW_TOKEN
  path/version binding, replay rejection, and future address-validation
  unblocking. Run with `zig build run-udp-address-validation-loopback`.
- [Retry token](examples/retry_token.zig): Retry datagram processing, token
  reuse, and Retry CID validation. Run with `zig build run-retry-token`.
- [Connection IDs](examples/connection_ids.zig): NEW_CONNECTION_ID,
  RETIRE_CONNECTION_ID, and route replacement state. Run with
  `zig build run-connection-ids`.
- [Stateless reset](examples/stateless_reset.zig): Reset token matching and
  inactive-CID reset construction. Run with `zig build run-stateless-reset`.
- [Initial keys](examples/initial_keys.zig): QUIC v1/v2 Initial key derivation
  and configured v2 Initial packetization. Run with `zig build run-initial-keys`.
- [Endpoint routing](examples/endpoint_routing.zig): In-memory DCID, tuple,
  Version Negotiation, Retry, and reset routing. Run with
  `zig build run-endpoint-routing`.
- [UDP endpoint loopback](examples/udp_endpoint_loopback.zig): Socket-backed
  endpoint routing with Version Negotiation, protected follow-up Initial,
  accepted protected Initial processing, protected server Initial response
  processing, and Initial/short-header classification. Run with
  `zig build run-udp-endpoint-loopback`.
- [UDP zero-CID loopback](examples/udp_zero_cid_loopback.zig): Zero-length CID
  tuple routing over loopback UDP. Run with `zig build run-udp-zero-cid-loopback`.
- [UDP preferred address loopback](examples/udp_preferred_address_loopback.zig):
  Preferred-address route migration and active-migration-disabled handling. Run
  with `zig build run-udp-preferred-address-loopback`.
- [UDP replacement CID loopback](examples/udp_replacement_cid_loopback.zig):
  Replacement CID registration, retire_prior_to handling, and reset-token
  retention. Run with `zig build run-udp-replacement-cid-loopback`.
- [UDP connection IDs loopback](examples/udp_connection_ids_loopback.zig):
  Lifecycle-routed protected NEW_CONNECTION_ID/RETIRE_CONNECTION_ID and ACK
  exchange. Run with `zig build run-udp-connection-ids-loopback`.
- [UDP protected loopback](examples/udp_protected_loopback.zig):
  Lifecycle-owned accepted protected Initial processing and protected server
  Initial response processing plus routed caller-keyed 1-RTT processing over
  loopback UDP. Run with `zig build run-udp-protected-loopback`.
- [UDP Handshake keys loopback](examples/udp_handshake_keys_loopback.zig):
  Socket-backed lifecycle-routed installed-key Handshake CRYPTO delivery and
  ACK cleanup over loopback UDP. Run with
  `zig build run-udp-handshake-keys-loopback`.
- [UDP Crypto stream loopback](examples/udp_crypto_stream_loopback.zig):
  Socket-backed mock `CryptoBackend` Handshake CRYPTO byte handoff,
  transport-parameter exchange, and routed ACK cleanup. Run with
  `zig build run-udp-crypto-stream-loopback`.
- [UDP 0-RTT loopback](examples/udp_zero_rtt_loopback.zig):
  Socket-backed lifecycle-routed installed-key 0-RTT STREAM delivery,
  accept-before-process enforcement, 1-RTT ACK cleanup, and server-side
  0-RTT key discard. Run with `zig build run-udp-zero-rtt-loopback`.
- [UDP 1-RTT loopback](examples/udp_one_rtt_loopback.zig):
  Socket-backed lifecycle-routed installed-key 1-RTT STREAM delivery and ACK
  cleanup. Run with `zig build run-udp-one-rtt-loopback`.
- [UDP CryptoBackend loopback](examples/udp_crypto_backend_loopback.zig):
  Socket-backed mock `CryptoBackend` 1-RTT traffic-secret handoff followed by
  lifecycle-routed installed-key STREAM delivery and ACK cleanup. Run with
  `zig build run-udp-crypto-backend-loopback`.
- [UDP HANDSHAKE_DONE loopback](examples/udp_handshake_done_loopback.zig):
  Socket-backed lifecycle-routed installed-key HANDSHAKE_DONE confirmation,
  Handshake key discard, and ACK cleanup. Run with
  `zig build run-udp-handshake-done-loopback`.
- [UDP flow control loopback](examples/udp_flow_control_loopback.zig):
  Lifecycle-routed protected STREAM/BLOCKED/MAX flow-control exchange over
  loopback UDP. Run with `zig build run-udp-flow-control-loopback`.
- [UDP spin bit loopback](examples/udp_spin_bit_loopback.zig): Configurable
  single-path spin-bit signaling over lifecycle-routed protected short packets.
  Run with `zig build run-udp-spin-bit-loopback`.
- [UDP ECN validation loopback](examples/udp_ecn_validation_loopback.zig):
  Lifecycle-routed modeled ECN state and ACK_ECN validation over loopback UDP.
  Run with `zig build run-udp-ecn-validation-loopback`.
- [UDP loss recovery loopback](examples/udp_loss_recovery_loopback.zig):
  Lifecycle-routed protected ACK-driven packet loss and timer-driven cleanup
  over loopback UDP. Run with `zig build run-udp-loss-recovery-loopback`.
- [UDP congestion recovery loopback](examples/udp_congestion_recovery_loopback.zig):
  Lifecycle-routed NewReno recovery-period and persistent-congestion behavior
  over loopback UDP. Run with `zig build run-udp-congestion-recovery-loopback`.
- [UDP PTO recovery loopback](examples/udp_pto_recovery_loopback.zig):
  Endpoint lifecycle PTO probing, routed receive processing, and retransmission
  choices over loopback UDP. Run with `zig build run-udp-pto-recovery-loopback`.
- [UDP STREAM retransmission loopback](examples/udp_stream_retransmission_loopback.zig):
  ACK-loss-triggered STREAM retransmission through lifecycle-routed protected
  receives. Run with `zig build run-udp-stream-retransmission-loopback`.
- [UDP key update loopback](examples/udp_key_update_loopback.zig):
  Lifecycle-routed installed-key key update, key phase advancement, and ACK
  gating. Run with `zig build run-udp-key-update-loopback`.
- [UDP path validation loopback](examples/udp_path_validation_loopback.zig):
  Lifecycle-routed PATH_CHALLENGE/PATH_RESPONSE route validation over a new
  peer port. Run with `zig build run-udp-path-validation-loopback`.
- [UDP Retry loopback](examples/udp_retry_loopback.zig): Lifecycle-owned Retry
  delivery, token validation, and routed follow-up Initial processing. Run
  with `zig build run-udp-retry-loopback`.
- [UDP close lifecycle loopback](examples/udp_close_lifecycle_loopback.zig):
  Lifecycle-routed protected close delivery, route retirement, and stateless
  reset follow-up. Run with `zig build run-udp-close-lifecycle-loopback`.
- [UDP stateless reset loopback](examples/udp_stateless_reset_loopback.zig):
  Socket-backed reset trigger delivery, reset emission, and client token match.
  Run with `zig build run-udp-stateless-reset-loopback`.

## Advanced Topics

- [Transport task matrix](docs/en/quic_transport_tasks.md): current RFC coverage, remaining work, and verification evidence.
- [Design notes](docs/en/spec.md): current architecture, protocol scope, and unsupported areas.
- Packet protection: QUIC v1/v2 Initial keys, Retry integrity, protected packet helpers, and key-update state.
- Endpoint lifecycle: DCID routing, route retirement, stateless reset lookup/emission, and endpoint recovery timers.
- Recovery and congestion: simplified RFC 9002 ACK/loss/PTO/NewReno/ECN model with deterministic tests.
- TLS status: mock `CryptoBackend` handoff is present; real TLS 1.3 transcript integration is still pending.

## License

MIT
