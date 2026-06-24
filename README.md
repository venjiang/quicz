# quicz

English | [简体中文](README_zh-CN.md)

A QUIC implementation in [Zig](https://ziglang.org/) aiming to follow the IETF QUIC standard defined at <https://quicwg.org/>.

> Status: **experimental / WIP**.  
> Goal: implement a practical QUIC transport subset aligned with the common
> capabilities expected from mature QUIC stacks. Optional extensions are
> tracked explicitly instead of being treated as required for the first usable
> transport.

## Features and Roadmap

### Implemented / In Progress

- [x] Buildable Zig package with `Connection`, frame-payload examples, and runnable loopback examples.
- [x] Core codec coverage for varints, packet headers, packet numbers, frames, transport parameters, transport errors including RFC 9368 version-negotiation close classification, Version Negotiation and compatible-version selection helpers, Retry, stateless reset, and QUIC v2 packet/key/token primitives.
- [x] Experimental in-memory transport state for streams, CRYPTO byte streams, flow control, connection IDs, Retry/tokens, path validation, close/idle timers, packet number spaces, and rollback on invalid frame payloads.
- [x] Packet protection helpers for QUIC v1/v2 Initial keys, Retry integrity, protected long/short packets, configured v2 protected long-packet/Retry wire versions, installed-key mock TLS handoff, and key update state.
- [x] Simplified RFC 9002-style ACK, loss, PTO, NewReno congestion, congestion-window and ack-eliciting send-admission budget/reason queries, ECN, retransmission, and endpoint recovery-timer models with socket-backed UDP loopback coverage.
- [x] In-memory endpoint routing/lifecycle helpers for DCID and IPv4 UDP tuple routing, Version Negotiation, zero-length CID routing, preferred/replacement CID routing, route retirement, stateless reset emission, and protected UDP loopbacks.
- [ ] Complete connection state machine and TLS-owned protected-packet packet number space routing.
- [ ] Endpoint-owned TLS-backed socket client/server echo with a live TLS handshake driving UDP packet routing, automatic traffic-secret installation, and 1-RTT STREAM delivery.
- [ ] Embeddable socket API where callers own UDP sockets, connection maps, timers, and datagram output queues.
- [ ] Minimal external interop entry for `handshake` and `transfer`.
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

### Practical Target Boundary

The first usable target is not "every QUIC option". It is a TLS-backed QUIC v1
client/server stream transport with UDP endpoint lifecycle ownership,
transport-parameter exchange, packet protection, bidirectional and
unidirectional streams, flow control, stream reset/STOP_SENDING, ACK/loss/PTO
recovery, congestion control, close/idle handling, connection IDs, path
validation, Retry/address validation, stateless reset, and interop evidence.

HTTP/3/QPACK, RFC 9221 DATAGRAM, full QUIC v2 / RFC 9368 version negotiation,
multi-path, qlog, GSO/GRO, PMTU discovery, and advanced congestion-controller
selection are tracked in the task plan, but they are not required for the
first interoperable transport milestone unless they become necessary for the
chosen interop target.

For the verifiable transport implementation task plan, see
[`docs/en/quic_transport_tasks.md`](docs/en/quic_transport_tasks.md).
For terminology, architecture, core protocol flows, and extension entry points,
see [`docs/en/architecture.md`](docs/en/architecture.md).
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

Common runnable examples:

- `run-tls-openssl-backend-adapter`: OpenSSL-backed C TLS adapter path,
  including local transport parameters, first outbound TLS CRYPTO flight, and
  quicz-encoded pair-transcript server transport-parameter bytes,
  Handshake/1-RTT secret, and inbound CRYPTO delivery through OpenSSL callback
  boundaries. It now sends the
  adapter-generated Initial CRYPTO flight as a protected Initial datagram over
  loopback UDP, routes real pair-transcript Handshake CRYPTO as a protected
  Handshake datagram over loopback UDP, reuses the matching Handshake/1-RTT
  secrets, and drives a loopback UDP 1-RTT STREAM echo with adapter-installed
  client keys and matching peer transcript secrets, including Application PTO
  service through the same lifecycle owner. After OpenSSL recv/release consumes
  inbound Handshake CRYPTO, the OpenSSL-backed `handshake_confirmed` callback
  confirms the client and an endpoint lifecycle-owned no-output Handshake
  drive discards the client Handshake packet-number space and keys. The paired
  loopback server also
  consumes client Handshake CRYPTO over loopback UDP, pulls peer transport
  parameters and Handshake/1-RTT secrets through the backend, confirms, and
  clears its Handshake keys; the direct server probe also consumes Handshake
  CRYPTO and reports `server_probe_confirmed=true` before protected close and
  route cleanup through one socket/lifecycle loop owner.
- `run-tls-openssl-pair-transcript`: OpenSSL client/server callback-mode TLS
  transcript, with level-separated CRYPTO handoff plus peer transport-parameter
  and traffic-secret callbacks on both endpoints, then mapped into quicz
  Initial/Handshake/Application CRYPTO queues. It records and parses
  role-specific peer transport-parameter bytes generated by quicz local
  transport-parameter export, and records keylog callback count/byte evidence
  without printing key material. The client Initial CRYPTO
  bytes are also sent through quicz protected Initial long-packet helpers and
  read back by the server connection, and both Initial flights also run over
  loopback UDP through the quicz endpoint lifecycle; a manual OpenSSL context
  check also routes the live Initial and Handshake TLS CRYPTO bytes through
  that same socket/lifecycle boundary. The OpenSSL Handshake secrets drive
  installed-key protected Handshake CRYPTO delivery in both directions,
  including loopback UDP delivery through the quicz endpoint lifecycle. The
  same manual OpenSSL context also installs matching 1-RTT secrets and drives
  a quicz STREAM request/echo/final-ACK exchange through the same
  socket/lifecycle path, then discards Handshake state and closes/cleans up
  both lifecycle route sets; the global OpenSSL pair transcript still
  separately verifies installed-key short-packet STREAM request/response and
  socket echo.
- `run-udp-echo-loopback`: socket-backed installed-key STREAM echo,
  including payload equality, ACK cleanup, and recovery timer cleanup.
- `run-udp-pto-recovery-loopback`, `run-udp-loss-recovery-loopback`, and
  `run-udp-congestion-recovery-loopback`: lifecycle-routed recovery and
  congestion behavior over loopback UDP.
- `run-udp-close-lifecycle-loopback` and `run-udp-stateless-reset-loopback`:
  route cleanup and reset behavior through the endpoint lifecycle owner.

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
`EndpointConnectionLifecycle` now exposes the core socket-loop and TLS-backend
loop entrypoints `feedDatagram`, `feedDatagramWithInstalledKeys`,
`feedDatagramWithInstalledKeysAcrossConnections`,
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndSelectNextDeadline`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndSelectNextDeadline`,
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndSelectNextDeadline`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndSelectNextDeadline`,
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline`,
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions`,
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions`,
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions`,
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions`,
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDrainDatagramsWithInstalledKeyOptions`,
`processPendingWork`,
`processAcceptedProtectedInitialWithCryptoBackendAndPollDatagram`,
`processAcceptedProtectedInitialWithCryptoBackendOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagram`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
`processPendingWorkAcrossConnections`, `processPendingWorkAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndDrainDatagrams`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
`processPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagram`,
`processPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagrams`,
`processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`,
`processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`,
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`,
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`,
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
`processPendingWorkAndDrainDatagrams`, `processDueDeadlineAndPollDatagram`,
`processDueDeadlineAndDrainDatagrams`,
`processDueDeadlineAndPollDatagramWithInstalledKeyOptions`,
`processDueDeadlineAndDrainDatagramsWithInstalledKeyOptions`,
`processDueDeadlineAndDriveCryptoBackendInSpaceAndPollDatagram`,
`processDueDeadlineAndDriveCryptoBackendInSpaceAndDrainDatagrams`,
`processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`,
`processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`,
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`,
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`,
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
`processDueDeadlineAcrossConnectionsAndPollDatagram`,
`processDueDeadlineAcrossConnectionsAndDrainDatagrams`,
`processDueDeadlineAcrossConnectionsAndPollDatagramWithInstalledKeyOptions`,
`processDueDeadlineAcrossConnectionsAndDrainDatagramsWithInstalledKeyOptions`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
`pollDatagram`, `drainDatagramsAcrossConnections`,
`pollDatagramAcrossConnections`, `driveCryptoBackendsInSpaceAndArmConnections`,
`driveCryptoBackendsInSpaceAndPollDatagram`,
`driveCryptoBackendInSpaceAndPollDatagram`,
`driveCryptoBackendsInSpaceAndDrainDatagrams`,
`driveCryptoBackendInSpaceAndDrainDatagrams`,
`driveCryptoBackendsInSpaceOrCloseAndArmConnections`,
`driveCryptoBackendsInSpaceOrCloseAndPollDatagram`,
`driveCryptoBackendInSpaceOrCloseAndPollDatagram`,
`driveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`,
`driveCryptoBackendInSpaceOrCloseAndDrainDatagrams`,
`driveCryptoBackendsInSpaceWithCompatibleVersionAndArmConnections`,
`driveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`,
`driveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`,
`driveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`,
`driveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`,
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndArmConnections`,
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
`driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
`driveCryptoBackendInSpaceAndDrainProtectedLongCryptoDatagrams`,
`driveCryptoBackendInSpaceOrCloseAndDrainProtectedLongCryptoDatagrams`,
`processProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams`,
`processProtectedLongDatagramInSpaceAndDriveCryptoBackendOrCloseAndDrainDatagrams`,
`processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams`,
`processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendOrCloseAndDrainDatagrams`,
`processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams`,
`processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendOrCloseAndDrainDatagrams`,
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams`,
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendOrCloseAndDrainDatagrams`,
`drainProtectedLongCryptoDatagramsInSpace`,
`processAcceptedProtectedInitialWithCryptoBackendAndDrainDatagrams`,
`nextDeadline`, and `nextDeadlineAcrossConnections` for routing, installed-key
packet receive, cross-connection receive dispatch, accepted-Initial-to-backend
server response and close propagation, timeout/timer work,
cross-connection pending-work sweep, due-deadline service, cross-connection
due-deadline dispatch, recovery wakeup packet output, installed-key packet
output, bounded caller-owned output draining, bounded long-header CRYPTO output
draining, cross-connection output dispatch,
cross-connection pending-work-to-output loop steps,
cross-connection pending-work-to-bounded-drain loop steps,
receive-to-backend-to-output loop steps, receive-to-backend-to-bounded-drain
loop steps, cross-connection TLS backend drive,
backend-drive-to-datagram output steps, backend-drive-to-bounded-drain output
steps, single-connection backend-drive-to-datagram output steps,
single-connection backend-drive-to-bounded-drain output steps,
single-connection compatible-version backend-drive-to-datagram output steps,
single-connection compatible-version backend-drive-to-bounded-drain output steps,
backend-drive-to-caller-keyed long-header drain steps,
close-propagating backend-drive-to-caller-keyed long-header drain steps,
caller-keyed receive-to-backend-to-bounded-drain loop steps,
caller-keyed receive-to-backend-close-to-bounded-drain loop steps,
routed caller-keyed receive-to-backend-to-bounded-drain loop steps,
routed caller-keyed receive-to-backend-close-to-bounded-drain loop steps,
installed-key Handshake receive-to-backend-to-bounded-drain loop steps,
close-propagating installed-key Handshake backend-drain loop steps,
routed installed-key Handshake receive-to-backend-to-bounded-drain loop steps,
routed installed-key Handshake receive-to-backend-close-to-bounded-drain loop steps,
single-connection installed-key receive-to-backend-to-output loop steps,
single-connection installed-key receive-to-backend-to-bounded-drain loop steps,
single-connection installed-key receive-to-backend-close-to-output loop steps,
single-connection installed-key receive-to-backend-close-to-bounded-drain loop steps,
single-connection compatible-version receive-to-backend-to-output loop steps,
single-connection compatible-version receive-to-backend-to-bounded-drain loop steps,
single-connection compatible-version receive-to-backend-close-to-output loop steps,
single-connection compatible-version receive-to-backend-close-to-bounded-drain loop steps,
single-connection pending-work-to-backend-to-output loop steps,
single-connection pending-work-to-backend-to-bounded-drain loop steps,
single-connection pending-work-to-backend-close-to-output loop steps,
single-connection pending-work-to-backend-close-to-bounded-drain loop steps,
single-connection compatible-version pending-work-to-backend-to-output loop steps,
single-connection compatible-version pending-work-to-backend-to-bounded-drain loop steps,
single-connection compatible-version pending-work-to-backend-close-to-output loop steps,
single-connection compatible-version pending-work-to-backend-close-to-bounded-drain loop steps,
single-connection due-deadline-to-backend-to-output loop steps,
single-connection due-deadline-to-backend-to-bounded-drain loop steps,
single-connection due-deadline-to-backend-close-to-output loop steps,
single-connection due-deadline-to-backend-close-to-bounded-drain loop steps,
single-connection compatible-version due-deadline-to-backend-to-output loop steps,
single-connection compatible-version due-deadline-to-backend-to-bounded-drain loop steps,
single-connection compatible-version due-deadline-to-backend-close-to-output loop steps,
single-connection compatible-version due-deadline-to-backend-close-to-bounded-drain loop steps,
pending-work-to-bounded-drain loop steps, pending-work-to-backend-to-output loop steps,
pending-work-to-backend-to-bounded-drain loop steps, due-deadline-to-backend-to-output
loop steps, due-deadline-to-bounded-drain loop steps,
due-deadline-to-backend-to-bounded-drain loop steps,
cross-connection due-deadline terminal-cleanup backend suppression,
close-propagating TLS backend drive, RFC 9368 compatible-version
backend sweeps, and event-loop wakeup selection across caller-owned connection
maps.
`EndpointConnectionDeadline.installedKeyPollOptions()` maps recovery wakeups
from `nextDeadline()` into installed-key poll options for Handshake and 1-RTT
paths. `processDueDeadlineAndPollDatagramWithInstalledKeyOptions()` and
`processDueDeadlineAndDrainDatagramsWithInstalledKeyOptions()` let callers
service due recovery wakeups with explicit installed-key output choices, such
as accepted 0-RTT; the cross-connection `WithInstalledKeyOptions` variants
preserve the same explicit choice while selecting the earliest due connection
from a caller-owned map. Single-connection due-deadline-to-backend poll and
drain wrappers also preserve explicit 0-RTT recovery output before any backend
drive; cross-connection due-deadline-to-backend poll/drain `WithInstalledKeyOptions`
variants do the same before backend sweeps. The direct receive-to-output
cross-connection `WithInstalledKeyOptions` feed helpers preserve per-connection
installed-key output choices after routed datagram processing. A production
TLS-owned socket event loop is still pending.

`Connection` is the canonical public connection handle. `QuicConnection` remains
available as a compatibility alias for older callers while the API is
experimental.

## Examples

- [Echo server](examples/echo_server.zig): Minimal frame-payload echo server skeleton.
  Run with `zig build run-server`.
- [Echo client](examples/echo_client.zig): Minimal frame-payload echo client skeleton.
  Run with `zig build run-client`.
- [Codec roundtrip](examples/codec_roundtrip.zig): Varints, packet headers,
  version negotiation including explicit compatible-version selection and RFC
  9368 downgrade close-code evidence, frames, transport parameters, and error
  codecs. Run with `zig build run-codec`.
- [Transport parameters](examples/transport_parameters.zig): Transport-parameter
  export, parsing, application including compatible-version selection, and
  close-on-error behavior. Run with `zig build run-transport-parameters`.
- [Flow control](examples/flow_control.zig): Connection, stream, stream-count,
  MAX_STREAMS overflow rejection, and BLOCKED/MAX frame behavior. Run with
  `zig build run-flow-control`.
- [Unidirectional streams](examples/uni_stream.zig): Local and peer
  unidirectional stream opening and validation. Run with `zig build run-uni-stream`.
- [Stream reset](examples/stream_reset.zig): RESET_STREAM send/receive behavior,
  retransmission boundaries, stream-state snapshots with reset-read/reset-acked
  evidence, and send-credit closure after reset. Run with
  `zig build run-stream-reset`.
- [STOP_SENDING](examples/stop_sending.zig): STOP_SENDING receive handling and
  stream-state snapshot evidence for the RESET_STREAM response. Run with
  `zig build run-stop-sending`.
- [CRYPTO streams](examples/crypto_stream.zig): Per-space CRYPTO buffering,
  receive-buffer overflow auto-close, mock backend handoff, protected backend
  transport-parameter auto-close, compatible backend Version Information
  handoff progress, backend-confirmed Handshake key discard, and protected
  CRYPTO flow. Run with `zig build run-crypto-stream`.
- [TLS backend adapter](examples/tls_backend_adapter.zig): C-ABI `TlsBackend`
  callback adaptation into the existing `CryptoBackend` drive path, with
  local/peer transport-parameter handoff, CRYPTO bytes, Handshake traffic
  secrets, and confirmation evidence. Run with
  `zig build run-tls-backend-adapter`.
- [TLS C ABI adapter](examples/tls_c_abi_adapter.zig): C-compiled callback
  object wired through `TlsBackend`, proving the adapter can be driven from a C
  boundary before binding a concrete TLS library. Run with
  `zig build run-tls-c-abi-adapter`.
- [TLS OpenSSL probe](examples/tls_openssl_probe.zig): Links OpenSSL via
  `pkg-config`, verifies the OpenSSL QUIC method and QUIC TLS callback/
  transport-parameter APIs, and records that callback mode is distinct from
  OpenSSL's full QUIC connection mode. Run with `zig build run-tls-openssl-probe`.
- [TLS OpenSSL pair transcript](examples/tls_openssl_pair_transcript.zig):
  OpenSSL client/server callback-mode TLS transcript using a fixed PSK for the
  example, level-separated CRYPTO handoff, peer transport-parameter callbacks,
  Handshake/1-RTT traffic-secret callbacks on both endpoints, and delivery of
  the generated CRYPTO bytes into quicz packet-number-space CRYPTO queues. It
  configures OpenSSL with quicz-encoded local transport-parameter bytes,
  records and parses the peer bytes received through OpenSSL callbacks, records
  keylog callback count/byte evidence without printing key material, then
  packetizes the client
  Initial CRYPTO bytes with quicz protected Initial long-packet helpers, routes
  both Initial flights over loopback UDP through the quicz endpoint lifecycle,
  and verifies a manual OpenSSL Initial/Handshake transcript over the same
  socket path, installs OpenSSL-produced Handshake secrets, and verifies
  protected Handshake CRYPTO delivery in both directions, including loopback
  UDP delivery through the same lifecycle. The same manual OpenSSL context
  installs OpenSSL-produced 1-RTT secrets and drives a STREAM request/echo
  plus final ACK through the same socket path, then verifies Handshake key
  discard and protected close/route cleanup through that lifecycle; the full
  pair transcript also verifies installed-key protected STREAM request/response
  and loopback UDP STREAM echo with OpenSSL-produced 1-RTT secrets.
  Run with `zig build run-tls-openssl-pair-transcript`.
- [TLS OpenSSL backend adapter](examples/tls_openssl_backend_adapter.zig):
  OpenSSL-backed `TlsBackend` wrapper that accepts quicz local transport
  parameters through `SSL_set_quic_tls_transport_params()`, drives
  `SSL_do_handshake()` to emit the first TLS CRYPTO flight, and carries
  quicz-encoded pair-transcript server transport parameters, real pair-transcript
  Handshake/1-RTT secrets, and inbound Handshake CRYPTO bytes through OpenSSL
  callback boundaries. It also
  routes the adapter-generated Initial CRYPTO flight through a protected
  Initial datagram over loopback UDP, routes real pair-transcript Handshake
  CRYPTO through a protected Handshake datagram over loopback UDP, and drives a
  loopback UDP 1-RTT STREAM echo with adapter-installed client keys and
  matching peer transcript secrets, including Application PTO service through
  the same lifecycle owner. After OpenSSL recv/release consumes inbound
  Handshake CRYPTO, the OpenSSL-backed `handshake_confirmed` callback confirms
  the client through the endpoint lifecycle-owned backend drive; the server
  connection probe also pulls real pair-transcript 1-RTT secrets through the
  backend, confirms the server connection, and records OpenSSL secret callbacks
  plus peer stream-count limits from the applied transport parameters before
  discarding its Handshake packet-number space and keys. The paired loopback
  endpoint then sends
  protected close and completes route cleanup through one socket/lifecycle loop
  owner. Run with
  `zig build run-tls-openssl-backend-adapter`.
- [Graceful close](examples/graceful_close.zig): Local/peer close, protected
  long/short close, invalid ACK/ACK_ECN-range auto-close, semantic frame-error
  auto-close including invalid ACK/ACK_ECN, 0-RTT ACK/ACK_ECN packet-type
  violations, invalid STREAMS_BLOCKED limits, conflicting STREAM data, and
  invalid stream control frames, protected receive auto-close, lifecycle-routed
  protected auto-close, protected long/0-RTT close-state discard, draining
  behavior, and close-triggered validation. Run with
  `zig build run-graceful-close`.
- [Idle timeout](examples/idle_timeout.zig): Modeled idle timeout export,
  refresh, close behavior, and endpoint route/timer cleanup. Run with
  `zig build run-idle-timeout`.
- [Packet spaces](examples/packet_spaces.zig): Initial, Handshake, 0-RTT, and
  Application packet-number-space behavior. Run with `zig build run-packet-spaces`.
- [ECN validation](examples/ecn_validation.zig): ACK_ECN validation and
  CE-driven congestion response. Run with `zig build run-ecn-validation`.
- [Loss recovery](examples/loss_recovery.zig): ACK-driven loss, RTT sampling,
  NewReno recovery-period ACK accounting, loss/CE-driven congestion probes,
  persistent-congestion min-RTT refresh, recovery-period clearing/re-entry, and
  non-contiguous persistent-congestion suppression. Run with
  `zig build run-loss-recovery`.
- [PTO recovery](examples/pto_recovery.zig): PTO timers, probe selection,
  backoff, client anti-deadlock PTO, anti-amplification gating/unblock service,
  and ACKed RESET_STREAM retransmission suppression. Run with
  `zig build run-pto-recovery`.
- [Endpoint recovery timers](examples/endpoint_recovery_timers.zig):
  Endpoint-owned recovery timer scheduling, caller-keyed and installed-key
  protected long/short probe polling, and routed protected receive refresh across
  connection handles. Run with `zig build run-endpoint-recovery-timers`.
- [Path validation](examples/path_validation.zig): PATH_CHALLENGE/PATH_RESPONSE
  retry, duplicate pending-response suppression, 1200-byte protected
  path-validation datagrams, and validation-driven lifecycle route updates. Run with
  `zig build run-path-validation`.
- [Address validation](examples/address_validation.zig): HMAC address-validation
  tokens, version binding, secret rotation, replay snapshots, lifecycle-owned
  HANDSHAKE_DONE/NEW_TOKEN emission/delivery timer evidence, and lifecycle-owned
  token validation unblocking. Run with
  `zig build run-address-validation`.
- [UDP address validation loopback](examples/udp_address_validation_loopback.zig):
  Socket-backed lifecycle-owned HANDSHAKE_DONE/NEW_TOKEN emission/delivery timer
  evidence, NEW_TOKEN path/version binding with explicit changed-path rejection,
  secret rotation, replay snapshot restore rejection, and lifecycle-owned
  address-validation block/unblock evidence. Run with
  `zig build run-udp-address-validation-loopback`.
- [Retry token](examples/retry_token.zig): Retry datagram processing,
  lifecycle-owned token validation/consumption, token reuse rejection, and Retry
  CID transport-parameter byte validation. Run with
  `zig build run-retry-token`.
- [Connection IDs](examples/connection_ids.zig): NEW_CONNECTION_ID,
  RETIRE_CONNECTION_ID, lifecycle-owned issue/register route bridging, and
  replacement state. Run with `zig build run-connection-ids`.
- [Stateless reset](examples/stateless_reset.zig): Reset token matching and
  inactive-CID reset construction. Run with `zig build run-stateless-reset`.
- [Initial keys](examples/initial_keys.zig): QUIC v1/v2 Initial key derivation
  and configured v2 Initial packetization. Run with `zig build run-initial-keys`.
- [Endpoint routing](examples/endpoint_routing.zig): In-memory DCID, tuple,
  Version Negotiation, Retry, and reset routing. Run with
  `zig build run-endpoint-routing`.
- [UDP endpoint loopback](examples/udp_endpoint_loopback.zig): Socket-backed
  endpoint routing with Version Negotiation, protected follow-up Initial,
  follow-up Original DCID evidence, accepted protected Initial processing,
  protected server Initial response processing, server transport-parameter
  byte validation, and Initial/short-header classification. Run with
  `zig build run-udp-endpoint-loopback`.
- [UDP zero-CID loopback](examples/udp_zero_cid_loopback.zig): Zero-length CID
  tuple routing, unknown tuple rejection, and route update over loopback UDP.
  Run with `zig build run-udp-zero-cid-loopback`.
- [UDP preferred address loopback](examples/udp_preferred_address_loopback.zig):
  Preferred-address transport-parameter byte handoff, route migration, and
  active-migration-disabled handling. Run with
  `zig build run-udp-preferred-address-loopback`.
- [UDP replacement CID loopback](examples/udp_replacement_cid_loopback.zig):
  Replacement CID registration, retire_prior_to handling, and reset-token
  retention. Run with `zig build run-udp-replacement-cid-loopback`.
- [UDP connection IDs loopback](examples/udp_connection_ids_loopback.zig):
  Lifecycle-routed protected NEW_CONNECTION_ID/RETIRE_CONNECTION_ID, endpoint
  issue/register route bridging, active replacement routing, and ACK exchange.
  Run with `zig build run-udp-connection-ids-loopback`.
- [UDP protected loopback](examples/udp_protected_loopback.zig):
  Lifecycle-owned accepted protected Initial processing and protected server
  Initial response processing plus routed caller-keyed 1-RTT processing over
  loopback UDP. Run with `zig build run-udp-protected-loopback`.
- [UDP Handshake keys loopback](examples/udp_handshake_keys_loopback.zig):
  Socket-backed lifecycle-routed installed-key Handshake CRYPTO delivery and
  ACK cleanup, plus serviced installed-key Handshake PTO probe routing over loopback UDP. Run with
  `zig build run-udp-handshake-keys-loopback`.
- [UDP Crypto stream loopback](examples/udp_crypto_stream_loopback.zig):
  Socket-backed mock `CryptoBackend` Handshake CRYPTO byte handoff,
  transport-parameter exchange, and routed ACK cleanup. Run with
  `zig build run-udp-crypto-stream-loopback`.
- [UDP 0-RTT loopback](examples/udp_zero_rtt_loopback.zig):
  Socket-backed lifecycle-routed installed-key 0-RTT STREAM delivery,
  accept-before-process enforcement, rejection-driven key discard, serviced
  installed-key 0-RTT PTO probe routing with duplicate STREAM discard evidence,
  accepted early ACK evidence, 1-RTT ACK cleanup, and client/server 0-RTT key
  discard evidence. Run with
  `zig build run-udp-zero-rtt-loopback`.
- [UDP 1-RTT loopback](examples/udp_one_rtt_loopback.zig):
  Socket-backed lifecycle-routed installed-key 1-RTT STREAM delivery, serviced
  installed-key 1-RTT PTO probe routing with duplicate STREAM discard evidence,
  and ACK cleanup. Run with `zig build run-udp-one-rtt-loopback`.
- [UDP echo loopback](examples/udp_echo_loopback.zig):
  Socket-backed lifecycle-routed installed-key 1-RTT STREAM echo, request/echo
  payload equality, serviced server-side 1-RTT PTO probe routing with duplicate
  STREAM discard evidence, final ACK cleanup, and client/server
  bytes-in-flight/timer-state evidence. Run with
  `zig build run-udp-echo-loopback`.
- [UDP CryptoBackend loopback](examples/udp_crypto_backend_loopback.zig):
  Socket-backed mock `CryptoBackend` 1-RTT traffic-secret handoff followed by
  lifecycle-routed installed-key STREAM echo, client/server installed-key PTO
  probe routing with duplicate STREAM discard evidence, final ACK cleanup, and
  client/server bytes-in-flight and recovery-timer deadline/cleanup evidence.
  Run with `zig build run-udp-crypto-backend-loopback`.
- [UDP HANDSHAKE_DONE loopback](examples/udp_handshake_done_loopback.zig):
  Socket-backed lifecycle-routed installed-key HANDSHAKE_DONE confirmation,
  server/client Handshake key discard and public state evidence, plus ACK
  pending/cleanup output. Run with
  `zig build run-udp-handshake-done-loopback`.
- [UDP flow control loopback](examples/udp_flow_control_loopback.zig):
  Lifecycle-routed protected STREAM/BLOCKED/MAX flow-control exchange over
  loopback UDP, including resumed FIN final-size evidence and caller-keyed
  resumed STREAM PTO probe routing with duplicate discard evidence. Run with
  `zig build run-udp-flow-control-loopback`.
- [UDP spin bit loopback](examples/udp_spin_bit_loopback.zig): Configurable
  single-path spin-bit signaling and route-update spin reset over
  lifecycle-routed protected short packets. Run with
  `zig build run-udp-spin-bit-loopback`.
- [UDP ECN validation loopback](examples/udp_ecn_validation_loopback.zig):
  Lifecycle-routed modeled ECN state and ACK_ECN validation over loopback UDP.
  Run with `zig build run-udp-ecn-validation-loopback`.
- [UDP loss recovery loopback](examples/udp_loss_recovery_loopback.zig):
  Lifecycle-routed protected ACK-driven packet loss and timer-driven cleanup
  over loopback UDP. Run with `zig build run-udp-loss-recovery-loopback`.
- [UDP congestion recovery loopback](examples/udp_congestion_recovery_loopback.zig):
  Lifecycle-routed NewReno recovery-period and persistent-congestion behavior
  over loopback UDP, with explicit repeated-loss suppression, minimum-window,
  and ACK_ECN CE-driven STREAM probe evidence. Run with
  `zig build run-udp-congestion-recovery-loopback`.
- [UDP PTO recovery loopback](examples/udp_pto_recovery_loopback.zig):
  Endpoint lifecycle timer service, protected long/short and installed-key
  0-RTT PTO probe polling, routed receive processing, and retransmission
  choices over loopback UDP. Run with `zig build run-udp-pto-recovery-loopback`.
- [UDP STREAM retransmission loopback](examples/udp_stream_retransmission_loopback.zig):
  ACK-loss-triggered STREAM retransmission through lifecycle-routed protected
  receives. Run with `zig build run-udp-stream-retransmission-loopback`.
- [UDP key update loopback](examples/udp_key_update_loopback.zig):
  Lifecycle-routed installed-key key update, key phase advancement, and ACK
  gating with observable ACK threshold, generation-count, and retained-generation
  old-key discard evidence, including second-update PTO probe routing and stale
  old-generation packet rejection. Run with `zig build run-udp-key-update-loopback`.
- [UDP path validation loopback](examples/udp_path_validation_loopback.zig):
  Lifecycle-routed PATH_CHALLENGE/PATH_RESPONSE validation-driven route update
  over a new peer port with close-propagating receive, plus pre-validation PING
  no-update evidence. Run with `zig build run-udp-path-validation-loopback`.
- [UDP Retry loopback](examples/udp_retry_loopback.zig): Lifecycle-owned Retry
  delivery, token validation/consumption, and follow-up Initial acceptance and
  processing. Run with `zig build run-udp-retry-loopback`.
- [UDP close lifecycle loopback](examples/udp_close_lifecycle_loopback.zig):
  Lifecycle-routed protected close delivery, protected receive auto-close,
  close/drain deadline evidence, timeout-driven route cleanup, route
  retirement, and stateless reset follow-up. Run with
  `zig build run-udp-close-lifecycle-loopback`.
- [UDP stateless reset loopback](examples/udp_stateless_reset_loopback.zig):
  Socket-backed active-route suppression, unknown-CID drop, reset trigger
  delivery, reset emission, and client token match. Run with
  `zig build run-udp-stateless-reset-loopback`.

## Advanced Topics

- [Transport task matrix](docs/en/quic_transport_tasks.md): current RFC coverage, remaining work, and verification evidence.
- [Architecture and terminology](docs/en/architecture.md): key terms, module boundaries, core protocol flows, extension points, and troubleshooting entry points.
- [Design notes](docs/en/spec.md): current architecture, protocol scope, and unsupported areas.
- Packet protection: QUIC v1/v2 Initial keys, Retry integrity, protected packet helpers, and key-update state.
- Endpoint lifecycle: DCID routing, route retirement, stateless reset lookup/emission, active-route reset receive-to-draining handling, and endpoint recovery timers.
- Recovery and congestion: simplified RFC 9002 ACK/loss/PTO/NewReno/ECN model with deterministic tests.
- TLS status: mock `CryptoBackend` handoff and a narrow C-ABI `TlsBackend`
  adapter are present; `run-tls-openssl-probe` links OpenSSL and verifies its
  QUIC TLS callback APIs, `run-tls-openssl-pair-transcript` completes an
  OpenSSL client/server callback-mode TLS transcript with level-separated
  CRYPTO handoff, maps the generated bytes into quicz CRYPTO queues, and
  verifies protected Initial long-packet delivery, socket-backed Initial
  delivery for both Initial flights, manual OpenSSL Initial/Handshake
  transcript routing over the same socket/lifecycle boundary, installed-key
  protected Handshake delivery, including socket-backed delivery, using
  OpenSSL Handshake secrets, same-context manual 1-RTT STREAM echo over the
  same socket/lifecycle path, same-context Handshake key discard plus protected
  close/route cleanup, and installed-key protected STREAM request/response
  plus socket-backed STREAM echo using OpenSSL 1-RTT secrets, while recording
  keylog callback count/byte evidence without printing key material;
  `run-tls-openssl-backend-adapter` wires an OpenSSL object into the adapter
  path far enough to emit the first TLS CRYPTO flight and deliver peer
  transport parameters, real pair-transcript Handshake/1-RTT secrets, and
  inbound CRYPTO through callback boundaries, routes adapter-generated Initial
  CRYPTO and real pair-transcript Handshake CRYPTO over loopback UDP as
  protected Initial/Handshake datagrams, then drives loopback UDP 1-RTT STREAM
  echo with adapter-installed client keys and matching peer transcript secrets,
  services an Application PTO probe through the same lifecycle owner, confirms
  the client through the OpenSSL-backed `handshake_confirmed` callback after
  OpenSSL recv/release consumes inbound Handshake CRYPTO,
  discards the client Handshake packet-number space and keys through a
  lifecycle-owned backend-confirmed no-output Handshake drive, and uses the
  server connection probe to pull real pair-transcript 1-RTT secrets, confirm
  the server connection, record OpenSSL secret callbacks plus peer stream-count
  limits from the applied transport parameters, and discard its Handshake packet-number
  space and keys. The
  paired loopback server also consumes client Handshake CRYPTO over loopback
  UDP, pulls peer transport parameters and Handshake/1-RTT secrets through the
  backend, confirms, and clears its Handshake keys; the direct server probe
  also consumes Handshake CRYPTO and reports `server_probe_confirmed=true`
  before protected close and route cleanup
  through one socket/lifecycle loop owner. The adapter output also prints that
  the consumed transcript transport-parameter bytes match the connection-applied
  peer bytes, plus transcript keylog evidence and the current wrapper keylog
  boundary.
  A full endpoint-owned live TLS handshake/socket loop is still pending.

## License

MIT
