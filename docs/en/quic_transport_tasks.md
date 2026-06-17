# QUIC transport implementation tasks

`quicz` aims to implement the IETF QUIC transport protocol in Zig. This task
plan converts that goal into verifiable work items that can be implemented and
tested incrementally.

## Scope

`quicz` tracks the IETF QUIC standards, but the practical implementation target
is not every optional protocol feature. Internal comparison against mature QUIC
stacks is used only to extract a common transport capability baseline. The
first usable target is QUIC v1 transport with TLS integration, client/server
endpoints, stream I/O, transport-parameter configuration, packet/timer driving,
loss recovery, congestion behavior, and interop.

Optional extensions such as HTTP/3, DATAGRAM, qlog, PMTU/GSO, QUIC v2, or
other extensions are useful to track, but they are not prerequisites for the
first interoperable `quicz` transport milestone.

Implementation strategy: do not reimplement mature, non-core capabilities
when a maintained library can be adapted cleanly. `quicz` owns QUIC transport
state, packet processing, recovery, endpoint lifecycle, and the public Zig API.
TLS, HTTP/3/QPACK, qlog, platform socket acceleration such as GSO/GRO, and
other mature adjunct capabilities should be integrated through narrow adapters
unless there is a documented reason that no suitable library can meet the
transport boundary.

The first implementation scope remains the QUIC transport core:

- RFC 8999: Version-Independent Properties of QUIC
- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control

Deferred standards and extensions, except already implemented QUIC v2
packet/key/token and RFC 9368 version-information primitives:

- Full QUIC v2 behavior, RFC 9369
- Full Compatible Version Negotiation, RFC 9368
- QUIC DATAGRAM, RFC 9221
- HTTP/3 and QPACK
- Multipath and other in-progress QUIC WG drafts

## Practical Transport Baseline

| Feature | Practical target | quicz status |
| --- | --- | --- |
| UDP client/server endpoint | Required for first usable milestone. One endpoint owner must drive accept/connect, packet receive/send, timers, route cleanup, and close. | Partial: socket-backed loopback examples, endpoint lifecycle helpers, and core socket-loop entrypoints for receive, accepted Initial backend response/close propagation, bounded long-header CRYPTO output draining, pending-work, due-deadline, TLS-backend drive, output polling, close propagation, compatible-version backend drive, and wakeup selection exist; production client/server event loop is missing. |
| TLS 1.3 integration | Required. Use a C TLS library with QUIC transport-parameter and traffic-secret hooks through a narrow Zig `TlsBackend` adapter. Do not implement TLS in-tree. | Partial: mock `CryptoBackend`, installed-key handoff, a tested C-ABI `TlsBackend` adapter, a C-object adapter probe, an OpenSSL QUIC TLS API/link probe, an OpenSSL client/server callback-mode transcript check with level-separated CRYPTO handoff mapped into quicz CRYPTO queues, role-specific peer transport-parameter byte parsing, keylog callback count/byte evidence without printing key material, protected Initial long-packet delivery plus socket-backed Initial delivery and manual OpenSSL Initial/Handshake transcript plus same-context 1-RTT STREAM echo, Handshake key discard, protected close, and route cleanup through the same socket/lifecycle boundary, installed-key protected Handshake delivery plus socket-backed Handshake delivery using OpenSSL-produced Handshake secrets, installed-key protected STREAM request/response plus socket-backed STREAM echo using OpenSSL-produced 1-RTT secrets, and an OpenSSL-backed adapter wrapper that emits the first TLS CRYPTO flight, consumes the pair-transcript server transport parameters, delivers real pair-transcript Handshake/1-RTT secrets and inbound CRYPTO through OpenSSL callback boundaries, routes adapter-generated Initial CRYPTO and real pair-transcript Handshake CRYPTO over loopback UDP as protected Initial/Handshake datagrams, drives loopback UDP 1-RTT STREAM echo, Application PTO service, protected close delivery, and route cleanup through one socket/lifecycle loop owner with adapter-installed client keys plus matching peer transcript secrets, proves direct server-probe confirmation after Handshake CRYPTO consumption, proves server-connection backend 1-RTT pull, OpenSSL secret callbacks, applied peer stream-count limits, handshake confirmation, and Handshake-space/key discard, and drives paired loopback server confirmation through backend-consumed Handshake CRYPTO plus peer transport-parameter and Handshake/1-RTT secret pull; full endpoint-owned live TLS handshake/socket loop is missing. |
| QUIC v1 packet protection | Required. Initial, Handshake, 0-RTT when enabled, and 1-RTT packets must be produced and consumed by the TLS-owned path. | Partial: v1/v2 Initial, Retry integrity, protected long/short helpers, and mock installed-key paths exist. |
| Streams | Required. Bidirectional and unidirectional stream open, read, write, FIN, reset, STOP_SENDING, and stream limits must work over protected UDP. | Partial: in-memory stream state and protected loopback exercises exist; TLS-owned UDP stream API is missing. |
| Flow control | Required. Connection, stream, and stream-count flow control must work over protected UDP. | Partial: frame-payload and protected loopback coverage exists; full socket-owned path is missing. |
| ACK/loss/PTO recovery | Required. ACK processing, packet/time-threshold loss, PTO, retransmission, and timer service must drive the endpoint loop. | Partial: deterministic recovery model and socket-backed loopbacks exist; socket-owned protected-packet lifecycle integration is incomplete. |
| Congestion control | Required at least at a NewReno-style baseline. CUBIC or configurable controllers are later performance work. | Partial: simplified NewReno-style behavior exists; production tuning and configurable controllers are missing. |
| Connection IDs and stateless reset | Required. Routing, CID issuance/retirement, reset-token handling, close cleanup, and inactive-CID reset emission must work in the endpoint lifecycle. | Partial: endpoint router, lifecycle helpers, and socket-backed loopbacks exist; full TLS-owned lifecycle integration is missing. |
| Retry and address validation | Required for server-side robustness and interop. | Partial: token policy, Retry validation, address-validation loopbacks, and TLS extension byte checks exist; production storage/replay policy is missing. |
| Path validation and migration | Required for single-path validation and route update; full multipath is out of scope. | Partial: PATH_CHALLENGE/PATH_RESPONSE and route-update loopbacks exist; production path policy is incomplete. |
| 0-RTT | Schedule after the first 1-RTT stream echo interop gate; not required for the current milestone. | Partial: explicit accept/reject and mock installed-key 0-RTT paths exist; real TLS replay policy is missing. |
| RFC 9221 DATAGRAM | Optional extension, not part of the first transport milestone. | Deferred. |
| HTTP/3 and QPACK | Application-layer work after the transport is interoperable. | Deferred. |
| QUIC v2 and RFC 9368 compatible version negotiation | Optional extension unless a selected interop target requires it. | Partial primitives exist; full behavior is deferred. |
| qlog, PMTU discovery, GSO/GRO, advanced congestion selection | Operational/performance extensions after the transport loop works. | Deferred or missing. |
| External interop | Required to claim the first usable transport milestone. | Missing. |

## RFC Coverage Status

Status values are `Done`, `Partial`, `Missing`, and `Deferred`. `Partial`
means the repository has code and tests for part of the area, but the
remaining behavior still appears in the task matrix below.

| Standard area | Status | Current evidence | Remaining proof |
| --- | --- | --- | --- |
| RFC 8999 version-independent properties | Partial | Version Negotiation packet codec, endpoint unsupported-version Version Negotiation response helper, client-side Version Negotiation packet validation/selection state, reserved-version greasing detection/selection skip, long/short packet envelopes, connection ID length checks including first-client-Initial DCID length enforcement, stateless reset helpers, packet codec/example tests, and socket-backed UDP endpoint routing loopback with client-side Version Negotiation selection plus protected follow-up Initial emission. | Full TLS-owned socket-backed packet routing and interop must prove complete version-independent behavior. |
| RFC 9000 transport protocol | Partial | Frame codec with ACK/ACK_ECN range validation, transport parameters, connection state, streams, flow control, connection IDs, Retry/tokens, path validation, close/reset behavior, endpoint idle route/timer cleanup, endpoint routing helpers, lifecycle-owned caller-keyed protected UDP packet loopback, socket-backed UDP path-validation route-update loopback, socket-backed UDP lifecycle Retry/address-validation loopback, and examples. | Full protected/TLS socket-backed client/server loopback, complete endpoint lifecycle, and external interop. |
| RFC 9001 TLS and packet protection | Partial | QUIC v1 Initial secret derivation, AEAD/header-protection helpers, Retry Integrity Tag, protected packet helpers, mock CRYPTO backend handoff, installed-key tests, and ACK-gated installed-key key-update initiation. | Real TLS backend transcript integration, TLS-owned traffic-secret production, remaining automatic key discard, and full TLS-owned live key-update scheduling/old-key discard. |
| RFC 9002 loss detection and congestion control | Partial | Invalid ACK/ACK_ECN range rejection before recovery side effects, largest-acknowledged RTT sampling, connection-level RTT estimate sharing and PTO backoff across packet number spaces with client Initial ACK reset suppression, Initial/Handshake RTT ACK-delay suppression plus Application ACK delay scaling/capping, packet/time-threshold loss, aggregate loss-time-before-PTO timer deadline selection/service with closing/draining disarm, anti-amplification-limited server PTO disarm/rearm plus expired-PTO service when new datagrams unblock sending, and client no-in-flight anti-deadlock PTO, endpoint-owned multi-connection recovery timer scheduling, cross-space bytes-in-flight congestion admission, peer max_udp_payload_size recovery max_datagram_size/initial-cwnd resync, endpoint connection lifecycle helper tying route retirement to timer disarm plus caller-keyed protected long/Initial-Handshake CRYPTO-space/0-RTT/short-packet, explicit key-phase/key-update short-packet, caller-owned key-phase short-packet, installed-key Handshake/0-RTT long-packet, and installed-key protected short-packet timer refresh, congestion-window bypass for one armed PTO probe, ACK-driven frame-payload STREAM/CRYPTO, protected CRYPTO, protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission requeue, and ACKed RESET_STREAM obsolete retransmission suppression, NewReno slow-start/congestion-avoidance byte-counted and batched-ACK growth with underutilized-cwnd suppression, recovery-period behavior, new-congestion-event one-packet recovery probe, and minimum-window ssthresh clamp, PTO-backoff-independent persistent congestion duration/response with min-RTT refresh, recovery-period reset/re-entry, and non-contiguous suppression, ACK_ECN CE-driven NewReno recovery response, packet-space PTO PING/new-data/in-flight-CRYPTO/protected-0-RTT-control/protected-0-RTT-STREAM/in-flight-STREAM/cross-space probe hooks with Initial/Handshake max_ack_delay suppression and Application PTO gating until handshake confirmation, ECN validation and lifecycle-owned UDP-path mirroring tests, and socket-backed UDP lifecycle loss/PTO recovery plus lifecycle congestion-recovery/lifecycle STREAM-retransmission loopbacks. | Full TLS-owned socket-owned protected-packet loss/PTO timer lifecycle integration and remaining NewReno edge cases with controlled-clock tests. |
| RFC 9221 QUIC DATAGRAM | Deferred | Explicitly outside the first transport-core scope. | Track separately after the core transport loop is functional. |
| RFC 9368 compatible version negotiation | Partial | `version_information` transport parameter codec, explicit directional first-flight compatibility relation helpers for compatible-version selection, connection-level export/application validation including post-VN server Version Information downgrade checks, server-side compatible Version Information apply/byte/close paths and backend-driven compatible peer transport-parameter handoff with peer Version Information snapshots, parsed `version_information` semantic close classification to `VERSION_NEGOTIATION_ERROR`, reserved Available Versions accepted but never selected, `VERSION_NEGOTIATION_ERROR` code, client-side incompatible VN packet validation/selection state, VN follow-up config propagation, lifecycle-owned old-attempt route/timer retirement, follow-up Initial route registration, endpoint-owned follow-up connection handoff, and lifecycle-owned protected follow-up Initial emission are present. | Full incompatible/compatible negotiation state machine, TLS-owned socket retry-loop integration, and interop. |
| RFC 9369 QUIC v2 | Partial | Version constant, long-header packet type bit mapping, configured v2 protected long-packet and Retry wire-version use, Retry packet codec mapping, v2 Retry Integrity Tag helpers, address-validation token originating-version binding, RFC 9368 `version_information` transport-parameter support, and RFC 9369 Initial salt plus `quicv2` packet-protection label derivation with Appendix A.1/A.4 vectors. | Remaining full compatible version negotiation state, endpoint routing, TLS-owned packetization, and interop. |
| HTTP/3 and QPACK | Deferred | Application protocols are outside this transport-core plan. | Start separate application-layer tasks after transport interop. |

The current codebase is still an experimental frame-payload transport skeleton.
`pollTx` and `processDatagram` move unencrypted QUIC frame payload bytes. The
connection layer now has a narrow Initial/Handshake CRYPTO/ACK/PING protected
long-packet coalesced send/receive bridge, installed-key Handshake long-packet
helpers, first-client-Initial DCID length and server-Initial token validation,
caller-keyed or installed-key 0-RTT STREAM/RESET_STREAM/STOP_SENDING protected long-packet routing, and caller-keyed 1-RTT protected
short-packet PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge with caller-owned and connection-installed key-phase state helpers, plus socket-backed UDP endpoint routing, lifecycle Retry/address-validation routing, lifecycle caller-keyed protected packet/lifecycle loss-recovery/lifecycle congestion-recovery/lifecycle PTO-recovery/lifecycle STREAM-retransmission loopbacks, and validation-driven UDP path-validation route updates, but it does not yet fully
produce or consume TLS-owned QUIC packets over UDP.

## Current Phase Boundary

As of 2026-06-04, the current implementation phase is the
mock/installed-key plus endpoint-lifecycle verification phase. This phase has
enough evidence to show that the transport skeleton can route protected
datagrams over real loopback UDP sockets, preserve endpoint-owned route/timer
lifecycle state, exercise caller-owned and installed-key packet protection,
service loss/PTO recovery timers, and prove key-update, path-validation, Retry,
address-validation, close, and stateless-reset behavior with deterministic
examples.

This phase is intentionally not a complete QUIC implementation. The evidence
does not prove a real TLS-owned client/server handshake, TLS-owned traffic
secret production, automatic TLS transcript-driven key lifecycle, external
interop, or a production socket event loop. Until those exist, all RFC 8999,
RFC 9000, RFC 9001, RFC 9002, RFC 9368, and RFC 9369 rows that depend on those
properties must remain `Partial` rather than `Done`.

The main task remains the IETF QUIC transport implementation. The next-stage
direction refines execution order and evidence requirements without replacing
the transport task matrix below: prioritize the endpoint-owned live TLS
handshake/socket loop first, then the embeddable socket API, minimal interop
entry, and TLS/interop observability.

The next implementation milestone is an endpoint-owned live TLS
handshake/socket loop. The minimum proof for that milestone is:

- a C TLS library backend that exposes QUIC transport-parameter and traffic
  secret hooks through a small Zig `TlsBackend` adapter, rather than a new
  in-tree TLS implementation;
- real TLS backend integration that exports and consumes QUIC transport
  parameters through the handshake transcript;
- TLS-owned Initial, Handshake, 0-RTT when enabled, and 1-RTT traffic-secret
  installation without caller-provided mock keys on the happy path;
- a local UDP client/server stream echo that drives connection accept,
  handshake confirmation, stream data delivery, ACK cleanup, loss/PTO timer
  service, key discard, close, and route cleanup through one lifecycle owner;
- adapter evidence from `run-tls-backend-adapter`, `run-tls-c-abi-adapter`,
  `run-tls-openssl-probe`, and `run-tls-openssl-backend-adapter`, plus
  `zig build test --summary all`;
- an interop note against at least one external QUIC implementation or a
  documented blocker explaining why interop cannot yet be run.

After the echo path, keep the transport core embeddable instead of baking
production socket policy into demos. The lifecycle core now exposes the first
socket-facing and TLS-backend loop API shape: `feedDatagram`, `feedDatagramWithInstalledKeys`,
`feedDatagramWithInstalledKeysAcrossConnections`,
`feedDatagramWithInstalledKeysAndSelectNextDeadline`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndSelectNextDeadline`,
`feedDatagramWithInstalledKeysAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndPollDatagram`,
`feedDatagramWithInstalledKeysAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDrainDatagrams`,
`processAcceptedProtectedInitialWithCryptoBackendAndPollDatagram`,
`processAcceptedProtectedInitialWithCryptoBackendOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagram`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`,
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
`processPendingWork`,
`processPendingWorkAcrossConnections`, `processPendingWorkAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndSelectNextDeadline`,
`processPendingWorkAcrossConnectionsAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndDrainDatagrams`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndSelectNextDeadline`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`,
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`,
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
`processPendingWorkAndDrainDatagrams`,
`processDueDeadlineAndPollDatagram`,
`processDueDeadlineAndDrainDatagrams`,
`processDueDeadlineAndSelectNextDeadline`,
`processDueDeadlineAcrossConnectionsAndSelectNextDeadline`,
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
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndSelectNextDeadline`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
`pollDatagram`, `drainDatagramsAcrossConnections`,
`pollDatagramAcrossConnections`, `driveCryptoBackendsInSpaceAndArmConnections`,
`driveCryptoBackendsInSpaceAndSelectNextDeadline`,
`driveCryptoBackendInSpaceAndSelectNextDeadline`,
`driveCryptoBackendsInSpaceAndPollDatagram`,
`driveCryptoBackendsInSpaceAndDrainDatagrams`,
`driveCryptoBackendsInSpaceOrCloseAndArmConnections`,
`driveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline`,
`driveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`,
`driveCryptoBackendsInSpaceOrCloseAndPollDatagram`,
`driveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`,
`driveCryptoBackendsInSpaceWithCompatibleVersionAndArmConnections`,
`driveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline`,
`driveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline`,
`driveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`,
`driveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`,
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndArmConnections`,
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`,
`driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`,
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`,
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`,
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
`nextDeadline`, and
`nextDeadlineAcrossConnections`, with one lifecycle owner responsible for
timers, route cleanup, close, installed-key packet receive, cross-connection
receive dispatch, cross-connection pending-work sweep, due-deadline service,
cross-connection due-deadline dispatch, recovery-wakeup packet output,
installed-key packet output, bounded caller-owned output draining,
cross-connection output dispatch, receive-to-next-deadline loop steps,
cross-connection pending-work-to-output loop
steps, cross-connection pending-work-to-next-deadline loop steps,
cross-connection pending-work-to-bounded-drain loop steps,
cross-connection due-deadline-to-next-deadline loop steps,
receive-to-output loop steps,
receive-to-bounded-drain loop steps,
receive-to-backend-to-output loop steps,
receive-to-backend-to-bounded-drain loop steps, cross-connection TLS backend drive, backend-drive-to-datagram output steps,
backend-drive-to-next-deadline loop steps,
backend-drive-to-bounded-drain output steps,
backend-drive-to-caller-keyed long-header drain steps,
close-propagating backend-drive-to-caller-keyed long-header drain steps,
caller-keyed receive-to-backend-to-bounded-drain loop steps,
caller-keyed receive-to-backend-close-to-bounded-drain loop steps,
routed caller-keyed receive-to-backend-to-bounded-drain loop steps,
routed caller-keyed receive-to-backend-close-to-bounded-drain loop steps,
installed-key Handshake receive-to-backend-to-bounded-drain loop steps,
close-propagating installed-key Handshake backend-drain loop steps,
routed installed-key 1-RTT receive-to-bounded-drain loop steps,
single-connection installed-key receive-to-backend-to-output loop steps,
single-connection installed-key receive-to-backend-to-bounded-drain loop steps,
single-connection installed-key receive-to-backend-close-to-output loop steps,
single-connection installed-key receive-to-backend-close-to-bounded-drain loop steps,
single-connection compatible-version receive-to-backend-to-output loop steps,
single-connection compatible-version receive-to-backend-close-to-output loop steps,
single-connection pending-work-to-backend-to-output loop steps,
single-connection pending-work-to-backend-to-bounded-drain loop steps,
single-connection pending-work-to-backend-close-to-output loop steps,
single-connection pending-work-to-backend-close-to-bounded-drain loop steps,
single-connection compatible-version pending-work-to-backend-to-output loop steps,
single-connection compatible-version pending-work-to-backend-close-to-output loop steps,
single-connection due-deadline-to-backend-to-output loop steps,
single-connection due-deadline-to-backend-close-to-output loop steps,
single-connection compatible-version due-deadline-to-backend-to-output loop steps,
single-connection compatible-version due-deadline-to-backend-close-to-output loop steps,
single-connection due-deadline-to-backend-to-bounded-drain loop steps,
single-connection due-deadline-to-backend-close-to-bounded-drain loop steps,
close-propagating TLS backend drive,
RFC 9368 compatible-version backend sweeps, pending-work-to-backend-to-output
loop steps, pending-work-to-bounded-drain loop steps,
pending-work-to-backend-to-bounded-drain loop steps,
due-deadline-to-backend-to-output loop steps,
due-deadline-to-bounded-drain loop steps,
due-deadline-to-backend-to-bounded-drain loop steps,
cross-connection due-deadline terminal-cleanup backend suppression, and
event-loop wakeup selection across caller-owned connection maps.
`EndpointConnectionDeadline.installedKeyPollOptions()`
maps recovery wakeups returned by `nextDeadline()` into installed-key poll
options for Handshake and 1-RTT paths. Production socket policy, full
TLS-owned handshake driving, and live key lifecycle remain pending. The first
interop entry should handle only `handshake` and `transfer` and return explicit
blockers until real TLS-owned binaries exist. Real TLS and interop paths must
also emit enough evidence for debugging, including keylog support and trace
events for handshake, transport parameters, traffic-secret installation,
packet-number spaces, ACK/loss/PTO, key discard, close, and route cleanup.

Further mock-only loopbacks are useful only when they close a specific gap in
the matrix below. They should not be treated as progress toward completing
QUIC unless the gap is named and the verification evidence is added here.

## Task Matrix

| Area | Current status | Required outcome | Verification |
| --- | --- | --- | --- |
| Standard tracking | Core/deferred RFC coverage table present | Keep each core RFC area marked as done, partial, missing, or deferred as implementation moves. | Markdown review plus `zig build test`. |
| RFC 8999 / 9000 packet codec | Partial with v2 type-bit awareness + endpoint unsupported-version VN response helper + client-side VN selection/follow-up route and connection handoff state | Complete version-independent packet handling, version negotiation, Retry, long and short headers, packet number handling, and transport error values. | Existing tests cover v1/v2 long-header packet type bit mapping, Retry codec mapping, reserved-version greasing detection/selection skip, Version Negotiation response CID echoing, client-side VN CID validation, Original Version ignore, mutual-version selection, follow-up config derivation, follow-up Initial route registration, follow-up connection handoff, first-client-Initial DCID length checks, server-Initial token rejection, Initial UDP datagram 1200-byte expansion/discard checks, roundtrip, boundary, truncation, invalid-value, and allocation-failure behavior; `run-codec` prints reserved-version skip evidence and `run-udp-endpoint-loopback` proves socket-backed endpoint routing for Version Negotiation, client-side VN selection, lifecycle-owned follow-up route replacement and connection handoff, and Initial classification. |
| RFC 9000 frame codec | Frame set present + shortest frame-type varint validation + ACK/ACK_ECN range validation with explicit close propagation + unknown type rejection + packet-type validation including 0-RTT ACK/ACK_ECN rejection + ACK/ACK_ECN unsent-packet rejection, MAX_STREAMS/STREAMS_BLOCKED count overflow, STREAM/RESET_STREAM/PATH_RESPONSE, conflicting STREAM data, STOP_SENDING/MAX_STREAM_DATA/STREAM_DATA_BLOCKED stream-control validation, NEW_CONNECTION_ID limit/reuse, RETIRE_CONNECTION_ID unknown/unsent, and role-specific NEW_TOKEN/HANDSHAKE_DONE semantic close classification with explicit close propagation | Cover all RFC 9000 transport frames with strict value validation and stable error mapping. | Per-frame encode/decode tests for valid, truncated, invalid, unknown inputs, and ACK/ACK_ECN ranges that would compute negative packet numbers; connection-level ACK/ACK_ECN processing rejects the same invalid ranges before recovery side effects; `frameDecodeErrorCode()` maps malformed frame decode failures to `FRAME_ENCODING_ERROR`; `framePacketTypeErrorCode()` maps syntactically valid frames in forbidden packet types to `PROTOCOL_VIOLATION`; `processDatagramOrClose()`, `processDatagramInSpaceOrClose()`, `processDatagramForPacketTypeOrClose()`, and protected long/short `*OrClose` receive wrappers, including direct and routed `EndpointConnectionLifecycle` variants, queue CONNECTION_CLOSE for classified frame-payload errors while the older receive APIs keep rollback-only behavior; tests cover invalid ACK/ACK_ECN range close propagation, 0-RTT ACK/ACK_ECN packet-type close propagation, ACK/ACK_ECN frames that acknowledge unsent packet numbers, flow-control, MAX_STREAMS/STREAMS_BLOCKED overflow, stream-limit, stream-control stream-state and stream-count failures, final-size, conflicting STREAM data, unmatched PATH_RESPONSE, active connection-ID limit overflow, legal replacement under `retire_prior_to`, duplicate NEW_CONNECTION_ID preservation, NEW_CONNECTION_ID sequence/CID mismatch, cross-sequence CID reuse rejection, reset-token reuse, RETIRE_CONNECTION_ID unknown/unsent close propagation, sent-CID retirement accept, server-received NEW_TOKEN, and server-received HANDSHAKE_DONE semantic close propagation. |
| Transport parameters | Typed codec + reserved-parameter greasing helper/ignore + connection exposure + preferred_address export/application + RFC 9368 `version_information` export/application validation, including VN-triggered server downgrade checks, server-side compatible Version Information apply/byte paths, peer Version Information snapshots, and `VERSION_NEGOTIATION_ERROR` close classification for parsed version-negotiation semantic failures + TLS extension byte encode/apply + CryptoBackend byte handoff plus strict, compatible, and close-propagating peer-parameter drive with selected-version progress reporting + configured local ACK delay export separated from peer recovery policy + peer max_udp_payload_size recovery resync + codec error classification and explicit close propagation to `TRANSPORT_PARAMETER_ERROR` | Add full TLS backend transcript handshake integration for exported parameters and full version-negotiation state ownership. | Existing roundtrip, reserved/unknown parameter ignore, duplicate/invalid parameter, connection apply/export, TLS extension byte encode/apply, mock-backend local/peer byte handoff, server preferred_address, `version_information`, VN-triggered downgrade checks, compatible-version selection apply, peer Version Information snapshot, default-value, local-vs-peer ACK delay, max_udp_payload_size-driven recovery resync, and `transportParameterErrorCode()` tests cover the codec and connection surface; `applyPeerTransportParameterBytesOrClose()` and `driveCryptoBackendInSpaceOrClose()` tests cover malformed extension, invalid peer-parameter close emission, and parsed RFC 9368 version-negotiation semantic close emission while the older apply/drive APIs keep rollback-only behavior; `driveCryptoBackendInSpaceWithCompatibleVersion*()` tests cover backend-driven compatible Version Information selection, selected-version progress reporting, and close emission before backend output is pulled; `run-transport-parameters` prints reserved-parameter ignore, compatible-version selection, peer Version Information snapshot, recovery datagram-size/cwnd, and transport-parameter auto-close evidence; `run-crypto-stream` prints protected backend transport-parameter auto-close and compatible Version Information handoff evidence from backend progress; `run-codec` prints transport-parameter close-code classification and `downgrade_close=0x11`; later real TLS backend and endpoint tests prove transcript integration and full version negotiation. |
| Connection state machine | Partial close-state + peer close diagnostics + idle timeout + explicit handshake progress state | Model Initial, Handshake, 0-RTT, 1-RTT, idle timeout, closing, draining, and closed states. | Existing tests cover close/drain transitions, closing/draining inbound datagram discard without parsing, peer close diagnostics, close expiry, idle expiry, endpoint lifecycle route/timer cleanup after idle and close timeout expiry, handshake progress from Initial to Handshake to Confirmed, and invalid-packet rollback; `run-udp-close-lifecycle-loopback` prints socket-backed protected close/drain state, close-deadline evidence, and timeout-driven route cleanup evidence; later protected-packet tests cover key-state transitions. |
| Packet number spaces | Partial frame-payload ACK/recovery + CRYPTO isolation and receive reassembly + Initial/Handshake protected CRYPTO/ACK/PING/CONNECTION_CLOSE coalesced send/receive bridge plus installed-key Handshake CONNECTION_CLOSE emission with first-client-Initial DCID length, server-Initial token validation, and RFC 9000 Initial UDP datagram size checks + caller-keyed or installed-key 0-RTT protected long STREAM/RESET_STREAM/STOP_SENDING routing + 1-RTT protected short PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge + frame-type filtering + RFC 9001 Initial discard after client Handshake send/server Handshake receive + discard cleanup that clears installed Handshake keys and ECN state + valid client-side HANDSHAKE_DONE-triggered, server-side sendHandshakeDone-triggered, backend-confirmed no-output, and backend-confirmed post-final-outbound-CRYPTO Handshake-space discard | Maintain distinct Initial, Handshake, and Application packet number spaces, then route protected packets into the matching space with the remaining TLS-triggered key discard rules. | Existing ACK/recovery, CRYPTO isolation, out-of-order CRYPTO receive, Initial/Handshake protected send/receive including first-client-Initial DCID rejection, server-Initial token rejection, caller-keyed Initial/Handshake and installed-key Handshake close emission, Initial UDP datagram 1200-byte expansion/discard checks, coalesced send/receive, caller-keyed and installed-key 0-RTT protected STREAM/RESET_STREAM/STOP_SENDING, 1-RTT protected PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive, forbidden-frame, RFC 9001 Initial discard, explicit discard, installed Handshake key cleanup, ECN state cleanup, and valid HANDSHAKE_DONE/backend-confirmed cleanup tests prove isolation and cleanup between spaces; later protected endpoint tests prove full routing. |
| Real datagram API | Initial/Handshake protected CRYPTO/ACK/PING/CONNECTION_CLOSE coalesced send/receive bridge with first-client-Initial DCID length, server-Initial token validation, and RFC 9000 Initial UDP datagram size checks + lifecycle-owned caller-keyed protected Initial/1-RTT short socket loopback + caller-keyed or installed-key 0-RTT protected long STREAM/RESET_STREAM/STOP_SENDING routing + protected 1-RTT short PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge + caller-owned and ACK-gated installed-key key-phase state 1-RTT short-packet bridge + configurable single-path spin-bit policy + protected long/short-packet helper + in-memory endpoint DCID/IPv4-tuple router + socket-backed endpoint routing loopback for VN/protected follow-up Initial/Initial/short-header classification + socket-backed zero-length CID tuple-routing loopback + socket-backed preferred-address route-migration loopback + socket-backed replacement-CID route-retirement loopback + socket-backed lifecycle connection-ID NEW/RETIRE loopback + socket-backed lifecycle ECN ACK_ECN validation/CE response loopback + socket-backed lifecycle flow-control credit-refresh loopback + socket-backed lifecycle loss-recovery loopback + socket-backed lifecycle congestion-recovery loopback + socket-backed lifecycle PTO recovery loopback + socket-backed lifecycle STREAM retransmission loopback + socket-backed lifecycle installed-key key-update loopback + socket-backed path-validation route-update loopback + socket-backed lifecycle Retry/address-validation loopback + socket-backed close-triggered route retirement + zero-length CID tuple routing + sequence/retire-prior-to route retirement + endpoint reset-token uniqueness checks + caller-validated path update + validation-driven PATH_RESPONSE route update + retired-CID stateless reset token lookup/datagram construction + socket-backed retired-CID stateless reset emission loopback + route/reset/drop receive classification | Add protected QUIC datagram receive/transmit APIs above the existing frame-payload skeleton. | Existing helper tests cover protected Initial packets, protected short-packet roundtrip, key-phase short-packet selection, protected long-packet boundary peeking, endpoint DCID routing including zero-length CID tuple routing, sequence/retire-prior-to route retirement, endpoint reset-token reuse rejection, caller-validated path updates, validation-driven PATH_RESPONSE route update, stateless reset token lookup/datagram construction after route retirement, endpoint receive action classification, lifecycle-owned ECN path-state mirroring, and lifecycle-owned issue/register replacement-CID route updates; `examples/udp_endpoint_loopback.zig` covers real loopback UDP Version Negotiation response delivery, protected follow-up Initial emission and server processing, supported Initial accept, client Initial SCID response routing, and server Initial SCID short-header routing; `examples/udp_zero_cid_loopback.zig` covers real loopback UDP short and long datagram routing for zero-length destination CIDs by local/remote tuple, path-specific retirement, and route path update; `examples/udp_preferred_address_loopback.zig` covers real loopback UDP preferred-address migration commit, current-route retirement, preferred CID routing on the preferred server address, active-migration-disabled rejection on a stray path, and retained reset-token lookup after retirement; `examples/udp_replacement_cid_loopback.zig` covers real loopback UDP replacement-CID registration with `retire_prior_to`, inactive reset-token lookup for retired sequence routes, active replacement CID routing, invalid sequence rejection, and active-migration-disabled rejection on a stray path; `examples/udp_connection_ids_loopback.zig` covers real loopback UDP lifecycle-routed protected NEW_CONNECTION_ID delivery, lifecycle-owned issue/register endpoint route replacement for a newly issued CID, inactive old-CID reset-token lookup, lifecycle-routed protected RETIRE_CONNECTION_ID through the active replacement CID, server-side local CID retirement, and lifecycle-routed ACK cleanup; `examples/udp_flow_control_loopback.zig` covers real loopback UDP lifecycle-owned protected STREAM delivery to the receive limit, protected STREAM_DATA_BLOCKED routing, receive-side MAX_DATA/MAX_STREAM_DATA credit refresh delivery, resumed STREAM data with FIN final-size evidence, and final ACK cleanup; `examples/udp_ecn_validation_loopback.zig` covers real loopback UDP delivery of a modeled ECT(0) protected PING, protected ACK_ECN validation, ACK_ECN CE-driven NewReno recovery response, `EndpointConnectionLifecycle` ECN state update for that UDP tuple, and migrated-path ECN isolation without claiming real IP-header ECN marking; `examples/udp_loss_recovery_loopback.zig` covers real loopback UDP protected short PING delivery followed by protected ACK-driven packet-threshold loss, lifecycle timer-driven time-threshold cleanup, and final timer disarm; `examples/udp_congestion_recovery_loopback.zig` covers real loopback UDP lifecycle-owned protected short PING/ACK routing followed by NewReno recovery-period suppression of repeated loss reduction and persistent congestion reduction to the minimum congestion window; `examples/udp_pto_recovery_loopback.zig` covers real loopback UDP lifecycle timer service plus protected short probe polling after ACK loss, protected PING fallback probe delivery, queued STREAM data and in-flight STREAM/CRYPTO data as PTO probes, duplicate receive/CRYPTO range discard, ACK cleanup, and final timer disarm; `examples/udp_stream_retransmission_loopback.zig` covers lifecycle-owned route selection for ACK-driven 1-RTT STREAM retransmission and final ACK cleanup over real loopback UDP; `examples/udp_key_update_loopback.zig` covers real loopback UDP lifecycle-owned installed-key key update initiation, next key-phase packet routing, peer key-phase advancement after authenticated receive, ACK delivery, key-update ACK gating, and second-update re-enable; `examples/udp_protected_loopback.zig` covers lifecycle-owned real loopback UDP protected client Initial route registration, protected server Initial routing, routed client 1-RTT PING, and routed server 1-RTT ACK with caller-supplied keys; `examples/udp_path_validation_loopback.zig` covers real loopback UDP PATH_CHALLENGE delivery to a new peer port, PATH_RESPONSE routing with `path_changed`, validation-driven lifecycle route path update, and confirmed routing on the new path; `examples/udp_retry_loopback.zig` covers lifecycle-owned real loopback UDP Retry delivery, Retry Source CID route switching, address-bound Retry token validation, replay rejection, follow-up protected Initial routing, and Retry transport-parameter checks; `examples/udp_close_lifecycle_loopback.zig` covers protected close delivery over UDP, connection-handle route retirement, retained inactive-CID reset-token lookup, reset emission, and client-side token matching; `examples/udp_stateless_reset_loopback.zig` covers real loopback UDP reset-trigger receive classification, server reset emission, and client-side token matching; connection tests cover protected Initial/Handshake CRYPTO, protected Initial/Handshake CONNECTION_CLOSE, first-client-Initial DCID rejection, server-Initial token rejection, Initial UDP datagram 1200-byte expansion/discard checks, ACK-only, PING, caller-keyed and installed-key 0-RTT STREAM/RESET_STREAM/STOP_SENDING, coalesced send/receive, protected 1-RTT PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive, installed-key short PING/ACK exchange, installed-key ACK-gated key-update initiation, key-phase-state PING receive with failure-state preservation, and enabled/disabled spin-bit state updates with invalid-packet preservation; later socket-backed client/server loopback must use TLS-owned keys and endpoint lifecycle ownership. |
| TLS integration | CRYPTO bridge hooks with per-space out-of-order receive buffering, receive-buffer limit close propagation, plus a pluggable backend drive helper, transport-parameter byte handoff plus strict, compatible, and protected close-propagating peer-parameter drives, selected compatible-version progress reporting, mock Handshake/0-RTT/1-RTT traffic-secret handoff, C-ABI `TlsBackend` to `CryptoBackend` adapter, backend-confirmed no-output and post-final-outbound-CRYPTO Handshake discard, socket-backed mock CryptoBackend Handshake CRYPTO stream loopback, explicit installed-key 0-RTT accept/reject, modeled 0-RTT discard at 1-RTT boundaries, OpenSSL callback-mode transcript evidence including copied role-specific peer transport-parameter bytes plus manual Initial/Handshake transcript, same-context 1-RTT STREAM echo, Handshake key discard, protected close, and route cleanup through the socket/lifecycle boundary, and OpenSSL-backed adapter wrapper evidence present; full endpoint-owned live TLS handshake/socket loop missing | Use a pluggable TLS backend interface driven by CRYPTO frames, with the concrete C TLS library kept outside the transport core. | Existing mock-backend and `TlsBackend` adapter tests cover CRYPTO delivery, CRYPTO receive-buffer limit rejection and close emission, local/peer transport-parameter byte handoff, compatible backend Version Information handoff with selected-version progress, C-ABI status-code/output-buffer adaptation into `driveCryptoBackendInSpace()`, backend output queuing and preservation, invalid peer transport-parameter rejection without output, invalid peer transport-parameter close emission without output, protected Handshake CONNECTION_CLOSE emission for installed keys, Handshake, 0-RTT, and 1-RTT traffic-secret installation, handshake confirmation, backend-confirmed no-output and post-final-outbound-CRYPTO Handshake discard, installed-key 0-RTT rejection before accept, accept-driven 0-RTT receive, reject-driven key discard, client 0-RTT cleanup on 1-RTT key install, server 0-RTT cleanup after accepted 1-RTT receive, and scratch-buffer boundaries; `run-udp-crypto-stream-loopback` covers socket-backed mock `CryptoBackend` Handshake key installation, transport-parameter byte handoff, protected Handshake CRYPTO flight delivery, backend receive/output, and routed ACK cleanup; `run-crypto-stream` covers CRYPTO buffer-limit close, protected close-propagating backend transport-parameter errors, and compatible backend Version Information handoff; `run-tls-openssl-pair-transcript` and `run-tls-openssl-backend-adapter` cover the current OpenSSL callback-mode transcript, consumed pair-transcript server transport parameters, keylog observability, traffic-secret handoff, protected loopback UDP delivery, direct server-probe Handshake consumption and confirmation evidence, server-connection backend 1-RTT pull/OpenSSL secret callback/peer stream-count limit enforcement/confirmation/discard evidence, paired loopback server backend-consumed Handshake CRYPTO plus confirmation evidence, Application PTO, key discard, close, and route cleanup evidence; a full live endpoint-owned TLS loop and interop still prove full integration. |
| Packet protection | Partial v1/v2 Initial keys + configured v2 protected long-packet wire-version/type-bit use + AES-GCM payload/header protection + protected long/short-packet helpers + caller-keyed protected UDP loopback + socket-backed lifecycle installed-key key-update loopback + unprotected spin-bit peek + v1/v2 Retry Integrity Tag helpers + `quic ku` key-update derivation + connection-installed Handshake and 0-RTT long-packet keys + explicit installed-key 0-RTT accept/reject + RFC 9001 Initial discard at Handshake send/receive boundaries + explicit installed Handshake/0-RTT key discard hooks + client-side HANDSHAKE_DONE-triggered, server-side sendHandshakeDone-triggered, backend-confirmed no-output, and backend-confirmed post-final-outbound-CRYPTO Handshake key discard + client/server 0-RTT key discard at modeled 1-RTT boundaries + caller-owned and connection-installed 1-RTT key-phase state helpers, ACK-gated installed-key update initiation, and explicit short-packet key-phase send/receive | Implement real TLS-backed early-data secret ownership, real TLS Handshake/1-RTT secret production, header protection, AEAD protection, remaining TLS-triggered Handshake key discard, full TLS 0-RTT acceptance/replay policy, full TLS-owned live key-update scheduling/old-key discard, and the rest of RFC 9369 packet protection behavior beyond configured Initial/long-packet/Retry primitives. | Existing RFC-vector and fixed-vector tests cover v1 and v2 Initial derivation, configured v2 protected Initial wire-version/type-bit emission and receive rejection by v1 connections, header protection, AEAD protection, protected packets, v1 and v2 Retry Integrity Tag, spin-bit peeking, `quic ku` key-update derivation, caller-owned key-phase state transitions, caller-keyed key-phase packet selection, mock Handshake/0-RTT/1-RTT traffic-secret installation, RFC 9001 Initial discard after Handshake send/receive, installed-key Handshake long-packet exchange, caller-keyed Initial/Handshake and installed-key Handshake close emission, installed-key 0-RTT long-packet exchange, installed-key 0-RTT rejection before accept, accept-driven 0-RTT receive, reject-driven key discard, explicit installed-key discard cleanup, valid HANDSHAKE_DONE and backend-confirmed no-output/post-final-outbound-CRYPTO cleanup, client 0-RTT cleanup on 1-RTT key install, server 0-RTT failure preservation and success cleanup after 1-RTT receive, installed-key short-packet exchange, installed-key key-phase advancement after successful receive, installed-key key-update rejection before handshake confirmation, ACK-gated repeat rejection, ACK-driven re-enable, invalid-payload rollback, `run-udp-protected-loopback` socket delivery, `run-initial-keys` configured v2 Initial packetization evidence, and `run-udp-key-update-loopback` lifecycle-owned installed-key key update over real loopback UDP sockets; later TLS/endpoint tests cover real traffic-secret use, remaining automatic Handshake key discard, and full TLS-owned live key-update scheduling. |
| Spin bit | Configurable single-path short-header spin-bit state + protected spin-bit peek + lifecycle-owned route-update spin-bit reset + socket-backed UDP lifecycle spin-bit route-update loopback | Keep default-disabled behavior and later bind multi-path spin-bit instances to full endpoint path lifecycle. | Existing tests cover enabled/disabled spin-bit updates, invalid-packet preservation, and lifecycle-owned reset after committed route path update; `run-udp-spin-bit-loopback` proves lifecycle-routed first false-spin PING/ACK receive paths, migrated lifecycle-routed second true-spin PING with `path_changed`, lifecycle route update plus spin reset, reset ACK spin, and ACK cleanup over real loopback UDP sockets. |
| Streams | Partial receive reassembly with duplicate retransmission discard + FIN completion + local reset/stop observability + public `StreamState` snapshots with Data Read/Reset Read receive states and Data Acked/Reset Acked send states + implicit lower-numbered receive stream creation + pre-STREAM peer-bidirectional STOP_SENDING handling | Complete stream state machines, FIN/reset rules, and read/write behavior beyond the current in-memory reassembly skeleton. | Bidirectional, unidirectional, FIN, reset, STOP_SENDING, stream-state snapshot, out-of-order, duplicate retransmission, conflict overlap, rollback, and final-size tests. |
| Flow control | Partial receive MAX and stream-count refresh + MAX_STREAMS overflow rejection + configurable receive data/stream-count windows + BLOCKED observability/retransmission/growth + implicit lower-numbered receive stream creation + STREAM_DATA_BLOCKED receive-state validation + pre-STREAM peer-bidirectional MAX_STREAM_DATA handling + protected short-packet and socket-backed UDP credit-refresh exchange | Complete remaining adaptive MAX/BLOCKED policy reactions. | Blocked/unblocked tests at connection, stream, and stream-count scope, including MAX_STREAMS > 2^60 rejection, target receive-window refresh, peer-BLOCKED growth, stream-count-window growth, receive-side stream-state validation, caller-keyed protected short-packet flow-control exchange, and `run-udp-flow-control-loopback` lifecycle-routed socket delivery for STREAM/STREAM_DATA_BLOCKED/MAX_DATA/MAX_STREAM_DATA/resumed FIN final-size evidence/final ACK. |
| Connection IDs | Partial local/peer lifecycle + stateless-reset-token uniqueness checks + endpoint sequence/retire-prior-to DCID route table + lifecycle-owned endpoint issue/register replacement-CID helper + connection-handle route retirement + socket-backed replacement-CID route-retirement loopback + socket-backed lifecycle connection-ID NEW/RETIRE loopback | Add remaining socket-owned connection lifecycle integration around DCID routing and replacement policy. | Existing tests cover local NEW_CONNECTION_ID issuing, retire_prior_to-aware peer active-CID-limit replacement, peer RETIRE handling, peer-issued NEW_CONNECTION_ID lifecycle, receive-path duplicate CID/token rejection, limit, rollback, endpoint route registration, endpoint reset-token reuse rejection, endpoint and lifecycle-owned issue/register replacement-CID route updates with retire_prior_to application, route retirement by CID, sequence number, retire_prior_to threshold, or connection handle, and unknown/ambiguous CID rejection; `run-udp-replacement-cid-loopback` proves replacement route registration, retire_prior_to retirement, inactive reset-token lookup, active replacement routing, invalid sequence rejection, and active-migration-disabled rejection over real loopback UDP sockets; `run-udp-connection-ids-loopback` proves protected NEW_CONNECTION_ID delivery, lifecycle issue/register route installation, active replacement CID route probing, protected RETIRE_CONNECTION_ID routing through the active replacement CID, server local-CID retirement, inactive reset-token lookup, and ACK cleanup over real loopback UDP sockets; later endpoint tests cover full socket-owned connection lifecycle integration. |
| Tokens and Retry | Partial codec + v1/v2 Retry Integrity Tag helpers + configured v2 server-side Retry datagram issuance and client-side Retry processing + server-side NEW_TOKEN issuing + client-side NEW_TOKEN storage + modeled server anti-amplification send limiting + HMAC-SHA256 address-bound expiring token generation/validation with originating-version binding + endpoint IPv4 peer-address token binding + in-memory endpoint address-validation policy with rotated secrets, secret-set export/restore, replay-filter snapshot export/restore, and replay rejection + lifecycle-owned token validation that unblocks a server connection and refreshes endpoint recovery scheduling + lifecycle-owned one-time Retry token validation/consumption + server-side Retry datagram issuance + client-side Retry datagram processing and handshake CID transport-parameter validation/export + socket-backed UDP lifecycle Retry/address-validation loopback | Add production endpoint token-secret storage/distribution around exported secret/replay snapshots and integrate it with socket-owned endpoint lifecycle. | Existing tests cover Retry packet codec, RFC 9001 and RFC 9369 Retry Integrity Tag vectors, configured v2 Retry issue/process/token reuse, protected NEW_TOKEN issuing/storage, modeled 3x anti-amplification limiting, HMAC address-token kind/address/tamper/expiry/version mismatch checks, endpoint remote IPv4/port token binding, in-memory endpoint secret rotation, secret-set export/restore with retention trimming, replay-filter snapshot export/restore with retention trimming, bounded replay-filter duplicate/capacity behavior, validated-token replay fingerprint recording, lifecycle-owned path-token validation unblock/timer refresh, lifecycle-owned Retry path-token validation and one-time token consumption, server-side Retry datagram issuance, client-side Retry datagram processing, `initial_source_connection_id`, `original_destination_connection_id`, and `retry_source_connection_id` validation/export; `run-address-validation` and `run-udp-address-validation-loopback` prove lifecycle-owned NEW_TOKEN validation unblocks later server sends; `run-retry-token` and `run-udp-retry-loopback` prove lifecycle-owned Retry token validation, replay rejection, token consumption, follow-up Initial acceptance, and Retry CID transport-parameter validation through TLS extension bytes; later endpoint tests cover production secret/replay storage integration. |
| Path validation | Partial timeout/retry + duplicate pending PATH_RESPONSE suppression + 1200-byte protected exchange with anti-amplification-limited fallback + `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramAndUpdatePath*()` committing route updates only after authenticated PATH_RESPONSE validation consumes an outstanding challenge, with a close-propagating `OrClose` variant + socket-backed UDP lifecycle path-validation route-update loopback | Bind validation automatically to the remaining full socket-owned endpoint path identity cases. | Existing tests cover matching, duplicate challenge suppression, duplicate/mismatched responses, rollback, timeout retry, retry exhaustion, protected PATH_CHALLENGE/PATH_RESPONSE datagram expansion, anti-amplification fallback, endpoint route path update after protected PATH_RESPONSE validation, lifecycle-owned caller-validated route path update, validation-driven lifecycle route path update, and authenticated frame-error close propagation without route update; `run-path-validation` prints the protected datagram sizes and lifecycle update result, and `run-udp-path-validation-loopback` proves the same close-propagating validation-driven lifecycle route-update flow over loopback UDP sockets with a new peer port, including a pre-validation protected PING that reports `path_changed` but leaves the endpoint route unchanged. |
| Stateless reset | Partial helper + constant-time token match + connection detection + NEW_CONNECTION_ID token uniqueness checks + endpoint inactive-CID reset datagram construction + route/reset/drop receive classification exposed through `EndpointConnectionLifecycle` + socket-backed UDP reset emission loopback + socket-backed close-triggered lifecycle route retirement/reset loopback | Integrate reset emission into socket-owned endpoint lifecycle and connection close/drop policy. | Existing tests cover reset token match, false-positive rejection, short datagram rejection, duplicate-token rejection across CIDs, retired-token ignore, active-route token suppression, retired-route token lookup, inactive-route reset datagram construction, smaller-than-trigger sizing, route/reset/drop receive action classification, lifecycle-owned route/reset/drop after timer-disarming retirement, and ambiguous reset-token CID rejection; `run-stateless-reset` demonstrates endpoint inactive-CID reset action; `run-udp-stateless-reset-loopback` demonstrates real UDP active-route suppression before retirement, unknown-CID drop classification, trigger delivery after retirement, reset emission, and client token matching; `run-udp-close-lifecycle-loopback` demonstrates protected close delivery, lifecycle-routed protected receive auto-close, `EndpointConnectionLifecycle` connection-handle route retirement, retained reset token lookup, reset emission, and client token matching; later endpoint tests cover full TLS-owned lifecycle integration. |
| ECN validation | Partial frame-payload ACK_ECN validation + ACK_ECN CE-driven NewReno recovery response + lifecycle-owned endpoint UDP-path ECN state policy + socket-backed UDP lifecycle ACK_ECN validation/CE response loopback | Bind ECN validation to real IP ECN marking once socket packetization exposes packet ECN marks. | Existing tests cover ECT(0) success, CE-counter congestion response, repeated CE suppression inside the NewReno recovery period, missing ACK_ECN failure, insufficient counters, counter totals exceeding sent ECT packets, reordered ACK handling, rollback, endpoint path-identity state isolation, and lifecycle-owned mirroring of connection ECN validation state to UDP path identity; `run-udp-ecn-validation-loopback` covers lifecycle-routed modeled ECT(0) protected PING delivery, lifecycle-routed protected ACK_ECN success, lifecycle-routed ECN-CE ACK_ECN congestion response, `EndpointConnectionLifecycle` ECN state update for the current UDP tuple, and migrated-path isolation without claiming real IP-header ECN marking. |
| RFC 9002 recovery | Partial largest-acknowledged RTT sampling + connection-level RTT estimate sharing and PTO backoff across packet number spaces with client Initial ACK reset suppression + Initial/Handshake RTT ACK-delay suppression + Application ACK delay scaling/capping + packet/time-threshold loss + aggregate loss-time-before-PTO timer deadline selection/service with closing/draining disarm, anti-amplification-limited server PTO disarm/rearm plus expired-PTO service when new datagrams unblock sending, and client no-in-flight anti-deadlock PTO + endpoint-owned multi-connection recovery timer scheduling + cross-space bytes-in-flight congestion admission + peer max_udp_payload_size recovery max_datagram_size/initial-cwnd resync + congestion-window bypass for one armed PTO probe + ACK-driven frame-payload STREAM/CRYPTO, protected CRYPTO, protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission requeue, and ACKed RESET_STREAM obsolete retransmission suppression + NewReno underutilized-cwnd suppression, slow-start/congestion-avoidance byte-counted and batched-ACK growth, recovery period, new-congestion-event one-packet recovery probe, and minimum-window ssthresh clamp + PTO-backoff-independent persistent congestion duration/response with min-RTT refresh, recovery-period reset/re-entry, and non-contiguous suppression + ACK_ECN CE-driven NewReno recovery response + packet-space PTO PING/new-data/in-flight-CRYPTO/protected-0-RTT-control/protected-0-RTT-STREAM/in-flight-STREAM/cross-space probe hook with Initial/Handshake max_ack_delay suppression and Application PTO gating until handshake confirmation + socket-backed UDP lifecycle loss/PTO recovery plus lifecycle congestion-recovery and lifecycle STREAM-retransmission loopbacks | Implement socket-owned protected-packet loss/PTO timer lifecycle integration and remaining NewReno edge cases. | Existing tests cover ACK, invalid ACK range rejection before recovery side effects, ACKs that newly acknowledge only lower ranges without taking an RTT sample, connection-level RTT sharing across packet number spaces, invalid-payload rollback after shared RTT updates, connection-level PTO backoff after one space expires, ACK reset of PTO backoff across spaces, client Initial ACK PTO-backoff reset suppression, client no-in-flight anti-deadlock Initial/Handshake PTO, anti-amplification-limited server PTO disarm/rearm plus expired-PTO service when new datagrams unblock sending, Initial/Handshake discard reset of PTO backoff, invalid-payload rollback after PTO backoff reset, Initial/Handshake RTT ACK-delay suppression, ACK delay exponent scaling, post-confirmation max_ack_delay capping, max_udp_payload_size-driven recovery max_datagram_size/initial-cwnd resync, packet-threshold loss, ACK-driven and timeout-driven time-threshold loss, aggregate timer deadline selection/service with loss-time precedence over PTO, no-op before deadline, due loss-time servicing without extra PTO probes, earliest-space PTO servicing, closing/draining recovery-timer disarm, endpoint-owned multi-connection timer scheduling/re-arming/disarming, cross-space bytes-in-flight congestion admission, protected short PTO service/disarm, protected short loss-time retransmission, protected short CRYPTO loss-time expiry/retransmission, ACK-driven lost STREAM, CRYPTO, protected CRYPTO, protected 0-RTT STREAM requeue, protected 0-RTT RESET_STREAM/STOP_SENDING requeue, and ACKed RESET_STREAM obsolete retransmission suppression, invalid-payload rollback after retransmission requeue, NewReno underutilized-cwnd suppression and slow-start/congestion-avoidance byte-counted/batched-ACK growth, NewReno recovery-period suppression for loss and ECN-CE, new-congestion-event one-packet recovery probe, minimum-window ssthresh clamp, PTO-backoff-independent persistent congestion duration/response including min-RTT refresh, recovery-period reset/re-entry, and non-contiguous loss suppression, packet-number-space PTO PING queuing with connection-level backoff, one-shot PTO probe congestion-window bypass, cross-space PTO peer probes, Initial/Handshake PTO deadline calculation without max_ack_delay, Application PTO no-op before handshake confirmation, queued STREAM data probe selection, PTO-driven in-flight CRYPTO/STREAM/protected-0-RTT-STREAM/protected-0-RTT-control retransmission, and congestion-window arithmetic; `run-loss-recovery` covers invalid ACK range rejection, old-largest ACK RTT preservation, cross-space bytes-in-flight congestion admission, aggregate loss-time timer service, NewReno underutilized-cwnd suppression and byte-counted/batched-ACK congestion-window growth, new-congestion-event STREAM recovery probe, minimum-window ssthresh clamp, persistent congestion duration that is not widened by PTO backoff, persistent-congestion min-RTT refresh, persistent-congestion recovery-period clearing/re-entry, and non-contiguous persistent-congestion suppression; `run-transport-parameters` covers peer max_udp_payload_size-driven recovery resync; `run-endpoint-recovery-timers` covers endpoint-owned selection and servicing across multiple connection handles plus closing-state recovery timer disarm; `run-crypto-stream` covers frame-payload Handshake CRYPTO loss requeue/retransmission and protected 1-RTT CRYPTO ACK-loss requeue/retransmission; `run-pto-recovery` covers aggregate PTO timer service, Application PTO gating until handshake confirmation, client Initial ACK PTO-backoff reset suppression, client no-in-flight anti-deadlock Initial PTO, anti-amplification-limited server PTO disarm/rearm plus unblock-time expired PTO service, connection-level RTT sharing and PTO backoff across packet number spaces, Initial/Handshake RTT ACK-delay suppression, congestion-window bypass for one armed PTO probe, ACKed RESET_STREAM obsolete retransmission suppression, protected 1-RTT CRYPTO PTO probe selection, and cross-space PTO peer probes; `run-udp-loss-recovery-loopback` covers protected short PING delivery over UDP, protected ACK-driven packet-threshold loss removal, lifecycle timer-driven time-threshold cleanup, and final timer disarm; `run-udp-congestion-recovery-loopback` covers lifecycle-owned protected short PING/ACK routing over UDP, repeated-loss suppression inside the NewReno recovery period, and persistent congestion reduction to the minimum window; `run-udp-ecn-validation-loopback` covers protected ACK_ECN CE response reducing the congestion window over UDP; `run-udp-pto-recovery-loopback` covers lifecycle timer-driven ACK-loss PTO over protected UDP packets, PING fallback probe delivery, queued STREAM data as PTO probe, in-flight STREAM and CRYPTO data as PTO probes, duplicate receive/CRYPTO range discard, ACK cleanup, and final timer disarm; `run-udp-stream-retransmission-loopback` covers lifecycle-owned route selection for ACK-driven 1-RTT STREAM retransmission over protected UDP packets and final ACK cleanup; `packet_spaces` covers protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING ACK-loss requeue and retransmission under a new packet number. Remaining controlled-clock tests cover full socket-owned protected-packet loss/PTO timer lifecycle integration. |
| UDP endpoint routing | Partial in-memory DCID/IPv4 tuple router + socket-backed UDP endpoint routing loopback with client-side VN selection/follow-up route replacement, connection handoff, and protected follow-up Initial emission + socket-backed zero-length CID tuple-routing loopback + socket-backed preferred-address route-migration loopback + socket-backed replacement-CID route-retirement loopback + socket-backed lifecycle connection-ID NEW/RETIRE loopback + socket-backed lifecycle flow-control credit-refresh loopback + socket-backed lifecycle ECN ACK_ECN validation/CE response loopback + socket-backed lifecycle loss-recovery loopback + socket-backed lifecycle congestion-recovery loopback + socket-backed lifecycle PTO recovery loopback + socket-backed lifecycle STREAM retransmission loopback + socket-backed lifecycle installed-key key-update loopback + socket-backed path-validation route-update loopback + socket-backed lifecycle Retry route-switch/address-validation loopback + socket-backed close-triggered route retirement/reset loopback + socket-backed stateless reset emission loopback + unsupported-version VN response helper + client-side VN selection/follow-up lifecycle helper + client Initial Source CID route registration + supported-version unknown-DCID Initial accept classification + accepted Initial Original DCID/server Initial SCID route registration + zero-length CID tuple routing + Retry DCID switch helper + caller-validated preferred-address migration commit + sequence/retire-prior-to/connection-handle route retirement + endpoint reset-token uniqueness checks + caller-validated path update + retired-CID stateless reset token lookup/datagram construction + route/version-negotiation/reset/drop/accept receive classification | Route UDP datagrams by DCID, local/remote address tuple, version support, and connection state. | Existing deterministic endpoint tests cover long-header DCID routing, unsupported-version Version Negotiation response generation with CID echoing, client Initial Source CID route registration for server Initial/VN responses, supported-version unknown-DCID Initial accept metadata, accepted Initial route registration and rollback, client-side VN selection/ignore/reject state, lifecycle-owned VN follow-up route/timer retirement plus follow-up route registration, endpoint-owned follow-up connection handoff, lifecycle-owned protected follow-up Initial emission, reused client Initial Source CID follow-up registration, short-header registered-CID matching, zero-length CID tuple routing, duplicate route rejection, duplicate sequence rejection, stateless reset token reuse rejection, Retry Source CID route switching, caller-validated preferred-address route migration, unknown CID rejection, ambiguous short-header CID rejection, path-specific zero-CID retirement, sequence-number route retirement for RETIRE_CONNECTION_ID wiring, retire_prior_to threshold retirement, connection-handle route retirement, caller-validated route path updates, stale path-update rejection, active-migration-disabled path rejection, stateless reset token lookup for inactive routes, reset datagram construction for inactive routes, route/version-negotiation/reset/drop/accept receive action classification, and lifecycle-owned ECN state mirroring by UDP path; `run-udp-endpoint-loopback` covers routing decisions, client-side VN selection, follow-up config derivation, old-attempt route retirement, follow-up Initial route registration, endpoint-owned follow-up connection handoff, protected follow-up Initial emission/server processing, and follow-up Initial routing over real loopback UDP sockets; `run-udp-zero-cid-loopback` covers zero-length CID tuple routing, long-header zero-DCID routing, path-specific retirement, and route path update over real loopback UDP sockets; `run-udp-preferred-address-loopback` covers caller-committed preferred-address route migration, preferred CID routing, current-route retirement, active-migration-disabled stray-path rejection, and retained reset-token lookup over real loopback UDP sockets; `run-udp-replacement-cid-loopback` covers replacement-CID route registration, retire_prior_to sequence retirement, inactive reset-token lookup, active replacement routing, invalid replacement sequence rejection, and active-migration-disabled stray-path rejection over real loopback UDP sockets; `run-udp-connection-ids-loopback` covers protected NEW_CONNECTION_ID and RETIRE_CONNECTION_ID exchange through lifecycle-owned endpoint routes, replacement CID routing, inactive reset-token lookup, and active replacement token suppression over real loopback UDP sockets; `run-udp-flow-control-loopback` covers protected STREAM_DATA_BLOCKED, MAX_DATA/MAX_STREAM_DATA, resumed STREAM data, and final ACK cleanup through lifecycle-owned endpoint routes over real loopback UDP sockets; `run-udp-ecn-validation-loopback` covers modeled ECT(0) protected PING routing, protected ACK_ECN validation, ACK_ECN CE response, lifecycle-owned endpoint ECN state update, and migrated-path ECN isolation over loopback UDP sockets; `run-udp-loss-recovery-loopback` covers protected short PING routing plus ACK-driven packet-threshold, lifecycle timer-driven time-threshold loss, and final timer disarm over loopback UDP sockets; `run-udp-congestion-recovery-loopback` covers lifecycle-owned protected short PING/ACK routing plus NewReno recovery-period suppression and persistent congestion window reduction over loopback UDP sockets; `run-udp-pto-recovery-loopback` covers lifecycle timer service plus protected short probe polling for ACK-loss PTO, protected PING fallback probe delivery, queued STREAM and in-flight STREAM/CRYPTO PTO probe delivery, duplicate receive/CRYPTO range discard, ACK cleanup, and final timer disarm over loopback UDP sockets; `run-udp-stream-retransmission-loopback` covers lifecycle-owned route selection for sparse ACK-driven 1-RTT STREAM retransmission and final ACK cleanup over loopback UDP sockets; `run-udp-key-update-loopback` covers lifecycle-owned installed-key key phase routing, peer key-phase advancement, and ACK-gated second-update re-enable over real loopback UDP sockets; `run-udp-path-validation-loopback` covers new-peer-port path_changed routing followed by validation-driven lifecycle path update and confirmed routing on the new path; `run-udp-retry-loopback` covers lifecycle-owned Retry response routing, Retry Source CID route switching, follow-up Initial routing, and accepted server Initial response routing over loopback UDP sockets; `run-udp-close-lifecycle-loopback` covers close-triggered connection-handle route retirement and follow-up inactive-CID reset emission over loopback UDP sockets; `run-udp-stateless-reset-loopback` covers socket-backed stateless reset emission for an inactive CID; later tests cover protected client/server integration. |
| Interop | Missing | Validate a minimal QUIC echo flow against at least one external implementation. | Manual or optional CI script records peer implementation and version. |

## Progress Notes

- 2026-06-17: Added
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndPollDatagram()`
  and the cross-connection
  `feedDatagramWithInstalledKeysAcrossConnectionsAndPollDatagram()` as
  socket-facing installed-key receive-to-output steps. Unit coverage proves
  feed classification routes before packet processing, the selected
  caller-owned connection polls one 1-RTT ACK datagram, decoy connections are
  not touched, and the single-connection wrapper preserves ACK cleanup on the
  peer.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDrainDatagrams()`
  and the cross-connection
  `feedDatagramWithInstalledKeysAcrossConnectionsAndDrainDatagrams()` as
  socket-facing installed-key receive-to-bounded-drain steps. Unit coverage
  proves feed classification routes before packet processing, the selected
  caller-owned connection drains a 1-RTT ACK into bounded output slots, decoy
  connections are not touched, and the single-connection wrapper preserves ACK
  cleanup on the peer.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndDrainDatagrams()`
  and its `OrClose` variant as routed installed-key 1-RTT
  receive-to-bounded-drain steps. Unit coverage proves route selection happens
  before packet processing, connection-id mismatches stop before ACK
  generation, successful routed installed-key PING receive drains the ACK into
  caller-owned output slots, and authenticated frame errors queue close while
  stopping before output drain.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams()`
  and its `OrClose` variant as routed installed-key Handshake
  receive-to-backend-to-bounded-drain steps. Unit coverage proves route
  selection happens before packet processing, connection-id mismatches stop
  before backend delivery, successful routed installed-key Handshake CRYPTO
  produces a protected response, and backend peer transport-parameter errors
  stop before output drain while leaving a protected Handshake close for the
  peer.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndDrainProtectedLongCryptoDatagrams()`
  as the close-propagating caller-keyed Initial/Handshake backend-drive to
  bounded-drain step. Unit coverage proves backend peer transport-parameter
  errors consume already received Handshake CRYPTO, stop before backend output
  pull or caller-keyed long-header CRYPTO drain, refresh endpoint recovery
  state, and leave a protected Handshake `TRANSPORT_PARAMETER_ERROR` close for
  the peer.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.processProtectedLongDatagramInSpaceAndDriveCryptoBackendOrCloseAndDrainDatagrams()`
  as the close-propagating caller-keyed long-header
  receive-to-backend-to-bounded-drain step. Unit coverage proves an
  authenticated Handshake CRYPTO datagram is processed before backend delivery,
  backend peer transport-parameter errors stop before output pull or drain, and
  the peer receives the protected Handshake `TRANSPORT_PARAMETER_ERROR` close.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams()`
  and its `OrClose` variant as routed caller-keyed long-header
  receive-to-backend-to-bounded-drain steps. Unit coverage proves route
  selection happens before packet processing, connection-id mismatches stop
  before backend delivery, successful routed Handshake CRYPTO produces a
  protected response, and backend peer transport-parameter errors stop before
  output drain while leaving a protected Handshake close for the peer.
- 2026-06-05: Migrated the current C TLS example boundary to Zig 0.16's
  `addTranslateC` build path. The C ABI declarations now live in small header
  files and the Zig examples import them with `@import("c")`; handwritten
  `extern fn` / `extern struct` declarations were removed from the current
  examples. The OpenSSL-backed `TlsBackend` wrapper also exposes a translated
  `handshake_confirmed` callback that reports confirmation after peer transport
  parameters, Handshake/1-RTT secrets, and OpenSSL recv/release consumption of
  inbound Handshake CRYPTO are available, so
  `run-tls-openssl-backend-adapter` now prints `backend_confirmed=true`. The same
  translate-c header also exposes an OpenSSL server-role backend constructor.
  The backend C harness now configures TLS 1.3 with a fixed example PSK and
  verifies that the server context can install local transport parameters,
  consume real client Initial CRYPTO, produce server Initial CRYPTO, and avoid
  reporting confirmed before the full handshake. The same example also delivers
  client Initial CRYPTO into a quicz server connection through a protected
  Initial datagram, drives the OpenSSL server backend with
  `driveCryptoBackendInSpace(.initial)`, packetizes the produced server Initial
  CRYPTO back to the client through quicz, and verifies peer transport
  parameters plus Handshake keys return to the connection layer. The OpenSSL
  backend adapter now also keeps CRYPTO buffers separated by packet space, so the
  server connection can pull pending Handshake CRYPTO through
  `driveCryptoBackendInSpace(.handshake)` and packetize it with installed
  Handshake keys. The verification client also sends protected Handshake CRYPTO
  back with the same backend session's Handshake keys, and the server connection
  delivers those bytes into the OpenSSL recv/release callbacks. Full server-side
  `SSL_do_handshake()` progression through Handshake/Application and confirmed
  remains pending.
- 2026-06-05: Added `examples/tls_openssl_pair_transcript.zig` plus a small C
  harness that completes an OpenSSL client/server callback-mode TLS transcript
  using a fixed example PSK. The harness routes CRYPTO bytes by OpenSSL
  protection level, verifies both endpoints finish the transcript without
  alerts, and records peer transport-parameter plus Handshake/1-RTT
  traffic-secret callbacks on both endpoints. The Zig side now copies and
  parses role-specific peer transport-parameter bytes, records keylog callback
  count/byte evidence without printing key material, and copies the generated
  CRYPTO bytes into quicz Initial/Handshake/Application frame-payload CRYPTO
  queues and reads them back by packet number space. It also packetizes
  the client Initial CRYPTO bytes with quicz protected Initial long-packet
  helpers and verifies server-side delivery, then routes both Initial flights
  over loopback UDP through the quicz endpoint lifecycle. It installs
  OpenSSL-produced Handshake secrets into quicz and verifies protected Handshake
  CRYPTO delivery in both directions, including loopback UDP delivery through
  the same lifecycle. The same manual OpenSSL context also installs
  OpenSSL-produced 1-RTT secrets and drives a STREAM request/echo/final-ACK
  exchange through the same socket/lifecycle path, then verifies Handshake key
  discard and protected close/route cleanup there as well. The full pair
  transcript still verifies installed-key protected STREAM request/response
  over short packets and a loopback UDP STREAM echo with those 1-RTT secrets.
  Full endpoint-owned live TLS handshake/socket loop
  remains pending.
- 2026-06-10: Added
  `EndpointAcceptedInitialCryptoBackendDatagramResult` and
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialWithCryptoBackendAndPollDatagram()`
  as a server Initial accept-to-TLS-backend response step. The helper
  authenticates the accepted protected client Initial, installs endpoint
  routes, drives the Initial-space `CryptoBackend`, and packetizes one
  backend-produced server Initial datagram without taking ownership of
  connection/backend/socket storage. Unit coverage proves the backend consumes
  client Initial CRYPTO, queues server Initial CRYPTO, refreshes endpoint
  recovery scheduling, and the client can decrypt the backend-produced response.
- 2026-06-10: Added
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialWithCryptoBackendOrCloseAndPollDatagram()`
  for the close-propagating accepted-Initial backend path. Peer
  transport-parameter errors returned by the Initial-space backend now queue a
  transport `CONNECTION_CLOSE` after route installation, stop before backend
  output polling, and leave the close to the existing protected long-packet
  poll path. Unit coverage proves the backend consumes client Initial CRYPTO,
  does not pull output after the peer-parameter error, exposes a close-timeout
  deadline through the lifecycle, and the client can decrypt the protected
  Initial close.
- 2026-06-10: Added `EndpointAcceptedInitialCryptoBackendDatagramDrainResult`,
  `EndpointConnectionLifecycle.drainProtectedLongCryptoDatagramsInSpace()`, and
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialWithCryptoBackendAndDrainDatagrams()`
  so socket loops can bound protected Initial/Handshake CRYPTO output work with
  caller-owned result slots. Unit coverage proves an accepted Initial can drive
  a backend that queues multiple Initial CRYPTO outputs, drain only the first
  protected server Initial datagram in a one-slot batch, continue draining the
  remaining Initial datagram in a later batch, and let the client reassemble the
  complete backend-produced CRYPTO bytes.
- 2026-06-10: Added
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndArmConnection()` so
  endpoint-owned loops can drive a connection `CryptoBackend` and refresh the
  aggregate recovery timer snapshot in one core API. Unit coverage proves that
  a backend-confirmed no-output Handshake drive confirms the connection,
  discards Handshake packet-number-space state, and clears the endpoint timer;
  the OpenSSL-backed adapter now uses this lifecycle helper on the client and
  paired server backend paths. Added
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndArmConnection()`
  for the close-propagating peer transport-parameter path; unit coverage proves
  invalid backend peer-parameter bytes queue a protected Handshake
  `TRANSPORT_PARAMETER_ERROR` close through the endpoint lifecycle without
  pulling backend output. Added endpoint lifecycle wrappers for
  `driveCryptoBackendInSpaceWithCompatibleVersion*()` as the RFC 9368
  compatible Version Information backend path; tests cover selected-version
  progress, Handshake discard/timer refresh, and protected
  `VERSION_NEGOTIATION_ERROR` close emission before backend output is pulled.
  Added
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndDrainProtectedLongCryptoDatagrams()`
  for socket loops that already hold Initial or Handshake packet-protection
  keys. Unit coverage proves a caller-keyed Handshake datagram can feed backend
  input, a backend drive can queue two Handshake CRYPTO outputs, a one-slot
  bounded drain emits only the first protected long-header datagram, and a
  later drain completes delivery to the peer. Added
  `EndpointConnectionLifecycle.processProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams()`
  as the single-connection receive-to-backend-to-bounded-drain step for
  caller-keyed Initial/Handshake paths; tests prove an authenticated Handshake
  datagram is processed before backend input delivery and bounded response
  draining. Added
  `EndpointConnectionLifecycle.processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams()`
  for the TLS-owned Handshake stage after traffic secrets are installed; tests
  prove installed-key Handshake receive, backend input delivery, multi-output
  backend CRYPTO, one-slot bounded drain, and later peer delivery through
  installed-key Handshake packet protection. Added
  `EndpointConnectionLifecycle.processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendOrCloseAndDrainDatagrams()`
  for the close-propagating installed-key Handshake backend path; tests prove
  backend peer transport-parameter errors stop before backend output pull or
  output drain and leave a protected Handshake close for the peer. Added
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagrams()`
  as a single-connection no-new-datagram tick; tests prove pending-work sweep
  accounting, backend drive, one-slot installed-key Handshake drain, and later
  peer delivery without requiring callers to build single-element view slices.
  Added
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`
  for the single-connection close-propagating no-new-datagram tick; tests prove
  backend errors stop before output pull and drain.
  The installed-key Handshake receive `OrClose` lifecycle wrapper now also
  refreshes endpoint state when authenticated frame errors queue protected
  `CONNECTION_CLOSE`; tests prove an armed Handshake recovery timer is cleared
  before the protected close is polled. The other endpoint protected receive
  `OrClose` wrappers now use the same error-path refresh rule for caller-keyed,
  installed-key, key-update, and key-phase long/0-RTT/1-RTT paths; short-packet
  and installed-key 1-RTT tests prove an armed Application recovery timer is
  cleared before the protected close is polled. On an already failing
  connection path, endpoint timer refresh is best-effort so callers keep the
  original connection error instead of a secondary timer-mirroring failure.
- 2026-06-10: Added the first core socket-loop entrypoints directly on
  `EndpointConnectionLifecycle`: `feedDatagram()` wraps version-independent
  routing, Version Negotiation, stateless reset, and Initial accept
  classification; `nextDeadline()` returns the earliest active idle,
  close/drain, or recovery deadline for a connection handle;
  `processPendingWork()` runs the endpoint-owned pending-work order of idle
  retirement, close/drain retirement, then loss/PTO service; and
  `pollDatagram()` emits installed-key Handshake, 0-RTT, or 1-RTT datagrams
  through the existing protected packet helpers. Unit coverage proves routed
  feed classification, idle-before-recovery pending-work retirement, closed
  connections no longer reporting stale idle deadlines, installed-key 1-RTT
  packet output, recovery timer refresh, and peer ACK scheduling. This is the
  embeddable API surface for socket loops; the production TLS-owned event loop
  remains pending.
- 2026-06-10: Added
  `EndpointConnectionLifecycle.processPendingWorkAndPollDatagram()` as the
  installed-key recovery wakeup bridge for socket loops. It preserves the
  `processPendingWork()` ordering, returns idle/close retirement without
  polling output, and only calls `pollDatagram()` after a due loss/PTO timer is
  actually serviced for the requested packet-number space. Unit coverage proves
  the before-deadline path is a no-op and the due Application PTO path emits an
  installed-key 1-RTT PING probe while keeping the endpoint recovery timer
  armed for the probe.
- 2026-06-10: Added
  `EndpointPendingWorkDatagramDrainResult` and
  `EndpointConnectionLifecycle.processPendingWorkAndDrainDatagrams()` as the
  bounded-output form of the installed-key recovery wakeup bridge. It preserves
  the same `processPendingWork()` gating as
  `processPendingWorkAndPollDatagram()`: before a loss/PTO timer is serviced it
  returns an empty drain result, and after a matching recovery wakeup it drains
  installed-key output into caller-owned result slots. Unit coverage proves the
  before-deadline no-op and the due Application PTO 1-RTT PING probe path.
- 2026-06-10: Added
  `EndpointConnectionDeadline.installedKeyPollOptions()` and
  `EndpointPollInstalledKeyDatagramOptions.fromRecoveryDeadline()` so socket
  loops can derive installed-key Handshake or 1-RTT poll options directly from
  `nextDeadline()` recovery wakeups. Initial recovery intentionally returns
  null because Initial packetization does not use installed TLS traffic
  secrets; 0-RTT remains an explicit poll choice for accepted early data. Unit
  coverage checks idle/Initial no-op mapping, Handshake DCID/SCID preservation,
  and Application-to-1-RTT mapping, and the PTO wakeup test now uses the
  deadline-derived options.
- 2026-06-10: Added
  `EndpointConnectionLifecycle.processDueDeadlineAndPollDatagram()` as the
  socket-loop wakeup entrypoint that combines `nextDeadline()` with pending-work
  processing. Calls before the current deadline return null and do not mutate
  connection or endpoint state. Due idle/close deadlines run retirement without
  output; due installed-key recovery deadlines reuse
  `processPendingWorkAndPollDatagram()` and may return a probe datagram. Unit
  coverage proves idle retirement through the due-deadline entrypoint and
  Application PTO wakeups that are no-ops before the deadline and emit an
  installed-key 1-RTT PING probe at the deadline.
- 2026-06-10: Added `EndpointDueWorkDatagramDrainResult`,
  `EndpointConnectionLifecycle.processDueDeadlineAndDrainDatagrams()`, and
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDrainDatagrams()`
  as bounded-output forms of the due-deadline wakeup path. Calls before the
  current deadline still return null; due idle/close deadlines return empty
  drain results; due installed-key recovery deadlines reuse
  `processPendingWorkAndDrainDatagrams()`. Unit coverage proves single-handle
  and cross-connection Application PTO wakeups drain 1-RTT PING probes while
  preserving earliest-deadline selection.
- 2026-06-11: Added
  `EndpointConnectionLifecycle.processDueDeadlineAndPollDatagramWithInstalledKeyOptions()`
  and
  `EndpointConnectionLifecycle.processDueDeadlineAndDrainDatagramsWithInstalledKeyOptions()`
  for socket loops that need explicit installed-key output selection after a
  due recovery deadline. This keeps the default `installedKeyPollOptions()`
  mapping for Handshake and 1-RTT while allowing accepted 0-RTT PTO wakeups to
  poll or drain `.zero_rtt` output. Unit coverage proves the before-deadline
  path is still a no-op, mismatched packet-space options are rejected before
  recovery state mutation, and due Application PTO wakeups can emit or drain a
  protected 0-RTT `RESET_STREAM` probe.
- 2026-06-11: Added `EndpointConnectionInstalledKeyPollView`,
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndPollDatagramWithInstalledKeyOptions()`,
  and
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDrainDatagramsWithInstalledKeyOptions()`.
  These are the caller-owned-connection-map forms of the explicit installed-key
  due-deadline wakeup path. Unit coverage proves earliest-deadline selection
  across two accepted 0-RTT connections, before-deadline no-op behavior, and
  protected 0-RTT `RESET_STREAM` poll/drain output without mutating the later
  connection.
- 2026-06-11: Updated the single-connection due-deadline-to-backend poll and
  bounded-drain wrappers to preserve explicit installed-key recovery output
  choices. Initial recovery still services pending work without emitting an
  installed-key datagram and can continue into backend drive; Handshake and
  Application recovery now validate the caller-provided output space before
  polling. Unit coverage proves accepted 0-RTT PTO wakeups return protected
  0-RTT `RESET_STREAM` recovery datagrams and stop before backend drive in both
  the poll and drain wrappers.
- 2026-06-11: Added
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions()`
  and
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions()`.
  These carry explicit installed-key recovery output selection through
  caller-owned connection maps before backend sweeps. Unit coverage proves
  accepted 0-RTT PTO wakeups are selected by earliest deadline, emit protected
  0-RTT `RESET_STREAM` datagrams, skip backend drive/drain, and leave the later
  connection untouched.
- 2026-06-10: Added `EndpointConnectionView` and
  `EndpointConnectionLifecycle.nextDeadlineAcrossConnections()` for embeddable
  socket loops where callers own the connection map. The lifecycle now combines
  connection-owned idle/close deadlines with endpoint-owned recovery snapshots
  across a caller-provided view slice without taking ownership of connection
  storage. Unit coverage proves selection order across close timeout, idle
  timeout, recovery PTO, and connections with no endpoint-visible deadline.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndSelectNextDeadline()`
  as the no-output pending-work-to-next-deadline socket-loop planning step.
  Unit coverage proves pending work retires an idle connection before wakeup
  selection, leaves a later recovery timer armed, and returns the recovery
  deadline for the remaining caller-owned connection map.
- 2026-06-17: Added `EndpointPendingWorkCryptoBackendNextDeadlineResult` and
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndSelectNextDeadline()`
  as the no-output pending-work-to-backend-drive-to-next-deadline socket-loop
  step. Unit coverage proves pending idle retirement runs before backend drive,
  backend progress refreshes endpoint recovery scheduling, and the resulting
  recovery deadline is selected without polling output.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline()`
  as the close-propagating no-output pending-work-to-backend-drive-to-next-deadline
  socket-loop step. Unit coverage proves pending idle retirement runs before
  close-propagating backend drive, endpoint recovery scheduling is refreshed,
  and the resulting recovery deadline is selected without polling output.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline()`
  as the RFC 9368-compatible no-output pending-work-to-backend-drive-to-next-deadline
  socket-loop step. Unit coverage proves pending idle retirement runs before
  compatible Version Information application, endpoint recovery scheduling is
  refreshed, and the resulting recovery deadline is selected without polling output.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`
  as the close-propagating RFC 9368-compatible no-output
  pending-work-to-backend-drive-to-next-deadline socket-loop step. Unit coverage
  proves pending idle retirement runs before compatible close-propagating backend
  drive, Version Information is applied, endpoint recovery scheduling is
  refreshed, and the resulting recovery deadline is selected without polling output.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.processDueDeadlineAndSelectNextDeadline()` and
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndSelectNextDeadline()`
  as no-output due-deadline-to-next-deadline socket-loop planning steps. Unit
  coverage proves calls before the deadline are no-ops, a due recovery deadline
  can be serviced and rescheduled for a single connection, a due idle deadline
  retires endpoint route state, and the next recovery deadline is returned for
  the remaining caller-owned connection map.
- 2026-06-10: Added `EndpointConnectionPollView` and
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndPollDatagram()`
  so embeddable socket loops can dispatch the earliest already-due deadline
  across caller-owned connections without giving the lifecycle connection
  storage ownership. Unit coverage proves calls before the earliest due
  deadline are no-ops, and that only the selected due connection emits the
  installed-key 1-RTT PTO probe while later-deadline connections remain
  untouched.
- 2026-06-10: Added `EndpointConnectionReceiveView` and
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnections()`
  so socket loops can route and process installed-key datagrams across a
  caller-owned connection set without duplicating endpoint route lookup and
  close-propagating protected receive logic. Unit coverage proves a routed
  1-RTT packet is delivered to the matching connection ID while another live
  caller-owned connection remains untouched.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndSelectNextDeadline()`
  and `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndSelectNextDeadline()`
  as no-output receive-to-next-deadline socket-loop steps. Unit coverage proves
  routed installed-key 1-RTT receive refreshes the selected connection's idle
  deadline, leaves an unrelated caller-owned connection untouched, and returns
  the next deadline without polling output.
- 2026-06-10: Added
  `EndpointConnectionLifecycle.pollDatagramAcrossConnections()` and
  `EndpointPolledDatagramResult` for caller-owned connection maps. Socket loops
  can now ask the lifecycle owner to poll installed-key output across a
  caller-ordered connection slice without duplicating timer mirroring around
  each connection. Unit coverage proves the first connection with queued output
  is selected and produces a protected 1-RTT PING while an earlier idle
  connection remains unsent.
- 2026-06-10: Added `EndpointDatagramDrainResult` and
  `EndpointConnectionLifecycle.drainDatagramsAcrossConnections()` so embeddable
  socket loops can drain installed-key output into caller-owned result slots
  with an explicit per-iteration bound. The result reports initialized entries
  even when a later poll fails, preserving caller ownership and release
  responsibility for partially drained datagrams. Unit coverage proves a
  one-slot batch emits only the first queued connection and a later drain
  continues with the remaining queued connection.
- 2026-06-10: Added `EndpointPendingWorkSweepResult` and
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnections()` so socket
  loops can sweep idle timeout, close/drain timeout, and recovery timer work
  across caller-owned connections without taking over connection storage. Unit
  coverage proves one pass can retire an idle connection and service another
  connection's due recovery timer while preserving the latter connection.
- 2026-06-10: Added `EndpointPendingWorkCryptoBackendDatagramResult` and
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram()`
  for no-new-datagram loop ticks. The helper applies idle/close/recovery
  pending work first, then drives caller-owned TLS backends, then polls
  installed-key output across caller-owned connections. Unit coverage proves an
  expired Application PTO can be serviced and emitted as a protected 1-RTT PING
  probe in the same lifecycle-owned API step without backend storage ownership.
- 2026-06-10: Added the close-propagating and RFC 9368-compatible pending-work
  backend loop variants:
  `processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram()`,
  `processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram()`,
  and
  `processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`.
  Unit coverage proves timer/flush ticks can stop before output polling on peer
  transport-parameter errors, apply authenticated compatible Version
  Information, and queue compatible-version close state through the same
  lifecycle-owned API boundary.
- 2026-06-10: Added `EndpointDueWorkCryptoBackendDatagramResult` and the
  due-deadline backend loop variants:
  `processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram()`,
  `processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram()`,
  `processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram()`,
  and
  `processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`.
  The helpers process the earliest due caller-owned connection first, return a
  due recovery datagram before driving TLS backends, and only continue into
  backend drive/output polling for live no-output due work; terminal idle/close
  cleanup stops before backend progress. Unit coverage proves one-output ownership, close-propagating backend
  errors, compatible Version Information application, and compatible-version
  close propagation through the same lifecycle-owned wakeup API.
- 2026-06-18: Added `EndpointDueWorkCryptoBackendNextDeadlineResult` and
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndSelectNextDeadline()`
  as the no-output due-deadline-to-backend-drive-to-next-deadline socket-loop
  step.
- 2026-06-18: Added
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline()`
  and
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline()`
  as the close-propagating and compatible-version no-output
  due-deadline/backend/deadline steps.
- 2026-06-18: Added
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`
  as the compatible-version close-propagating no-output
  due-deadline/backend/deadline step. Unit coverage for the next-deadline due
  paths proves the earliest due recovery deadline is serviced before backend
  drive, backend progress refreshes another connection's recovery scheduling,
  compatible Version Information is applied, and the resulting recovery
  deadline is selected without polling output.
- 2026-06-10: Added `EndpointCryptoBackendDriveView`,
  `EndpointCryptoBackendDriveSweepResult`, and
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceAndArmConnections()`
  so a TLS-backed socket loop can drive caller-owned connection/backend pairs
  in one lifecycle-owned sweep. The helper reuses the single-connection backend
  drive path and refreshes endpoint recovery scheduling for each connection.
  Unit coverage proves two caller-owned backends are driven, their outbound
  Handshake CRYPTO bytes are aggregated in progress counters, and each
  connection receives its own queued CRYPTO output.
- 2026-06-17: Added `EndpointCryptoBackendDriveNextDeadlineResult`,
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceAndSelectNextDeadline()`,
  and `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndSelectNextDeadline()`
  as no-output backend-drive-to-next-deadline socket-loop steps. Unit coverage
  proves backend drive refreshes endpoint recovery scheduling for a connection
  with in-flight application data and returns the resulting recovery deadline
  without polling output.
- 2026-06-10: Added
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceOrCloseAndArmConnections()`
  for TLS-backed socket loops that need close-propagating peer
  transport-parameter handling across caller-owned connection/backend pairs.
  The sweep stops at the first backend error so the originating connection
  error is not hidden by later backend work. Unit coverage proves an earlier
  backend can queue CRYPTO output, the failing backend enters closing state
  without pulling output, and later backends are not driven.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline()`
  and
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndSelectNextDeadline()`
  as close-propagating no-output backend-drive-to-next-deadline socket-loop
  steps. Unit coverage proves successful backend drive refreshes endpoint
  recovery scheduling and returns the resulting recovery deadline without
  polling output; backend errors continue to use the existing close-propagating
  sweep semantics.
- 2026-06-10: Added
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionAndArmConnections()`
  and
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndArmConnections()`
  for RFC 9368-compatible TLS backend sweeps across caller-owned
  connection/backend pairs. The success sweep aggregates peer
  transport-parameter bytes, compatible-version selection, handshake
  confirmation, and recovery-timer refresh across multiple connections. The
  close-propagating sweep stops at the first peer Version Information error and
  leaves later backends untouched. Unit coverage proves both the two-connection
  compatible-version success path and the first-error close path.
- 2026-06-17: Added
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline()`,
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline()`,
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`,
  and
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`
  as RFC 9368-compatible no-output backend-drive-to-next-deadline socket-loop
  steps. Unit coverage proves compatible Version Information application,
  endpoint recovery scheduling refresh, and recovery deadline selection without
  polling output.
- 2026-06-10: Added `EndpointCryptoBackendDriveDatagramResult` and
  backend-drive-to-datagram loop steps:
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceAndPollDatagram()`,
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndPollDatagram()`,
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceOrCloseAndPollDatagram()`,
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndPollDatagram()`,
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram()`,
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`,
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`,
  and
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`.
  These helpers combine one lifecycle-owned TLS backend sweep with installed-key
  datagram polling across caller-owned connections, without taking ownership of
  connection/backend storage. Unit coverage proves backend-produced Handshake
  CRYPTO can be driven, packetized as a protected installed-key Handshake
  datagram, and consumed by the peer as CRYPTO bytes in the same loop-facing
  API step. The single-connection forms reuse the same sweep path with one
  connection/backend pair and prove one-datagram polling, close-before-poll
  suppression, and compatible-version peer information handling.
- 2026-06-10: Added `EndpointCryptoBackendDriveDatagramDrainResult` and
  backend-drive-to-bounded-drain loop steps:
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams()`,
  and
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`.
  These helpers keep backend progress and bounded caller-owned output draining
  in one lifecycle-owned API step. Unit coverage proves multiple queued
  installed-key datagrams can be drained after a backend sweep, while
  close-propagating backend errors stop before any output slot is initialized
  and compatible-version variants apply or reject peer Version Information
  before draining. The single-connection forms reuse the same sweep path with
  one connection/backend pair and prove one-slot bounded drain, close-before
  drain suppression, and compatible-version peer information handling.
- 2026-06-10: Added `EndpointFeedCryptoBackendDriveDatagramResult` and
  receive-to-backend-to-output loop steps:
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagram()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`,
  and
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`.
  These helpers serve caller-owned connection and backend maps. Routed installed-key
  datagrams are processed, then the selected backend sweep consumes received
  CRYPTO, and installed-key output is polled in the same lifecycle-owned API
  step. Non-routed Version Negotiation, stateless reset, supported Initial
  acceptance, and drop results return without backend driving. Unit coverage
  proves a protected Handshake CRYPTO datagram is routed to the server
  connection, consumed by the backend, answered as a protected Handshake
  datagram, and consumed by the peer as CRYPTO bytes; it also proves dropped
  datagrams do not drive OrClose/compatible backends, and close-propagating
  backend peer-parameter errors stop before output polling. The single-connection
  forms reuse the same lifecycle path with one connection/backend pair and prove
  routed receive-to-backend-to-poll response delivery, close-before-poll
  suppression, compatible peer Version Information application, and
  compatible-version close-before-poll suppression.
- 2026-06-10: Added `EndpointFeedCryptoBackendDriveDatagramDrainResult` and
  receive-to-backend-to-bounded-drain loop steps:
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams()`,
  and
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`.
  These helpers combine routed installed-key receive, selected TLS backend
  sweep, and bounded caller-owned output draining without taking ownership of
  connection/backend storage. Unit coverage proves a routed Handshake CRYPTO
  datagram can drive backend output and drain multiple protected response
  datagrams in the same loop step. The single-connection form reuses the same
  lifecycle path with one connection/backend pair and proves one-slot bounded
  drain plus later peer delivery; the single compatible-version form also
  proves peer Version Information application before bounded drain, while its
  OrClose form queues CONNECTION_CLOSE and stops before output draining when no
  compatible version is selected. Dropped datagrams do not drive any backend,
  and close-propagating peer-parameter errors stop before output draining.
- 2026-06-11: Added cross-connection pending-work-to-output and
  pending-work-to-bounded-drain loop steps:
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndPollDatagram()`
  and
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDrainDatagrams()`.
  These no-backend helpers sweep idle/close/recovery work across caller-owned
  connections before polling or draining installed-key output. Unit coverage
  proves ordinary queued output is not polled when no recovery timer is
  serviced, a serviced PTO wakeup can return one protected output datagram, and
  bounded draining can return PTO output from two caller-owned connections in
  one loop step.
- 2026-06-10: Added pending-work-to-backend-to-output and
  pending-work-to-backend-to-bounded-drain loop steps:
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagram()`,
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram()`,
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`,
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`,
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams()`,
  and
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`.
  These helpers run endpoint pending work before TLS backend progress and
  bounded output draining. Unit coverage proves a no-new-datagram loop tick can
  drive a backend and drain multiple queued installed-key datagrams, while
  close-propagating backend errors stop before output draining. The
  single-connection compatible-version form proves peer Version Information is
  applied before bounded drain, while its OrClose form queues CONNECTION_CLOSE
  and stops before output draining when no compatible version is selected.
  The single-connection output-polling forms prove one-datagram polling,
  close-before-poll suppression, compatible peer Version Information handling,
  and compatible-version close-before-poll suppression.
- 2026-06-10: Added due-deadline-to-backend-to-output and
  due-deadline-to-backend-to-bounded-drain loop steps:
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceAndPollDatagram()`,
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram()`,
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`,
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`,
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams()`,
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams()`,
  and
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`.
  These helpers preserve due recovery datagram ownership: when a deadline
  already emits a protected probe, backend work is skipped; when the due
  deadline has no datagram, backend progress and bounded output draining run in
  the same lifecycle-owned step. The single-connection form stops before
  backend progress after terminal idle/close cleanup; its OrClose form queues
  CONNECTION_CLOSE on backend peer-parameter errors and returns before output
  draining. The single compatible-version form proves peer Version Information
  is applied before bounded drain after an Initial recovery wakeup with no
  installed-key datagram, while its OrClose form queues CONNECTION_CLOSE and
  stops before output draining when no compatible version is selected. Unit
  coverage proves recovery-datagram ownership, non-output deadline backend
  drive, close-propagating drain suppression, and an Initial recovery wakeup
  that continues into Handshake backend output, emits only the first protected
  datagram under a one-slot budget, and delivers the remaining backend CRYPTO
  through a later drain. The single-connection output-polling forms prove the
  same non-output deadline backend progression with one-datagram polling,
  close-before-poll suppression, compatible peer Version Information handling,
  and compatible-version close-before-poll suppression. Cross-connection
  output-polling and bounded-drain forms now also stop before backend progress
  after terminal idle/close cleanup, including close-propagating and
  compatible-version variants.
- 2026-06-10: Extended the socket-facing lifecycle surface with
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeys()`. The helper
  combines version-independent feed classification with routed installed-key
  Handshake, 0-RTT, or 1-RTT protected receive, and uses close-propagating
  receive paths for authenticated plaintext frame errors. Unit coverage now
  proves a client lifecycle can `pollDatagram()` an installed-key 1-RTT packet,
  while a server lifecycle routes and processes that same packet through
  `feedDatagramWithInstalledKeys()`, preserves route evidence, schedules the
  peer ACK, and does not arm a recovery timer for ACK-only receive state.
- 2026-06-05: Extended `examples/tls_openssl_backend_adapter.zig` so the server
  connection probe pulls real pair-transcript 1-RTT secrets through the
  OpenSSL-backed backend, reports handshake confirmation, and discards server
  Handshake packet-number-space keys through the same `driveCryptoBackendInSpace()`
  path. The same probe now also proves the applied peer transport parameters
  enforce the server-side bidirectional stream-count limit. The example now prints
  `server_connection_initial=1511/1184/1223/1184/43/true/3/8/true` for server
  Initial CRYPTO bytes, server output bytes, protected Initial datagram bytes,
  client-read Initial CRYPTO bytes, peer transport-parameter bytes, Handshake
  key installation, OpenSSL secret callback count, eight allowed peer-limited
  bidirectional streams, and the blocked ninth open. It also prints
  `server_connection_application=true/true/true/false` for server 1-RTT key
  install, server confirmation, server Handshake-space discard, and cleared
  server Handshake keys. The paired loopback server now also consumes client
  Handshake CRYPTO over loopback UDP through the backend, pulls peer transport
  parameters plus Handshake/1-RTT secrets, confirms, and clears Handshake keys;
  `peer_backend=36/72/43/36/36/true/true/true/true/false` records CRYPTO bytes,
  datagram bytes, peer transport-parameter bytes, backend inbound/released
  bytes, key installation, confirmation, discard, and cleared Handshake keys.
  The direct OpenSSL server probe now consumes Handshake CRYPTO and reports
  `server_probe_initial=1547/1184/36` plus `server_probe_confirmed=true` for
  total received CRYPTO bytes, server Initial output bytes, Handshake released
  bytes, and confirmation.
  Full endpoint-owned live TLS handshake/socket loop remains pending.
- 2026-06-04: Extended `examples/tls_openssl_backend_adapter.zig` so the
  OpenSSL-backed `TlsBackend` wrapper drives `SSL_do_handshake()` and emits the
  first TLS CRYPTO flight through the existing quicz CRYPTO output path after
  passing local transport parameters into `SSL_set_quic_tls_transport_params()`.
  The example still records OpenSSL callback mode as separate from OpenSSL full
  QUIC mode, accepts Handshake CRYPTO bytes into the wrapper, consumes the
  pair-transcript server transport parameters, delivers real pair-transcript Handshake/1-RTT secrets, and
  inbound CRYPTO through OpenSSL callback boundaries, routes the
  adapter-generated Initial CRYPTO flight through a protected Initial datagram
  over loopback UDP, routes real pair-transcript Handshake CRYPTO through a
  protected Handshake datagram over loopback UDP, then drives loopback UDP
  1-RTT STREAM echo with adapter-installed client keys plus matching peer
  transcript secrets. The same lifecycle owner now services the client
  Application PTO and routes the protected probe to the server without
  re-delivering duplicate stream data. After OpenSSL recv/release consumes
  inbound Handshake CRYPTO, the OpenSSL-backed `handshake_confirmed` callback
  confirms the client and a no-output Handshake drive discards the client
  Handshake packet-number space and keys; paired loopback server-side backend
  confirmation was left for the next adapter step.
  The Initial, Handshake, Application echo, Application PTO, protected close,
  and close/drain timeout cleanup now share one socket/lifecycle loop owner;
  the example prints matching `peer_tp_bytes` and `transcript_tp` values to show
  that the connection-applied peer bytes came from quicz-encoded transport
  parameters configured into the pair transcript, prints
  `transcript_keylog=5/5/773/773` for the full OpenSSL pair transcript, and
  `adapter_keylog=0/0` for the current
  callback-mode wrapper boundary, prints `adapter_pto=62/53/511/1` for PTO deadline, PTO datagram
  bytes, server route, and server ACK largest, prints
  `adapter_key_discard=true/true/true/true/false/false` for client/server
  confirmation, client/server Handshake-space discard, and cleared client/server
  Handshake keys, then prints `adapter_endpoint_routes=3/4/0/0` after retiring
  all registered client/server routes. Full endpoint-owned live TLS
  handshake/socket loop remains pending.
- 2026-06-04: Added `examples/tls_openssl_probe.zig` plus a small C probe
  linked through `pkg-config` OpenSSL. The probe verifies OpenSSL exposes a
  usable QUIC method and that a normal TLS object accepts QUIC TLS callbacks
  plus local transport-parameter bytes; it also records that OpenSSL callback
  mode is distinct from OpenSSL's full QUIC connection mode because
  `SSL_is_quic()` remains false after setting callbacks. Real TLS transcript
  driving remains pending.
- 2026-06-04: Added `examples/tls_c_abi_adapter.zig` and a C-compiled demo
  callback object to prove `TlsBackend` can be driven from an actual C object,
  not only from Zig functions with C calling convention. This still does not
  bind a concrete TLS library, but it verifies the FFI boundary needed by the
  next mature C TLS backend slice.
- 2026-06-04: Added `examples/tls_backend_adapter.zig` plus
  `zig build run-tls-backend-adapter` to prove the C-ABI `TlsBackend` adapter
  contract from a runnable example. The example does not bind a concrete TLS
  library yet; it verifies the narrow adapter seam for local/peer
  transport-parameter bytes, inbound/outbound CRYPTO bytes, Handshake traffic
  secret installation, and handshake confirmation before the real C TLS binding
  slice.
- 2026-06-04: Added a narrow C-ABI `TlsBackend` adapter that converts
  status-code/output-buffer C TLS callbacks into the existing `CryptoBackend`
  drive path. Unit coverage proves local/peer transport-parameter handoff,
  inbound and outbound CRYPTO bytes, Handshake traffic-secret installation, and
  handshake confirmation through the adapter. Binding a concrete C TLS library
  remains pending.
- 2026-06-04: Recorded the implementation strategy that mature non-core
  capabilities should be adapted instead of reimplemented. QUIC transport
  state, packet processing, recovery, endpoint lifecycle, and the Zig API
  remain in scope for `quicz`; TLS and similar adjunct capabilities should use
  maintained libraries behind narrow adapters.
- 2026-06-04: Re-scoped the practical target to a mature QUIC transport
  capability baseline instead of treating every optional QUIC extension as part
  of the first milestone. The new baseline table records required
  first-milestone features, deferred extensions, and current `quicz` status for
  each item.
- 2026-06-04: Added an explicit phase boundary for the current
  mock/installed-key plus endpoint-lifecycle verification phase. The task plan
  now states that the existing socket-backed loopbacks prove protected routing,
  recovery-timer service, and endpoint lifecycle behavior for the experimental
  skeleton, but do not prove full TLS-owned QUIC. The next milestone is an
  endpoint-owned live TLS handshake/socket loop backed by a C TLS library via a
  narrow Zig `TlsBackend` adapter, with transport-parameter transcript handoff,
  traffic-secret ownership, lifecycle cleanup, and external interop evidence or
  a documented interop blocker.
- 2026-06-02: Switched UDP Version Negotiation follow-up server
  transport-parameter validation to TLS extension bytes. The server now encodes
  local transport parameters and the follow-up client parses/applies those
  bytes, preserving Original DCID, Initial SCID, and Version Information
  validation; the example also proves malformed transport-parameter bytes queue
  `TRANSPORT_PARAMETER_ERROR`; `run-udp-endpoint-loopback` now prints
  `server_tp_bytes`, `malformed_tp_close`, and `followup_timers`.
- 2026-06-02: Added server transport-parameter validation to the UDP Version
  Negotiation follow-up loopback. After the protected server Initial is routed
  to the follow-up client, the example applies the server's authenticated
  transport parameters and verifies the selected Version Information;
  `run-udp-endpoint-loopback` now prints `server_tp_version=0x6b3343cf`.
- 2026-06-02: Added Version Negotiation follow-up Original DCID evidence.
  The lifecycle protected follow-up Initial test now asserts that the returned
  follow-up connection records the old Initial Destination CID for later
  transport-parameter validation; `run-udp-endpoint-loopback` now prints
  `followup_odcid_len=8`.
- 2026-06-02: Added selected compatible-version reporting to
  `CryptoBackendProgress`. Compatible backend peer-parameter drives now return
  the selected QUIC version directly from the drive result, while strict drives
  keep the field null; `run-crypto-stream` prints the selected version from
  backend progress.
- 2026-06-02: Added compatible Version Information handoff through
  `CryptoBackend` peer transport-parameter bytes.
  `driveCryptoBackendInSpaceWithCompatibleVersion()` and the close-propagating
  variant apply backend-provided peer parameters with explicit RFC 9368
  compatibility before pulling backend output; `run-crypto-stream` now prints
  `backend_compatible_version selected=0x6b3343cf peer_versions=2`.
- 2026-06-02: Added server-side compatible Version Information application.
  `Connection` now stores a peer Version Information snapshot, exposes
  `peerVersionInformation()` / `selectPeerCompatibleVersion()`, and offers
  byte and close-propagating compatible apply paths that require the selected
  version to match the server connection's configured `chosen_version`.
  `run-transport-parameters` now prints `compatible_selected=0x6b3343cf` and
  `compatible_peer_versions=2`.
- 2026-06-02: Added explicit RFC 9368 compatible-version selection helpers.
  `VersionCompatibility` records directional first-flight compatibility and
  `selectCompatibleVersion()` only selects non-reserved client-advertised
  versions whose first flight can be converted by caller-provided compatibility
  rules. `run-codec` now prints `compatible_selected=0x6b3343cf`.
- 2026-06-02: Added RFC 9368 close-code classification for parsed
  `version_information` semantic failures. `applyPeerTransportParameterBytesOrClose()`
  now preserves the older rollback-only API surface while queueing
  `VERSION_NEGOTIATION_ERROR` for downgrade/negotiation failures and
  `TRANSPORT_PARAMETER_ERROR` for malformed transport parameters; `run-codec`
  now prints `downgrade_close=0x11`.
- 2026-06-03: Added UDP close lifecycle close/deadline evidence and endpoint
  lifecycle route cleanup after close/drain timeout expiry.
  `udp_close_lifecycle_loopback` now asserts and prints close/drain deadlines
  for lifecycle-routed protected receive auto-close and the explicit
  CONNECTION_CLOSE path, plus remaining route/reset-token counts after
  connection-handle retirement.
- 2026-06-03: Added controlled-clock persistent-congestion recovery-period
  reset evidence. Persistent congestion now has direct `Recovery` assertions and
  `run-loss-recovery` output proving that it clears the current NewReno recovery
  period, resets congestion-avoidance credit, and allows a later congestion
  event to establish a fresh recovery start; the example now prints
  `recovery_cleared=true` and `reentry_start=1900`.
- 2026-06-02: Added controlled-clock NewReno recovery-period ACK accounting
  coverage. `Recovery` tests now verify that an ACK for a packet sent at the
  recovery-start boundary clears PTO backoff, updates RTT, and removes bytes in
  flight without growing `congestion_window` or accumulating congestion-avoidance
  credit; `loss_recovery` now prints
  `recovery ACK accounting cwnd=6000 latest_rtt=80 inflight=10800 credit=0`.
- 2026-06-02: Added socket-backed UDP installed-key 0-RTT PTO recovery
  coverage. `udp_pto_recovery_loopback` now emits an installed-key 0-RTT
  RESET_STREAM over loopback UDP, services the Application PTO through
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedZeroRttDatagramWithInstalledKeys()`,
  verifies the protected 0-RTT retransmission under packet number 1, routes it
  to the accepting server, and delivers a 1-RTT ACK that clears client recovery
  state. The example now prints `zero_rtt_probe_bytes=37` and
  `zero_rtt_ack_bytes=27`.
- 2026-06-02: Added
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedZeroRttDatagramWithInstalledKeys()`.
  The endpoint lifecycle can now service a due Application recovery timer and
  emit a protected 0-RTT long-header PTO/loss probe while `Connection` owns
  installed local 0-RTT keys. Tests cover before-deadline no-op, RESET_STREAM
  retransmission before PING fallback, installed-key 0-RTT packet opening, and
  timer re-arm; `endpoint_recovery_timers` now prints
  `installed_zero_rtt_pto_bytes=37`.
- 2026-06-02: Added
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedHandshakeDatagramWithInstalledKeys()`.
  The endpoint lifecycle can now service a due Handshake recovery timer and
  emit a protected long-header PTO/loss probe while `Connection` owns installed
  Handshake keys. Tests cover before-deadline no-op, Handshake PTO probe
  emission, installed-key long-packet opening, Initial-space discard, and timer
  re-arm; `endpoint_recovery_timers` now prints
  `installed_handshake_pto_bytes=36`.
- 2026-06-02: Added
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys()`.
  The endpoint lifecycle can now service a due Application recovery timer and
  emit a protected 1-RTT PTO/loss probe while `Connection` owns installed
  1-RTT keys. Tests cover before-deadline no-op, PTO probe emission, installed
  key packet opening, and ACK disarm; `endpoint_recovery_timers` now prints
  `installed_pto_bytes=25`.
- 2026-06-02: Routed long-header Handshake PTO service through the
  socket-backed UDP PTO loopback. `udp_pto_recovery_loopback` now performs an
  Initial CRYPTO/ACK exchange over loopback UDP, services the resulting
  Handshake anti-deadlock PTO through `EndpointConnectionLifecycle`, delivers
  the protected long-header PING to the server, returns a Handshake ACK, and
  prints `long_pto_bytes=36` plus `long_ack_bytes=38`.
- 2026-06-02: Added
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedLongDatagram()`.
  The endpoint lifecycle can now service a due Initial/Handshake recovery timer
  and emit the caller-keyed protected long-header PTO/loss probe in the same
  route/timer owner. Tests cover before-deadline no-op, Handshake PTO probe
  emission, Initial-space discard after the Handshake send, and timer re-arm;
  `endpoint_recovery_timers` now prints `long_pto_bytes=36` as deterministic
  evidence.
- 2026-06-02: Added
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedShortDatagram()`.
  The endpoint lifecycle can now service a due Application recovery timer and
  emit the caller-keyed protected short PTO/loss probe in one route/timer owner.
  Tests cover before-deadline no-op, PTO probe emission, and ACK disarm;
  `udp_pto_recovery_loopback` now uses the helper for PING, STREAM, and CRYPTO
  PTO probes over loopback UDP.
- 2026-06-02: Discarded Handshake packet-number space after a TLS backend
  confirms the handshake and the final outbound Handshake CRYPTO frame is
  actually sent. The connection now keeps installed Handshake keys while
  backend output is still queued, then clears the Handshake space and keys on
  frame-payload or protected long-packet send commit. Tests cover both send
  paths; `crypto_stream` prints post-send discard evidence.
- 2026-06-02: Refreshed RFC 9002 persistent-congestion RTT state. When the ACK
  that establishes persistent congestion also produces the newest RTT sample,
  the recovery path now resets `min_rtt` to that sample and re-syncs the shared
  RTT estimate across packet number spaces. Tests cover direct recovery state
  and connection-level ACK handling; `loss_recovery` prints the refreshed
  `min_rtt` evidence.
- 2026-06-02: Added client no-in-flight anti-deadlock PTO handling. When a
  client Initial/Handshake ACK or loss event leaves no ack-eliciting packets in
  flight before the handshake is confirmed, the recovery timer now starts from
  that event and queues an Initial probe, or a Handshake probe once Handshake
  keys are installed. Tests cover Initial and Handshake selection; `pto_recovery`
  prints the Initial anti-deadlock probe evidence.
- 2026-06-02: Serviced expired PTO when anti-amplification unblocks. A server
  that was at the anti-amplification limit now records the newly received
  datagram bytes, re-arms the aggregate PTO timer, and immediately services the
  timer if the original deadline elapsed while the server was blocked. Tests
  cover re-arm without service and expired-deadline service; `pto_recovery`
  prints the unblock service evidence.
- 2026-06-02: Added socket-backed UDP installed-key echo loopback coverage.
  `udp_echo_loopback` uses connection-owned 1-RTT keys, real loopback UDP
  sockets, and `EndpointConnectionLifecycle` route ownership to deliver a
  client STREAM, echo the same bidirectional stream data from the server, route
  the final ACK, and print request/echo payload equality plus
  bytes-in-flight/timer-state evidence.
- 2026-06-02: Extended socket-backed UDP CryptoBackend 1-RTT loopback coverage
  to echo. `udp_crypto_backend_loopback` now combines mock `CryptoBackend`
  1-RTT traffic-secret handoff and modeled handshake confirmation with
  lifecycle-routed client STREAM delivery, server bidirectional STREAM echo,
  final ACK routing, and bytes-in-flight/timer-state evidence over real
  loopback UDP sockets.
- 2026-06-02: Exposed installed-key 1-RTT key-update ACK-gate state.
  `Connection.pendingOneRttKeyUpdateAckThreshold()` returns the packet-number
  threshold that must be ACKed before another local key update can start, and
  `udp_key_update_loopback` now prints first/second threshold values plus ACK
  gate clearing evidence over lifecycle-routed UDP.
- 2026-06-02: Added key-phase generation observability for installed 1-RTT key
  updates. `Aes128KeyPhaseState.keyUpdateCount()` and the connection local/peer
  count accessors expose send-side and receive-side key-phase advances without
  mutating state; `udp_key_update_loopback` now prints client local and server
  peer update-count evidence across the ACK-gated update flow.
- 2026-06-02: Exposed retained key-generation windows for installed 1-RTT key
  updates. `Aes128KeyPhaseState.retainsKeyGeneration()` and the connection
  local/peer accessors let endpoint loops prove old generations are no longer
  retained after a key update while current/next generations remain available;
  `udp_key_update_loopback` now prints old-generation discard evidence.
- 2026-06-02: Extended UDP installed-key key-update loopback through the second
  update packet. After the first ACK clears the key-update gate, the client now
  sends a second key-phase PING, the server advances to generation 2 and drops
  generation 1 from its retained window, and a second ACK clears the client's
  second update gate.
- 2026-06-02: Added stale old-generation packet rejection evidence after the
  second installed-key update. Tests and `udp_key_update_loopback` now craft a
  generation-1 packet at the next expected packet number after the server has
  advanced to generation 2, prove authentication fails, and verify peer packet
  number, pending ACK, and key-update count remain unchanged.
- 2026-06-01: Added public `StreamState` snapshots through
  `Connection.streamState()`. The read-only API reports modeled send-side
  FIN/reset closure, receive-side final-size/reset state, buffered receive
  bytes, and read offsets without creating streams or mutating state. Tests
  cover unknown/invalid stream IDs, FIN delivery, receive final-size snapshots,
  and RESET_STREAM send/receive snapshots; `stream_reset` prints the reset
  snapshot evidence.
- 2026-06-01: Extended `StreamState` with receive-side STOP_SENDING
  observability. The snapshot now exposes whether this endpoint has queued or
  sent STOP_SENDING for a stream receive side, while preserving the existing
  receive lifecycle state and later RESET_STREAM final-size/error snapshots.
  Tests cover the stop request and peer reset response, and `stop_sending`
  prints the snapshot evidence.
- 2026-06-01: Refined `StreamState` receive-side snapshots with Data Read and
  Reset Read states. `recvOnStream()` now marks a FIN stream read only when the
  application consumes or observes all final bytes, and marks a reset stream
  read only when the application observes `StreamClosed`. Tests cover data,
  zero-length FIN, and reset observation; `stream_reset` prints the reset-read
  snapshot evidence.
- 2026-06-01: Added send-side Data Acked and Reset Acked `StreamState`
  snapshots. ACK processing now marks FIN streams acked only after every STREAM
  frame through FIN has left queued and in-flight recovery state, and marks
  RESET_STREAM acked when the reset frame is acknowledged. Tests cover split FIN
  ACK ordering and RESET_STREAM ACK observation; `stream_reset` prints the
  reset-acked evidence.
- 2026-06-01: Suppressed obsolete RESET_STREAM retransmission after the reset is
  acknowledged. ACK-driven loss and PTO control-frame probe selection now skip a
  RESET_STREAM whose send stream is already `reset_acked`, so a stale in-flight
  reset packet cannot requeue another reset after the retransmission has been
  acknowledged. Tests cover the PTO retransmission/ACK/loss race, and
  `pto_recovery` prints the suppression evidence.
- 2026-06-01: Added controlled-clock evidence that ACK-driven lost packets must
  be contiguous before they can establish RFC 9002 persistent congestion.
  Non-contiguous lost packet numbers spanning the persistent-congestion duration
  now keep the connection on the normal NewReno recovery path, and
  `loss_recovery` prints the suppressed persistent-congestion case.
- 2026-06-01: Added explicit close-on-error evidence for
  `STREAMS_BLOCKED_BIDI` and `STREAMS_BLOCKED_UNI` values above the RFC 9000
  stream-count limit. Rollback-only receive now has connection-level coverage
  preserving peer blocked state, and `processDatagramOrClose()` queues
  `FRAME_ENCODING_ERROR` CONNECTION_CLOSE for both frame types.
  `graceful_close` prints both invalid STREAMS_BLOCKED close paths.
- 2026-06-01: Added explicit ACK_ECN packet-type close evidence. 0-RTT
  `ACK_ECN` now has rollback-only forbidden-frame coverage and
  `processDatagramForPacketTypeOrClose()` queues `PROTOCOL_VIOLATION`
  CONNECTION_CLOSE for the same packet-type violation. `graceful_close` prints
  the invalid 0-RTT ACK_ECN close path.
- 2026-06-01: Added explicit ACK_ECN close-on-error evidence. Invalid
  ACK_ECN ranges now have direct `FRAME_ENCODING_ERROR` close coverage, and
  ACK_ECN frames that acknowledge unsent packet numbers have direct
  `PROTOCOL_VIOLATION` close coverage. `graceful_close` prints both ACK_ECN
  close paths.
- 2026-06-01: Added explicit close-on-error evidence for stream-control frame
  stream validation. Invalid `STOP_SENDING` and `MAX_STREAM_DATA` frames for
  receive-only streams now have direct `STREAM_STATE_ERROR` close coverage, and
  `STREAM_DATA_BLOCKED` beyond the receive stream-count limit has direct
  `STREAM_LIMIT_ERROR` close coverage. `graceful_close` prints the three
  stream-control close paths.
- 2026-06-01: Added explicit close-on-error evidence for invalid ACK ranges.
  The frame codec still rejects ranges that underflow packet numbers or whose
  first range exceeds the largest acknowledged packet, and
  `processDatagramOrClose()` now has direct coverage showing those decode
  failures queue `FRAME_ENCODING_ERROR`. `graceful_close` prints invalid ACK
  range close evidence.
- 2026-06-01: Added semantic close propagation for ACK frames that acknowledge
  unsent packet numbers. The rollback-only receive path still rejects the ACK
  before recovery side effects, and close-on-error receive now queues a
  `PROTOCOL_VIOLATION` CONNECTION_CLOSE. `graceful_close` prints the ACK close
  evidence.
- 2026-06-01: Added semantic close propagation for conflicting STREAM bytes.
  The rollback-only receive path still rejects changed data at a repeated
  offset without committing it, while close-on-error receive now maps confirmed
  byte conflicts to `PROTOCOL_VIOLATION` and leaves identical retransmissions
  on the existing non-close path. `graceful_close` prints the stream-conflict
  close evidence.
- 2026-06-01: Added a per-packet-number-space CRYPTO receive-buffer limit.
  `Connection.Config.max_crypto_buffer_size` now bounds the largest accepted
  CRYPTO end offset; rollback-only receive APIs reject over-limit CRYPTO
  without mutating buffered bytes, and close-on-error receive APIs queue a
  `CRYPTO_BUFFER_EXCEEDED` CONNECTION_CLOSE. `crypto_stream` prints the
  buffer-limit close evidence.
- 2026-05-30: Added caller-keyed protected Initial/Handshake
  `CONNECTION_CLOSE` emission through `pollProtectedLongDatagram()`. Pending
  transport close frames now bypass the closing-state guard, prefer Handshake
  keys when supplied, fall back to Initial keys, keep close packets out of
  bytes-in-flight, and retain retransmission until the close deadline;
  `graceful_close` prints both protected long close paths.
- 2026-05-30: Added protected Handshake CONNECTION_CLOSE emission for
  installed Handshake keys. `pollProtectedHandshakeDatagramWithInstalledKeys()`
  now prioritizes pending transport close frames before the closing-state guard,
  emits a protected Handshake `CONNECTION_CLOSE`, enters closing after the send,
  and lets peers receive draining close diagnostics; `crypto_stream`
  demonstrates backend transport-parameter errors reaching protected Handshake
  close.
- 2026-05-30: Added close-propagating CryptoBackend transport-parameter drive
  coverage. `driveCryptoBackendInSpaceOrClose()` now preserves the existing
  backend-drive success behavior while routing invalid peer transport-parameter
  extension bytes through `applyPeerTransportParameterBytesOrClose()`, so the
  next send is a `TRANSPORT_PARAMETER_ERROR` CONNECTION_CLOSE and backend
  output is not pulled after the error.
- 2026-05-30: Added socket-backed UDP CryptoBackend Handshake CRYPTO stream
  coverage. `udp_crypto_stream_loopback` drives mock `CryptoBackend`
  Handshake traffic-secret installation, local/peer transport-parameter byte
  handoff, CRYPTO flight production/consumption, lifecycle-routed protected
  Handshake datagrams, and routed ACK cleanup over real loopback UDP.
- 2026-05-30: Added socket-backed UDP CryptoBackend 1-RTT handoff coverage.
  `udp_crypto_backend_loopback` drives a mock `CryptoBackend` to install
  connection-owned 1-RTT traffic secrets and mark the modeled handshake
  confirmed, then uses `EndpointConnectionLifecycle` over real loopback UDP to
  route a protected STREAM and ACK cleanup.
- 2026-05-30: Added socket-backed UDP installed-key HANDSHAKE_DONE loopback
  coverage. `udp_handshake_done_loopback` delivers a server HANDSHAKE_DONE
  frame with connection-owned 1-RTT keys over real loopback UDP through
  `EndpointConnectionLifecycle`, verifies server/client-side handshake
  confirmation and Handshake key discard, then prints ACK pending/cleared
  evidence while routing the ACK back to clear server Application-space bytes
  in flight.
- 2026-06-02: Exposed public connection-state evidence in
  `udp_handshake_done_loopback`. The loopback now asserts and prints
  server/client `handshakeState=confirmed` and `connectionState=active` after
  lifecycle-routed HANDSHAKE_DONE delivery, tying the existing key-discard and
  ACK-cleanup evidence to the modeled connection state machine.
- 2026-05-29: Added socket-backed UDP installed-key 1-RTT STREAM loopback
  coverage. `udp_one_rtt_loopback` installs connection-owned 1-RTT traffic
  secrets, confirms the modeled handshake, delivers a protected STREAM frame
  over real loopback UDP through `EndpointConnectionLifecycle`, and verifies
  routed ACK cleanup for the Application packet number space.
- 2026-06-04: Extended `udp_one_rtt_loopback` with serviced installed-key 1-RTT
  PTO evidence. The example now records the client Application PTO deadline,
  services it through
  `serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys()`, routes
  the protected 1-RTT STREAM PTO probe over loopback UDP, and verifies the
  duplicate STREAM data is discarded while the server ACKs the PTO packet number.
- 2026-05-29: Added socket-backed UDP installed-key Handshake loopback
  coverage. `udp_handshake_keys_loopback` uses connection-installed Handshake
  traffic secrets over real loopback UDP sockets through
  `EndpointConnectionLifecycle`, delivers Handshake CRYPTO in both directions,
  and verifies routed Handshake ACK cleanup.
- 2026-06-04: Extended `udp_handshake_keys_loopback` with serviced installed-key
  Handshake PTO evidence. The example now services the server Handshake PTO
  through `serviceRecoveryTimerAndPollProtectedHandshakeDatagramWithInstalledKeys()`,
  routes the protected Handshake CRYPTO PTO probe over loopback UDP, verifies the
  duplicate CRYPTO data is not delivered again, and then ACKs both server
  Handshake packets back to zero bytes in flight.
- 2026-05-29: Added socket-backed UDP 0-RTT loopback coverage.
  `udp_zero_rtt_loopback` uses installed 0-RTT keys over real loopback UDP
  sockets through `EndpointConnectionLifecycle`, validates that receive
  processing is rejected before explicit 0-RTT acceptance, delivers early STREAM
  data after acceptance with ACK evidence, clears the client's bytes in flight
  with a routed 1-RTT ACK, and proves client/server 0-RTT key discard across
  the 1-RTT boundary.
- 2026-06-02: Added rejection-driven installed-key 0-RTT discard evidence to
  `udp_zero_rtt_loopback`. The loopback now rejects early-data processing before
  acceptance, explicitly calls `rejectZeroRtt()`, proves the peer 0-RTT receive
  keys and accepted flag are cleared, and verifies a later accept attempt fails.
- 2026-06-04: Extended `udp_zero_rtt_loopback` with serviced installed-key
  0-RTT PTO evidence. The example now arms the endpoint recovery timer after
  modeled handshake confirmation, services the client's Application PTO through
  `serviceRecoveryTimerAndPollProtectedZeroRttDatagramWithInstalledKeys()`,
  routes the protected 0-RTT STREAM PTO probe over loopback UDP, and verifies
  the duplicate STREAM data is discarded while ACK largest advances to the PTO
  packet number.
- 2026-06-03: Added lifecycle-owned address-token validation unblocking.
  `EndpointConnectionLifecycle.validateAddressTokenForPathAndArmConnection()`
  now validates a path-bound endpoint token, records replay state, marks the
  server peer address validated, and refreshes endpoint recovery scheduling in
  one step. Tests prove wrong-path tokens do not unblock or record replay, while
  valid NEW_TOKEN values unblock a server and arm its existing recovery timer;
  `run-address-validation` and `run-udp-address-validation-loopback` now use the
  lifecycle helper for future-server unblock evidence.
- 2026-06-04: Added lifecycle-owned Retry token validation and consumption.
  `EndpointConnectionLifecycle.validateRetryTokenForPathAndArmConnection()`
  checks pending one-time Retry state before recording endpoint replay state,
  validates the path-bound Retry token, consumes the connection Retry token,
  unblocks anti-amplification, and refreshes endpoint recovery scheduling in one
  step. Tests prove wrong-path and missing-pending-token failures do not record
  replay or unblock the server, while replayed valid Retry tokens leave pending
  connection state untouched; `run-retry-token` and `run-udp-retry-loopback` now
  use the lifecycle helper for Retry token acceptance.
- 2026-06-04: Added lifecycle-owned Retry follow-up Initial acceptance.
  `EndpointConnectionLifecycle.processRetryValidatedProtectedInitialDatagram()`
  keeps the post-Retry server receive path on the endpoint lifecycle owner:
  route selection, Initial accept metadata extraction, path-bound Retry token
  validation/consumption, and protected Initial processing now happen in one
  helper. Tests prove missing pending Retry state does not record replay or
  process the packet; `run-udp-retry-loopback` now uses the helper for the
  Retry-derived client Initial.
- 2026-06-04: Routed address-validation protected HANDSHAKE_DONE/NEW_TOKEN
  emission through endpoint lifecycle polling. `address_validation` and
  `udp_address_validation_loopback` now use
  `EndpointConnectionLifecycle.pollProtectedShortDatagram()` for server-side
  HANDSHAKE_DONE and NEW_TOKEN packets before lifecycle-routed client delivery,
  so the same lifecycle owner mirrors protected short-packet send timers. Both
  examples now print `emit_timers=1`.
- 2026-06-04: Tightened socket-backed UDP echo timer-state evidence.
  `udp_echo_loopback` and `udp_crypto_backend_loopback` now assert and print both
  endpoint lifecycle timer counts after the final ACK is routed: the client
  final-ACK side still exposes one endpoint timer, and the server side is fully
  disarmed with zero bytes in flight.
- 2026-06-04: Extended `udp_echo_loopback` with serviced server-side 1-RTT PTO
  evidence. The echo loopback now re-arms the server Application recovery timer
  after the client receives echoed STREAM data, services it through
  `serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys()`, routes
  the protected echo STREAM PTO probe over loopback UDP, verifies the duplicate
  STREAM data is discarded while the client ACK largest advances, and then uses
  the final ACK to clear server bytes in flight and disarm the server timer.
- 2026-06-04: Extended `udp_crypto_backend_loopback` installed-key recovery
  timer evidence. The mock `CryptoBackend` 1-RTT loopback now asserts and prints
  the client STREAM send-side PTO deadline, services that due Application timer
  through `serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys()`,
  routes the resulting protected STREAM PTO probe over loopback UDP, verifies
  the duplicate STREAM is not delivered again, services the server echo
  send-side PTO through the same installed-key endpoint helper, routes that
  protected echo STREAM PTO probe back to the client, verifies duplicate echo
  data is discarded while the client ACK largest advances, then verifies the
  final routed ACK disarms the server lifecycle timer and clears server bytes in
  flight.
- 2026-05-29: Added socket-backed UDP address-validation loopback coverage.
  `udp_address_validation_loopback` delivers protected HANDSHAKE_DONE and
  NEW_TOKEN over real loopback UDP sockets through
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()`, then
  validates NEW_TOKEN path binding with changed-path rejection output,
  originating-version binding, secret rotation, replay snapshot restore
  rejection, and lifecycle-owned address-validation block/unblock output.
- 2026-05-29: Routed the address-validation protected HANDSHAKE_DONE and
  NEW_TOKEN receive paths through the endpoint lifecycle helper.
  `address_validation` now registers the client receive CID with
  `EndpointConnectionLifecycle` and uses
  `processRoutedProtectedShortDatagram()` for both protected short packets
  before validating NEW_TOKEN path/version binding and replay rejection.
- 2026-05-29: Routed UDP Retry follow-up protected Initial receives through
  the endpoint lifecycle helper. `udp_retry_loopback` now uses
  `EndpointConnectionLifecycle.processRoutedProtectedInitialDatagram()` for
  both the Retry-derived client Initial received by the server and the protected
  server Initial received by the client, while keeping the unprotected Retry
  packet itself on the route-only Retry processing path.
- 2026-05-29: Routed remaining caller-keyed short-packet receives in
  `endpoint_recovery_timers` through the endpoint lifecycle helper. The
  caller-keyed 0-RTT ACK cleanup, caller-keyed 1-RTT PING delivery, and
  caller-keyed 1-RTT ACK cleanup paths now use
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` instead
  of a separate `routeDatagram()` plus `processProtectedShortDatagram()` pair.
- 2026-05-29: Routed UDP path-validation protected receives through the
  endpoint lifecycle helper. `udp_path_validation_loopback` now registers the
  client's new-port receive CID with its lifecycle owner, then uses
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` for both
  the protected PATH_CHALLENGE delivery and the `path_changed` protected
  PATH_RESPONSE receive. The example also sends a protected PING on the new
  path before PATH_RESPONSE validation and verifies that the lifecycle helper
  reports `path_changed` without committing a route update.
- 2026-05-29: Routed UDP close lifecycle protected receive through the
  endpoint lifecycle helper. `udp_close_lifecycle_loopback` now uses
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` for the
  protected CONNECTION_CLOSE receive path, so route selection, connection-handle
  validation, routed DCID length selection, packet processing, and
  recovery-timer refresh stay on the same lifecycle owner that later retires
  the route and emits the stateless reset.
- 2026-05-30: Added a socket-backed protected receive auto-close path to
  `udp_close_lifecycle_loopback`. The example now sends an authenticated
  malformed protected short packet through loopback UDP, processes it with
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramOrClose()`,
  sends the queued CONNECTION_CLOSE back to the client, and keeps the existing
  close-triggered route retirement/stateless reset scenario unchanged.
- 2026-05-30: Added semantic frame-processing close propagation for the
  close-on-error receive wrappers. `processDatagramForPacketTypeOrClose()`
  now preserves the rollback-only behavior of the base receive path while
  queuing CONNECTION_CLOSE for classified STREAM/RESET_STREAM flow-control,
  stream-limit, and final-size failures. Tests cover all three mappings, and
  `examples/graceful_close.zig` prints the semantic auto-close evidence.
- 2026-05-30: Added semantic close propagation for unmatched PATH_RESPONSE
  frames. The close-on-error receive wrappers now map a PATH_RESPONSE without a
  matching outstanding PATH_CHALLENGE to `PROTOCOL_VIOLATION`, while matching
  PATH_RESPONSE frames continue to clear the challenge without closing; tests
  cover both branches and `examples/graceful_close.zig` prints the auto-close
  evidence.
- 2026-05-30: Added semantic close propagation for role-specific
  NEW_TOKEN/HANDSHAKE_DONE violations. Server-side close-on-error receive now
  maps peer NEW_TOKEN and HANDSHAKE_DONE frames to `PROTOCOL_VIOLATION`, while
  the existing client-side accept/storage paths and rollback-only receive APIs
  stay unchanged; tests cover both close paths and `examples/graceful_close.zig`
  prints the auto-close evidence.
- 2026-05-30: Added semantic close propagation for active connection-ID limit
  overflow. Close-on-error receive now maps NEW_CONNECTION_ID frames that would
  exceed `active_connection_id_limit` after applying `retire_prior_to` to
  `CONNECTION_ID_LIMIT_ERROR`; tests cover both the overflow close and a legal
  replacement that retires an old CID first, and `examples/graceful_close.zig`
  prints the auto-close evidence.
- 2026-05-30: Added semantic close propagation for invalid NEW_CONNECTION_ID
  reuse. Close-on-error receive now maps sequence/CID mismatches and stateless
  reset token reuse to `PROTOCOL_VIOLATION`, while exact duplicate
  NEW_CONNECTION_ID frames remain idempotent; tests cover all three branches,
  and `examples/graceful_close.zig` prints the reset-token-reuse auto-close
  evidence.
- 2026-05-30: Tightened the rollback-only NEW_CONNECTION_ID receive path to
  reject reusing an existing peer-issued CID value under a different sequence
  number. The base `processDatagram()` path now matches the close-on-error
  classifier's CID-reuse validation while preserving ACK and active-CID state
  on invalid payload rollback.
- 2026-05-30: Made local NEW_CONNECTION_ID issuance account for the
  replacement frame's `retire_prior_to` before enforcing the peer's active CID
  limit. A server at the peer-advertised CID limit can now issue a valid
  replacement CID when the same frame retires an older sequence, while
  non-replacement overflow remains rejected.
- 2026-05-30: Added semantic close propagation for invalid
  RETIRE_CONNECTION_ID frames. Close-on-error receive now maps unknown or
  unsent local CID sequence numbers to `PROTOCOL_VIOLATION`, while sent local
  CIDs can still be retired without closing; tests cover both close branches
  and the accept branch, and `examples/graceful_close.zig` prints the
  retire-CID auto-close evidence.
- 2026-05-29: Routed UDP ECN validation loopback protected receives through
  the endpoint lifecycle helper. `udp_ecn_validation_loopback` now uses
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` for the
  modeled ECT(0) PING, ACK_ECN validation, ECN-CE ACK_ECN congestion response,
  and second PING receive paths, while the existing lifecycle ECN path-state
  refresh remains the endpoint-owned post-validation mirror step.
- 2026-05-29: Routed UDP spin-bit loopback protected receives through the
  endpoint lifecycle helper. `udp_spin_bit_loopback` now uses
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` for the
  first false-spin PING/ACK, migrated true-spin PING, and reset-spin ACK
  receive paths while keeping server/client route-update spin reset on the
  lifecycle owner.
- 2026-05-29: Routed UDP connection-ID loopback protected receives through the
  endpoint lifecycle helper. `udp_connection_ids_loopback` now uses
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` for
  protected NEW_CONNECTION_ID, ACK, RETIRE_CONNECTION_ID, and final ACK receive
  paths, while keeping unprotected route probes and retired-token lookup as
  route-only endpoint checks.
- 2026-06-02: Added
  `EndpointConnectionLifecycle.issueConnectionIdRoute()` to bridge
  `Connection.issueConnectionId()` with lifecycle-owned endpoint route
  registration. The helper registers the active route with the same stateless
  reset token carried in NEW_CONNECTION_ID, applies `retire_prior_to`, and
  rolls back the just-issued local CID if route registration fails. Tests cover
  successful replacement route retirement and duplicate route-sequence rollback;
  `connection_ids` and `udp_connection_ids_loopback` now use the lifecycle
  helper instead of manually syncing connection and route state.
- 2026-05-29: Routed UDP flow-control loopback receives through the endpoint
  lifecycle helper. `udp_flow_control_loopback` now uses
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` for
  protected STREAM, STREAM_DATA_BLOCKED, MAX_DATA/MAX_STREAM_DATA, resumed
  STREAM with FIN final-size evidence, and final ACK receive paths, so route selection, connection-handle
  validation, routed DCID length selection, packet processing, and
  recovery-timer refresh stay on the lifecycle owner.
- 2026-05-29: Routed UDP recovery loopback receives through endpoint lifecycle
  helpers. `udp_loss_recovery_loopback`, `udp_congestion_recovery_loopback`,
  `udp_pto_recovery_loopback`, and `udp_stream_retransmission_loopback` now use
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` for
  socket receive paths, so route selection, connection-handle validation,
  routed DCID length selection, protected packet processing, and recovery-timer
  refresh share the lifecycle-owned boundary already used by endpoint tests.
- 2026-05-29: Added lifecycle-owned routed protected long-datagram processing.
  `EndpointConnectionLifecycle.processRoutedProtectedLongDatagram()` now returns
  both the selected route and the processed long-packet count while combining
  endpoint route selection, connection-handle validation, coalesced long-packet
  processing, and recovery-timer refresh. Tests cover mismatch rejection, routed
  DCID validation, processed-count preservation, Initial ACK cleanup, and timer
  disarm; `endpoint_recovery_timers` now uses it for generic protected Initial
  receive paths.
- 2026-05-29: Added lifecycle-owned routed explicit key-update and
  caller-owned key-phase short-packet processing.
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithKeyUpdate()`
  and `processRoutedProtectedShortDatagramWithKeyPhaseState()` now combine
  endpoint route selection, connection-handle validation, routed DCID length
  selection, caller-owned key-phase/key-update processing, and recovery-timer
  refresh. Tests cover mismatch rejection, routed DCID validation, key-phase
  preservation before route validation, ACK cleanup, and timer disarm;
  `endpoint_recovery_timers` now uses the helpers for explicit key-phase
  receive paths.
- 2026-05-29: Added lifecycle-owned routed caller-keyed long-packet
  processing. `EndpointConnectionLifecycle.processRoutedProtectedLongDatagramInSpace()`
  and `processRoutedProtectedZeroRttDatagram()` now combine endpoint route
  selection, connection-handle validation, caller-supplied key processing, and
  recovery-timer refresh for direct Handshake and 0-RTT receive paths. Tests
  cover mismatch rejection, routed DCID validation, Handshake ACK cleanup, and
  0-RTT STREAM delivery; `endpoint_recovery_timers` now uses the helpers for
  caller-keyed long-packet receive paths.
- 2026-05-29: Added lifecycle-owned routed installed-key Handshake and 0-RTT
  long-packet processing.
  `EndpointConnectionLifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys()`
  and `processRoutedProtectedZeroRttDatagramWithInstalledKeys()` now combine
  endpoint route selection, connection-handle validation, connection-owned TLS
  key processing, and recovery-timer refresh. Tests cover mismatch rejection,
  routed DCID validation, Handshake ACK cleanup, and 0-RTT STREAM delivery;
  `endpoint_recovery_timers` now uses the helpers for installed-key long-packet
  receive paths.
- 2026-05-29: Added lifecycle-owned routed installed-key protected short-packet
  processing. `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeys()`
  now combines endpoint route selection, connection-handle validation, routed
  DCID length selection, connection-owned 1-RTT key processing, and recovery-timer
  refresh. Tests cover route mismatch rejection and ACK cleanup; `udp_key_update_loopback`
  and `endpoint_recovery_timers` now use it for installed-key PING/ACK receive
  processing.
- 2026-05-29: Added lifecycle-owned routed protected short-packet processing.
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` now
  combines endpoint route selection, connection-handle validation, routed DCID
  length selection, caller-keyed 1-RTT packet processing, and recovery-timer
  refresh. Tests cover route mismatch rejection and ACK cleanup; `udp_protected_loopback`
  now uses it for routed 1-RTT PING/ACK processing.
- 2026-05-29: Added lifecycle-owned routed protected Initial processing.
  `EndpointConnectionLifecycle.processRoutedProtectedInitialDatagram()` now
  routes a protected Initial datagram to the expected connection handle, derives
  client/server Initial keys from the packet version and Original DCID,
  processes the packet in Initial space, and mirrors recovery timers. Tests and
  the UDP endpoint/protected loopbacks now use it for client-side protected
  server Initial response processing.
- 2026-05-29: Added lifecycle-owned accepted Initial response emission.
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialResponseDatagram()`
  now records authenticated client Initial bytes for the modeled server
  anti-amplification budget, queues caller-provided server Initial CRYPTO
  bytes, emits a protected server Initial response, and mirrors recovery
  timers through the endpoint lifecycle. Tests cover server/client CRYPTO
  delivery, client-side response routing, and anti-amplification accounting;
  `udp_protected_loopback` and `udp_endpoint_loopback` now send protected
  server Initial responses through this helper.
- 2026-05-29: Added lifecycle-owned accepted protected Initial processing.
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialDatagram()` now
  authenticates and processes the accepted client Initial before installing
  Original DCID/server Initial SCID endpoint routes, so malformed protected
  Initial packets do not leave active routes behind. Tests cover successful
  CRYPTO delivery plus route/token installation and tampered Initial rollback;
  `udp_protected_loopback` and `udp_endpoint_loopback` now use the helper for
  server-side accepted Initial processing over loopback UDP.
- 2026-05-29: Added lifecycle-owned protected Version Negotiation follow-up
  Initial emission. `EndpointConnectionLifecycle.processVersionNegotiationProtectedInitialDatagram()`
  now validates VN, retires the old attempt, registers the follow-up route,
  initializes the follow-up client connection, queues caller-provided Initial
  CRYPTO bytes, emits a protected Initial using the selected-version Initial
  keys, and mirrors the recovery timer. Tests cover v2 packetization and server
  CRYPTO receive; `udp_endpoint_loopback` now sends the protected follow-up
  Initial over loopback UDP.
- 2026-05-29: Added endpoint-owned Version Negotiation connection handoff.
  `EndpointConnectionLifecycle.processVersionNegotiationHandoffDatagram()` now
  wraps VN validation, follow-up config derivation, old-attempt route/timer
  retirement, follow-up Initial route registration, and follow-up `Connection`
  creation. Tests cover accepted and ignored handoff paths; `udp_endpoint_loopback`
  now consumes the returned follow-up connection directly.
- 2026-05-29: Added lifecycle-owned Version Negotiation follow-up route
  orchestration. `EndpointConnectionLifecycle.processVersionNegotiationFollowupDatagram()`
  now validates client-side VN, derives the follow-up config, retires the old
  attempt, and registers the follow-up client Initial Source CID route in one
  endpoint-owned step. Tests cover accepted, ignored, and reused-SCID paths;
  `udp_endpoint_loopback` now uses the helper for follow-up Initial routing.
- 2026-05-29: Added lifecycle-owned Version Negotiation follow-up handling.
  `EndpointConnectionLifecycle.processVersionNegotiationDatagram()` now wraps
  client-side VN validation, derives the follow-up client config, and retires
  the old connection handle's routes/timer only after a VN packet is accepted.
  Tests cover accepted and ignored VN paths; `udp_endpoint_loopback` now uses
  the helper to retire the old attempt and register the follow-up Initial route.
- 2026-05-29: Added client-side Version Negotiation follow-up config
  propagation. `Connection.versionNegotiationFollowupConfig()` now converts a
  validated RFC 8999 Version Negotiation selection into the next client
  connection config, preserving the advertised available-version list while
  setting the selected chosen version and RFC 9368 downgrade-check state. Tests
  cover follow-up config generation, authenticated Version Information success,
  downgrade rejection, and the no-selection error path; `codec_roundtrip` now
  uses the helper for its Version Negotiation evidence.
- 2026-05-29: Added configured QUIC v2 protected long-packet and Retry
  wire-version use. `Config.chosen_version = .v2` now makes protected
  Initial/Handshake/0-RTT long-packet builders emit v2 version/type bits and
  makes long-packet receive plus Retry processing reject cross-version packets.
  Tests cover v2 Initial packetization/receive, v1 rejection of v2 Initial, and
  v2 Retry issue/process with follow-up Initial token reuse; `initial_keys`
  prints configured v2 Initial packetization evidence.
- 2026-05-29: Added RFC 9002 max_datagram_size recovery resync from peer
  `max_udp_payload_size`. Applying peer transport parameters now updates all
  packet-number-space recovery states to the effective send datagram size; if
  the peer limit shrinks that size, congestion windows reset to the
  recalculated initial congestion window and congestion-avoidance credit is
  cleared. Tests cover direct recovery decrease/increase behavior and
  connection-level peer-parameter application; `transport_parameters` prints
  the resynced recovery datagram size and congestion window.
- 2026-05-29: Added RFC 9002 anti-amplification-limited server PTO
  disarm/rearm. `ptoDeadlineMillis()` now returns null while an unvalidated
  server has no remaining anti-amplification send credit, so direct PTO checks
  and the aggregate loss-detection timer do not queue probes. Recording
  additional peer bytes re-exposes the original PTO deadline and service path.
  Tests cover disarm, no-op service, rearm, and PING probe emission;
  `pto_recovery` now prints the rearmed deadline evidence.
- 2026-05-29: Added RFC 9002 client Initial ACK PTO-backoff reset
  suppression. Client-side ACK processing now preserves the connection-level
  PTO backoff snapshot when an Initial ACK newly acknowledges an ack-eliciting
  packet; Handshake and Application ACKs keep the normal reset behavior. Tests
  cover preserved client Initial backoff, subsequent Handshake ACK reset, and
  `pto_recovery` now prints the two-path evidence.
- 2026-05-29: Added RFC 9002 connection-level PTO backoff across packet
  number spaces. The PTO deadline helper now derives Initial, Handshake, and
  Application deadlines from one connection backoff count; servicing the
  earliest due PTO advances that count for every non-discarded space; ACK of an
  ack-eliciting packet and Initial/Handshake discard reset it. Invalid payload
  rollback restores the cross-space backoff snapshot. Tests cover Initial PTO
  service backing off Handshake, ACK reset, discard reset, invalid-payload
  rollback, and `pto_recovery` now prints the backed-off Handshake deadline
  evidence.
- 2026-05-29: Added RFC 9002 connection-level RTT estimate sharing across
  packet number spaces. A largest-acknowledged RTT sample now updates the RTT
  estimator for every non-discarded Initial, Handshake, and Application packet
  number space, while still keeping sent-packet, loss, PTO backoff, and
  congestion accounting scoped to the ACKed space. Invalid multi-frame payloads
  roll shared RTT changes back with the rest of recovery state;
  `pto_recovery` now prints the shared RTT and Handshake PTO deadline evidence.
- 2026-05-29: Added RFC 9002 cross-space bytes-in-flight congestion
  admission. `Connection.totalBytesInFlight()` now exposes the aggregate
  Initial/Handshake/Application in-flight byte count, and ack-eliciting sends
  use that aggregate before applying a packet number space's congestion window;
  PTO and congestion probes keep their one-shot bypass behavior. Tests cover an
  Application STREAM remaining queued while Initial and Handshake in-flight
  bytes fill the congestion window, then sending after an Initial ACK frees
  aggregate budget; `loss_recovery` now prints `cross-space congestion gate`.
- 2026-05-29: Added RFC 9002 largest-acknowledged RTT sampling. ACKs that
  only newly acknowledge lower ranges after the frame's largest acknowledged
  packet was already processed still clear sent-packet state, bytes in flight,
  and PTO backoff, but they no longer update RTT estimates. Tests cover the
  connection ACK path and the recovery accounting helper; `loss_recovery` now
  prints `old-largest ACK preserved RTT`.
- 2026-05-29: Added RFC 9000 ACK range structural validation on the
  connection-level ACK API path. Caller-constructed ACK/ACK_ECN frames now
  reject ranges that would compute negative packet numbers before recovery
  state is touched, matching the existing wire-codec validation. Tests cover
  no sent-packet, bytes-in-flight, largest-acknowledged, or timer mutation;
  `loss_recovery` prints the rejected invalid range.
- 2026-05-29: Added RFC 9002 Application Data PTO gating before handshake
  confirmation. Application-space PTO deadlines now stay null until
  `confirmHandshake()` or the modeled TLS/backend path marks the handshake
  confirmed, so aggregate endpoint timers and PTO service do not retransmit
  0-RTT/1-RTT data before peers are known to have usable keys. Tests cover
  direct timer/service no-op before confirmation, cross-space peer-probe
  suppression, and confirmed Application PTO behavior; `pto_recovery` now
  prints the gated deadline after confirmation.
- 2026-05-29: Extended RFC 9002/RFC 3465 NewReno congestion-avoidance
  credit handling for batched ACKs. `growCongestionAvoidance()` now consumes
  every full congestion-window worth of accumulated ACK credit, so a single
  ACK frame that newly acknowledges multiple windows can grow by multiple max
  datagrams while preserving leftover credit under the updated window. Tests
  cover direct recovery state and the connection ACK aggregation path;
  `loss_recovery` now prints `batched_avoidance_cwnd=14400`.
- 2026-05-29: Disarmed aggregate RFC 9002 recovery timers after entering
  closing or draining. `lossDetectionTimerDeadlineMillis()` now returns null
  once close state prevents further loss/PTO recovery work, so
  `EndpointConnectionLifecycle` timer refresh removes stale endpoint timers
  while the separate close/drain deadline remains owned by the connection.
  Tests cover direct closing/draining queries and endpoint timer disarm;
  `endpoint_recovery_timers` now prints `close_disarmed=true`.
- 2026-05-28: Added RFC 9002/RFC 3465 byte-counted NewReno
  congestion-avoidance credit. `Recovery` now accumulates acknowledged bytes in
  congestion avoidance and grows `congestion_window` in max-datagram
  increments after full-cwnd byte credits have been acknowledged, avoiding
  per-ACK integer round-up for tiny ACKs. Tests cover direct recovery state
  and the connection ACK path; `loss_recovery` now prints the unchanged
  credit-only cwnd before the full byte-counted cwnd increase.
- 2026-05-28: Added RFC 9002 NewReno underutilized-cwnd growth suppression.
  Connection ACK processing now checks whether bytes in flight reached the
  congestion window before the ACK was applied; underutilized ACKs still update
  RTT, PTO count, and bytes-in-flight accounting, but they do not grow
  `congestion_window`. Tests cover the direct recovery helper and connection
  ACK path, while `loss_recovery` now prints the unchanged underutilized cwnd
  before showing full-window slow-start and byte-counted congestion-avoidance growth.
- 2026-05-28: Added RFC 9002 NewReno new-congestion-event one-packet
  recovery probe allowance. When ACK-driven loss or ACK_ECN CE starts a new
  recovery period and the affected packet number space already has
  ack-eliciting data queued, the next send can bypass the reduced congestion
  window once while still respecting anti-amplification and buffer-size checks.
  Tests cover a full-cwnd STREAM retransmission after packet-threshold loss and
  a queued STREAM probe after a CE-driven congestion event; `loss_recovery` now
  prints the loss probe and CE probe bytes, cwnd, and inflight evidence.
- 2026-06-04: Added controlled-clock CE-driven NewReno congestion-probe
  evidence. A new ACK_ECN CE test fills the congestion window with ECT packets,
  queues STREAM data, proves the pre-CE send is blocked, then verifies the CE
  congestion event grants exactly one probe despite the reduced full cwnd.
  `loss_recovery` now prints `CE congestion probe`.
- 2026-06-04: Extended `udp_congestion_recovery_loopback` with a socket-backed
  CE-driven probe phase. The example routes modeled ECT protected PING packets
  over real loopback UDP, receives a protected ACK_ECN CE signal, and delivers
  the one-shot protected STREAM probe through `EndpointConnectionLifecycle`
  while printing CE count, reduced cwnd, inflight bytes, and route evidence.
- 2026-05-28: Extended Initial/Handshake packet-number-space discard cleanup to
  ECN state. `discardPacketNumberSpace()` now clears modeled ECT sent counters,
  cumulative ACK_ECN counters, ECN largest-acknowledged, and validation state
  for the discarded space. Tests cover a capable Handshake ECN state returning
  to `unknown` after discard; `packet_spaces` prints the discarded Handshake ECN
  state evidence.
- 2026-05-28: Suppressed ACK delay for Handshake RTT samples. RTT updates now
  treat both Initial and Handshake packet number spaces as immediately
  acknowledged spaces, while Application packets still use peer ACK delay
  scaling and post-confirmation `max_ack_delay` capping. Tests cover second RTT
  samples that would regress if Handshake ACK delay were subtracted;
  `pto_recovery` now prints the Handshake smoothed RTT evidence.
- 2026-05-27: Added one-shot PTO probe congestion-window bypass. PTO service now
  arms a per-space probe marker for existing pending data, retransmission data,
  or fallback PING, and the next ack-eliciting send in that packet number space
  can bypass congestion-window admission while still respecting endpoint
  send-budget checks. Commit paths consume the marker on send. Tests cover
  frame-payload and protected short-packet PTO probes with bytes in flight
  already at `congestion_window`; `pto_recovery` now prints `cwnd=100
  inflight=101` for the emitted probe.
- 2026-05-27: Added `EndpointConnectionLifecycle` to own endpoint routing and
  recovery-timer scheduling together. The helper keeps the existing
  caller-owned `Connection` model, but a socket event loop can now arm,
  service, route, and retire a connection handle through one endpoint state
  owner; retiring a handle removes both routes and any armed loss/PTO timer.
  Tests cover route lookup, active timer arming, route/timer retirement, and
  idempotent second retirement; `endpoint_recovery_timers` now prints both
  `timers_remaining=0` and `routes_remaining=0`. Remaining work is full
  TLS-owned socket-backed protected-packet lifecycle integration and remaining
  NewReno edge cases.
- 2026-05-28: Added endpoint lifecycle helpers for installed-key protected
  1-RTT short-packet send/receive timer refresh. Socket loops can now poll or
  process a connection-owned-key short packet through `EndpointConnectionLifecycle`
  and have the endpoint-owned recovery timer table refreshed in the same call.
  Tests cover route-selected protected PING delivery, ACK generation, ACK
  cleanup, and final timer disarm; `endpoint_recovery_timers` now prints
  `protected_timers=0`.
- 2026-05-28: Added endpoint lifecycle helpers for protected long-header
  datagram send/receive timer refresh. Socket loops can now poll or process
  Initial, Handshake, or 0-RTT long packets through `EndpointConnectionLifecycle`
  and keep the endpoint-owned recovery timer table synchronized. Tests cover
  route-selected protected Initial CRYPTO delivery, Initial ACK cleanup, and
  final timer disarm; `endpoint_recovery_timers` includes the protected long
  Initial/ACK exchange in its `protected_bytes` evidence.
- 2026-05-28: Added endpoint lifecycle helpers for connection-installed
  Handshake long-packet send/receive timer refresh. Socket loops can now use
  `EndpointConnectionLifecycle` after TLS/`CryptoBackend` installs Handshake
  traffic secrets, without passing packet-protection keys through the endpoint
  loop. Tests cover route-selected installed-key Handshake CRYPTO delivery,
  Handshake ACK cleanup, and final timer disarm; `endpoint_recovery_timers`
  includes the installed Handshake exchange in its `protected_bytes` evidence.
- 2026-05-28: Added endpoint lifecycle helpers for connection-installed 0-RTT
  long-packet send/receive timer refresh. Socket loops can now use
  `EndpointConnectionLifecycle` after TLS/`CryptoBackend` installs local or
  accepted peer early-data secrets, without passing 0-RTT packet-protection
  keys through the endpoint loop. Tests cover route-selected installed-key
  0-RTT STREAM delivery, delayed Application ACK cleanup by 1-RTT ACK, and
  final timer disarm; `endpoint_recovery_timers` includes the installed 0-RTT
  exchange in its `protected_bytes` evidence.
- 2026-05-28: Added endpoint lifecycle helpers for caller-keyed protected
  1-RTT short-packet send/receive timer refresh. Socket loops that still hold
  packet-protection keys outside the connection can now use the same
  `EndpointConnectionLifecycle` route/timer owner as installed-key paths.
  Tests cover route-selected caller-keyed PING delivery, ACK cleanup, and final
  timer disarm; `endpoint_recovery_timers` includes the caller-keyed short
  exchange in its `protected_bytes` evidence.
- 2026-05-28: Added endpoint lifecycle helpers for caller-owned key-phase-state
  1-RTT short-packet send/receive timer refresh. External key-update state can
  now pass through the endpoint route/timer owner while `Connection` keeps
  packet-number, ACK, and recovery ownership. Tests cover route-selected next
  key-phase PING delivery, authenticated peer key-phase advancement, ACK
  cleanup, and final timer disarm; `endpoint_recovery_timers` includes the
  caller-owned key-phase exchange in its `protected_bytes` evidence.
- 2026-05-28: Added endpoint lifecycle helpers for explicit key-phase and
  key-update protected 1-RTT short-packet timer refresh. Deterministic
  key-update tests can now pass the wire key-phase bit plus current/next
  receive keys through the endpoint route/timer owner. Tests cover
  route-selected next-key PING delivery, explicit current/next-key receive,
  ACK cleanup, and final timer disarm; `endpoint_recovery_timers` includes the
  explicit key-phase exchange in its `protected_bytes` evidence.
- 2026-05-28: Added endpoint lifecycle helpers for direct caller-keyed 0-RTT
  long-packet send/receive timer refresh. Endpoint loops that already hold
  early-data packet-protection keys can now bypass long-packet coalescing while
  still using one route/timer owner. Tests cover route-selected 0-RTT STREAM
  delivery, caller-keyed 1-RTT ACK cleanup, and final timer disarm;
  `endpoint_recovery_timers` includes the direct caller-keyed 0-RTT exchange
  in its `protected_bytes` evidence.
- 2026-05-28: Added endpoint lifecycle helpers for caller-keyed single-space
  Initial/Handshake protected long CRYPTO datagram timer refresh. Endpoint
  loops can now poll a specific CRYPTO packet-number-space datagram or process
  one matching protected long packet while keeping route and recovery timer
  ownership in `EndpointConnectionLifecycle`. Tests cover route-selected
  caller-keyed Handshake CRYPTO delivery, ACK cleanup through the single-space
  process helper, and final timer disarm; `endpoint_recovery_timers` includes
  the caller-keyed Handshake CRYPTO exchange in its `protected_bytes` evidence.
- 2026-05-28: Exposed endpoint receive classification through
  `EndpointConnectionLifecycle`. Socket loops can now use the same lifecycle
  owner for active route delivery, connection-handle route retirement, recovery
  timer disarm, and retained inactive-CID stateless reset emission. Tests cover
  active route classification, timer-disarming retirement, retained reset-token
  lookup, and reset datagram generation; `udp_close_lifecycle_loopback` now
  uses `EndpointConnectionLifecycle` for close-triggered route retirement and
  stateless reset emission.
- 2026-05-28: Added lifecycle-owned caller-validated route path updates.
  `EndpointConnectionLifecycle.updateRoutePath()` now commits a validated UDP
  tuple migration on the same state owner used for route lookup, receive
  classification, protected datagram helpers, and route/timer retirement. Tests
  cover pre-update `path_changed` routing, committed no-change routing on the
  new path, and stale current-path rejection; `udp_path_validation_loopback`
  now uses the lifecycle owner to commit the protected PATH_RESPONSE-validated
  route update.
- 2026-05-28: Added lifecycle-owned ECN path-state mirroring.
  `EndpointConnectionLifecycle` now owns `endpoint.EcnPathPolicy` and can
  refresh one UDP tuple's ECN state from a connection packet-number space after
  ACK_ECN validation. Tests cover capable and failed ECN outcomes remaining
  scoped to separate UDP paths; `udp_ecn_validation_loopback` now routes through
  the lifecycle owner and writes the active path's ECN state through that owner.
- 2026-05-28: Added lifecycle-owned spin-bit reset on route path update.
  `EndpointConnectionLifecycle.updateRoutePathAndResetSpinBit()` now commits a
  caller-validated UDP tuple migration and resets the connection's next
  outgoing spin bit only after the route update succeeds. Tests cover
  pre-update true spin state, `path_changed` routing on the migrated tuple,
  committed no-change routing after update, and reset next-spin state;
  `udp_spin_bit_loopback` now sends the second PING from a migrated client
  port and proves the lifecycle route update clears both server and client
  next-spin state.
- 2026-05-28: Added lifecycle-owned replacement-CID route registration.
  `EndpointConnectionLifecycle.registerReplacementConnectionId()` now commits
  NEW_CONNECTION_ID-style replacement routes, applies `retire_prior_to`, and
  exposes retained inactive-CID reset-token lookup through
  `statelessResetTokenForDatagram()`. Tests cover retired old-CID routing,
  retained reset-token lookup, active replacement routing, and active-route
  reset-token suppression; `udp_connection_ids_loopback` now performs its
  protected NEW_CONNECTION_ID/RETIRE_CONNECTION_ID route updates through the
  lifecycle owner. `issueConnectionIdRoute()` later connects local CID issuing
  to the same lifecycle-owned route update.
- 2026-05-28: Routed the flow-control UDP loopback through the endpoint
  lifecycle owner. `udp_flow_control_loopback` now registers client/server
  DCIDs and performs STREAM, STREAM_DATA_BLOCKED, MAX_DATA/MAX_STREAM_DATA, and
  final ACK route selection through `EndpointConnectionLifecycle`, keeping the
  socket-backed credit-refresh exercise on the same state owner as other
  lifecycle-routed UDP examples.
- 2026-05-28: Routed the installed-key key-update UDP loopback through the
  endpoint lifecycle owner. `udp_key_update_loopback` now registers
  client/server DCIDs and selects the next key-phase PING plus ACK routes
  through `EndpointConnectionLifecycle`, keeping authenticated peer key-phase
  advancement and ACK-gated second-update re-enable on lifecycle-owned endpoint
  routes.
- 2026-05-28: Routed the loss-recovery UDP loopback through the endpoint
  lifecycle owner. `udp_loss_recovery_loopback` now registers client/server
  DCIDs, routes packet-threshold ACK delivery through
  `EndpointConnectionLifecycle`, and services the time-threshold loss timer
  through the same lifecycle owner, keeping route selection and recovery timer
  cleanup on one socket-backed endpoint state owner.
- 2026-05-28: Routed the PTO recovery UDP loopback through the endpoint
  lifecycle owner. `udp_pto_recovery_loopback` now registers client/server
  DCIDs, routes fallback PING, queued STREAM, in-flight STREAM, in-flight
  CRYPTO, and final ACK delivery through `EndpointConnectionLifecycle`, and
  services PTO timers through the same lifecycle owner until
  `timers_remaining=0`.
- 2026-05-28: Routed the STREAM retransmission UDP loopback through the
  endpoint lifecycle owner. `udp_stream_retransmission_loopback` now registers
  client/server DCIDs and routes sparse ACK, retransmitted STREAM, duplicate
  receive, and final ACK cleanup through `EndpointConnectionLifecycle`, keeping
  ACK-driven STREAM retransmission on the same lifecycle route owner as
  loss/PTO recovery.
- 2026-05-28: Routed the congestion-recovery UDP loopback through the endpoint
  lifecycle owner. `udp_congestion_recovery_loopback` now registers
  client/server DCIDs and routes protected PING and ACK delivery through
  `EndpointConnectionLifecycle` in both recovery-period and persistent
  congestion phases, keeping NewReno congestion evidence on the same lifecycle
  route owner as loss/PTO/STREAM recovery.
- 2026-05-28: Routed the caller-keyed protected UDP loopback through the
  endpoint lifecycle owner. `udp_protected_loopback` now registers the client
  Initial SCID route, classifies the server-side accepted Initial, registers the
  accepted Original DCID/server Initial SCID routes, and routes protected server
  Initial, 1-RTT PING, and 1-RTT ACK delivery through
  `EndpointConnectionLifecycle`.
- 2026-05-28: Routed the Retry/address-validation UDP loopback through the
  endpoint lifecycle owner. `udp_retry_loopback` now uses
  `EndpointConnectionLifecycle` for client Initial SCID route registration,
  server Initial accept classification, Retry Source CID route switching,
  Retry delivery back to the client, follow-up Initial routing, and accepted
  server Initial response routing while preserving address-bound token
  validation and replay rejection.
- 2026-05-27: Corrected the NewReno minimum-window clamp edge. Congestion
  events now keep `ssthresh` at the halved congestion window while clamping only
  `congestion_window` up to `kMinimumWindow`. Tests cover direct recovery-state
  behavior and ACK-driven connection loss; `loss_recovery` now prints the
  resulting `cwnd=2400 ssthresh=1500` evidence.
- 2026-05-27: Added cross-space PTO probe queuing. When any packet-number
  space PTO expires, the controlled-clock PTO hook now queues probes in other
  packet number spaces that still have in-flight packets. Later connection-level
  PTO backoff updates make the earliest due PTO service advance the shared
  backoff while suppressing duplicate peer probes. Tests cover
  Initial-triggered Handshake peer-space probes, duplicate suppression, and the
  backed-off Handshake deadline; `pto_recovery` now prints the peer-space probe
  evidence.
- 2026-05-27: Corrected RFC 9002 persistent congestion duration so PTO
  exponential backoff does not widen the threshold. `Recovery` now separates the
  base PTO calculation used by persistent congestion from the backed-off PTO
  used for probe timers. Tests cover direct recovery-state PTO backoff,
  ACK-driven persistent congestion after PTO backoff, and `loss_recovery` prints
  the persistent-congestion duration evidence.
- 2026-05-27: Aligned inbound datagram handling for closing and draining
  states. Frame-payload and protected receive entry points now discard inbound
  datagrams while the close timer is still active, without parsing invalid
  bytes, generating ACKs, or advancing peer packet-number state; `.closed`
  still rejects after the close deadline. Tests cover queued local close,
  draining peer close, invalid-payload discard, protected short-packet receive
  after close, and `graceful_close` now prints the preserved packet-number
  evidence for discarded packets.
- 2026-06-01: Extended close-state discard coverage to protected long-header
  and 0-RTT receive entry points. The close-path tests now exercise the
  close-propagating long/0-RTT wrappers while both locally `closing` and peer
  `draining`, proving invalid protected bytes are not parsed, do not generate
  ACKs, and do not advance Initial or Application peer packet numbers;
  `graceful_close` prints the matching long/0-RTT discard evidence.
- 2026-05-27: Added ACK_ECN ECN-CE congestion response. Valid ACK_ECN
  CE counter increases now enter the same NewReno recovery period used for
  loss without treating the acknowledged packet as lost, and repeated CE
  increases for packets sent before the recovery start do not reduce the
  congestion window again. Tests cover recovery-state bytes-in-flight
  preservation, connection-level CE reduction/recovery-period suppression,
  invalid-payload rollback after CE reduction, and `udp_ecn_validation_loopback`
  now prints `ce_count=1` plus `ce_cwnd=6762`. Remaining work is full
  socket-owned protected-packet loss/PTO timer lifecycle integration and
  remaining NewReno edges.
- 2026-05-27: Wired socket-backed UDP loss/PTO recovery examples through
  endpoint-owned recovery timers. Protected-packet PTO and loss-time tests now
  prove endpoint arm/service/disarm around protected short packets; the UDP
  loss example now services time-threshold cleanup through
  `EndpointConnectionLifecycle` and prints `time_timers=0`, while the UDP PTO
  example now drives PING, queued STREAM, in-flight STREAM, and CRYPTO probes
  through `EndpointConnectionLifecycle` and prints `timers_remaining=0`.
  Remaining work is full socket-owned
  connection ownership and TLS-owned protected-packet timer integration.
- 2026-05-27: Added explicit NewReno congestion-window growth coverage.
  Recovery tests now assert slow start grows the congestion window by newly
  acknowledged bytes and congestion avoidance uses the
  `max_datagram_size * bytes_acked / congestion_window` increase floor. A
  connection-level ACK test proves `receiveAckInSpace()` drives the same
  growth path, and `loss_recovery` prints the slow-start and
  congestion-avoidance cwnd values. Remaining work is full socket-owned
  protected-packet loss/PTO timer lifecycle integration and remaining NewReno
  edge cases.
- 2026-05-27: Added endpoint-owned recovery timer scheduling for multiple
  connection handles. `EndpointLossDetectionTimers` mirrors each connection's
  aggregate `lossDetectionTimerDeadlineMillis()` result, chooses the earliest
  endpoint deadline, calls `serviceLossDetectionTimer()` for the selected
  connection, and then re-arms or disarms that handle from current connection
  state. Tests cover endpoint selection, before-deadline no-op behavior,
  PTO-driven re-arm, ACK-driven disarm, and loss-time service disarm.
  `endpoint_recovery_timers` demonstrates the same event-loop handoff across
  two caller-owned connections. Remaining work is full socket-owned
  protected-packet loss/PTO timer lifecycle integration and remaining NewReno
  edge cases.
- 2026-05-27: Added aggregate RFC 9002 loss detection timer service.
  `lossDetectionTimerDeadlineMillis()` reports the earliest timer cause across
  packet number spaces, gives pending loss-time deadlines precedence over PTO,
  and otherwise selects the earliest PTO deadline. `serviceLossDetectionTimer()`
  now lets an endpoint/event loop service that due aggregate timer directly by
  applying due loss-time handling or PTO probing. Tests cover loss-time
  precedence over PTO, no-op before deadline, due loss-time service without
  extra PTO probes, earliest-space PTO service, and protected short CRYPTO
  retransmission when the selected loss-time deadline expires. `loss_recovery`
  demonstrates aggregate loss-time service, and `pto_recovery` demonstrates
  aggregate PTO service. The socket-backed `udp_loss_recovery_loopback` and
  `udp_pto_recovery_loopback` examples now also service their due loss/PTO
  deadlines through the aggregate helper. Remaining work is socket-owned
  protected-packet loss/PTO timer lifecycle integration and remaining NewReno
  edge cases.
- 2026-05-27: Added protected 0-RTT RESET_STREAM/STOP_SENDING retransmission
  coverage. Successful protected 0-RTT control-frame sends retain allocation-free
  sidecars in the Application packet number space's sent-packet record;
  ACK-driven packet-threshold loss requeues RESET_STREAM or STOP_SENDING, and
  PTO expiry prefers reusing in-flight 0-RTT control frames before falling back
  to PING. Tests cover ACK-loss requeue, decryption under a new 0-RTT packet
  number, PTO-driven control-frame probing, invalid-payload rollback for
  STOP_SENDING requeue, and the `packet_spaces` example's RESET_STREAM and
  STOP_SENDING retransmission demonstration. Remaining work is socket-owned
  protected-packet loss/PTO timer lifecycle integration and remaining NewReno
  edge cases.
- 2026-05-27: Added protected 0-RTT STREAM retransmission coverage. Successful
  protected 0-RTT STREAM sends retain an owned STREAM sidecar in the
  Application packet number space's sent-packet record; ACK-driven
  packet-threshold loss requeues early data, and PTO expiry prefers cloning
  in-flight 0-RTT STREAM data before falling back to PING. Tests cover
  ACK-loss requeue, decryption under a new 0-RTT packet number, PTO-driven
  0-RTT STREAM probing, and sidecar cleanup boundaries; `packet_spaces` now
  demonstrates protected 0-RTT STREAM delivery and sparse-ACK-triggered
  protected 0-RTT STREAM retransmission. Later updates covered protected 0-RTT
  RESET_STREAM/STOP_SENDING retransmission; remaining work is socket-owned
  protected-packet loss/PTO timer lifecycle integration and remaining NewReno
  edge cases.
- 2026-05-26: Added ACK-driven frame-payload CRYPTO retransmission requeue.
  Sent CRYPTO packets now retain an owned CRYPTO frame copy; ACK-driven
  packet-threshold or time-threshold loss inserts that copy back at the front of
  the same packet number space's CRYPTO send queue, preserving queue rollback on
  invalid multi-frame payloads. Tests cover Handshake-space CRYPTO loss requeue,
  retransmission under a new packet number, and invalid-payload rollback;
  `run-crypto-stream` now prints the modeled lost Handshake CRYPTO
  retransmission. Later updates covered protected CRYPTO loss/PTO, protected
  0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission, and aggregate
  loss/PTO timer deadline selection. Remaining work is socket-owned
  protected-packet loss/PTO timer lifecycle integration and remaining NewReno
  edge cases.
- 2026-05-26: Extended the PTO probe hook to reuse in-flight Application
  STREAM data when no newer ack-eliciting data is queued. The hook still
  prefers queued data, falls back to PING only when no stream retransmission is
  available, and keeps PTO backoff/accounting unchanged. Tests cover
  frame-payload PTO STREAM retransmission, and `run-udp-pto-recovery-loopback`
  now proves protected UDP PTO fallback PING, queued STREAM probe, in-flight
  STREAM retransmission probe, duplicate receive discard, and final ACK cleanup.
  protected CRYPTO, protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING
  retransmission, and aggregate loss/PTO timer selection are now covered;
  socket-owned protected-packet loss/PTO timer lifecycle integration remains
  pending.
- 2026-05-26: Added ACK-driven STREAM retransmission requeue for lost
  Application packets. Sent STREAM packets now retain a copy of the transmitted
  frame data, ACK-driven packet-threshold or time-threshold loss requeues that
  data for a new packet number, ACK and invalid-payload rollback paths free or
  restore the owned frame copies, and `examples/udp_stream_retransmission_loopback.zig`
  plus `run-udp-stream-retransmission-loopback` now prove lifecycle-owned
  protected UDP delivery, sparse ACK loss classification, protected STREAM
  retransmission, duplicate receive discard, and final ACK cleanup. Protected
  CRYPTO and protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission
  are now covered; full protected-packet timer scheduling remains pending.
- 2026-05-26: Added `examples/udp_congestion_recovery_loopback.zig` and the
  `run-udp-congestion-recovery-loopback` build step. The example sends
  protected short PING packets over loopback UDP through the lifecycle route
  owner, returns protected ACK frames that trigger NewReno recovery-period
  behavior, prints evidence that repeated loss does not reduce the congestion
  window again inside recovery, and prints evidence that persistent congestion
  reduces the congestion window to the minimum window. ACK-driven and
  PTO-driven 1-RTT STREAM
  retransmission plus ACK-driven frame-payload CRYPTO retransmission and
  protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission are now
  covered separately.
- 2026-05-26: Added `examples/udp_loss_recovery_loopback.zig` and the
  `run-udp-loss-recovery-loopback` build step. The example sends protected
  short PING packets over loopback UDP, returns protected ACK frames that
  acknowledge only the largest packet, and now proves packet-threshold loss
  removal plus lifecycle timer-driven time-threshold cleanup through the real
  UDP route owner. ACK-driven and PTO-driven 1-RTT STREAM retransmission plus ACK-driven
  frame-payload CRYPTO retransmission are now covered separately;
  protected CRYPTO and protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING
  retransmission are now covered.
- 2026-05-26: Added `examples/udp_pto_recovery_loopback.zig` and the
  `run-udp-pto-recovery-loopback` build step. The example delivers an initial
  protected PING over loopback UDP, withholds the ACK, drives lifecycle PTO
  service to send and deliver a protected PING fallback probe, then ACKs both
  packets. It also queues new STREAM data after an unacked STREAM packet and
  proves lifecycle service sends that queued data as the protected probe before
  ACK cleanup. It also proves PTO reuses an in-flight STREAM copy when there is
  no newer queued data and routes in-flight CRYPTO PTO probes through the same
  lifecycle owner. Protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING
  retransmission is now covered separately.
- 2026-05-26: Added `examples/udp_ecn_validation_loopback.zig` and the
  `run-udp-ecn-validation-loopback` build step. The example sends a modeled
  ECT(0) protected short PING over loopback UDP, returns a protected ACK_ECN,
  validates the client's ECN state as `capable`, writes that state through
  `EndpointConnectionLifecycle` for the active UDP tuple, and proves a migrated
  tuple still starts from `unknown`. It deliberately does not claim real
  IP-header ECN marking.
- 2026-05-26: Added `examples/udp_spin_bit_loopback.zig` and the
  `run-udp-spin-bit-loopback` build step. The example enables the modeled
  single-path spin-bit policy on both endpoints, sends protected short PING/ACK
  exchanges over loopback UDP, verifies the first round stays `spin=false`,
  sends the second true-spin PING from a migrated client port, and proves
  lifecycle-owned route update/reset clears the next server ACK and client
  outgoing spin bits.
- 2026-05-26: Added `examples/udp_flow_control_loopback.zig` and the
  `run-udp-flow-control-loopback` build step. The example sends protected
  STREAM data to the receive limit over loopback UDP, reports
  STREAM_DATA_BLOCKED through the endpoint lifecycle owner, delivers receive-side
  MAX_DATA and MAX_STREAM_DATA credit refreshes back to the sender, resumes the
  STREAM with FIN, and proves final ACK cleanup.
- 2026-06-04: Extended `udp_flow_control_loopback` with caller-keyed resumed
  STREAM PTO evidence. After receive-side MAX_DATA/MAX_STREAM_DATA refresh lets
  the sender resume the STREAM with FIN, the example mirrors the client recovery
  timer into `EndpointConnectionLifecycle`, services the Application PTO through
  `serviceRecoveryTimerAndPollProtectedShortDatagram()`, routes the protected
  resumed STREAM PTO probe over loopback UDP, verifies duplicate FIN data is not
  delivered again while server ACK largest advances, and then uses the final ACK
  to clear client bytes in flight.
- 2026-05-26: Added `examples/udp_key_update_loopback.zig` and the
  `run-udp-key-update-loopback` build step. The example installs modeled
  1-RTT traffic secrets into client and server connections, initiates an
  installed-key update, sends the next key-phase PING over lifecycle-owned
  loopback UDP routing, verifies server peer key-phase advancement after
  authenticated receive, sends an ACK back over the same lifecycle owner, and
  proves the ACK gate re-enables the next local key update.
- 2026-06-04: Extended `udp_key_update_loopback` with installed-key key-phase
  PTO evidence. After the second local key update sends its next-phase PING, the
  example services the client's Application recovery timer through
  `serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys()`, routes
  the PTO probe over loopback UDP, verifies the probe keeps the current key
  phase and advances the server ACK largest, then proves a stale old-generation
  packet is still rejected without changing peer key-update state before the
  final ACK clears the second ACK gate.
- 2026-05-26: Added `examples/udp_connection_ids_loopback.zig` and the
  `run-udp-connection-ids-loopback` build step. The example delivers protected
  NEW_CONNECTION_ID frames over loopback UDP, updates endpoint routes for the
  replacement CID, proves the old CID only exposes an inactive reset token,
  probes active replacement CID routing, routes protected RETIRE_CONNECTION_ID
  through the active replacement CID, and verifies server-side local CID
  retirement plus ACK cleanup.
- 2026-05-26: Added `examples/udp_replacement_cid_loopback.zig` and the
  `run-udp-replacement-cid-loopback` build step. The example registers an
  initial route through `EndpointConnectionLifecycle`, installs replacement
  CIDs with `retire_prior_to` over loopback UDP through the lifecycle owner,
  proves retired sequence routes expose inactive reset tokens while active
  replacement CIDs suppress reset tokens, rejects invalid replacement sequence
  metadata, and rejects a stray path under active-migration-disabled policy.
- 2026-05-26: Added `examples/udp_preferred_address_loopback.zig` and the
  `run-udp-preferred-address-loopback` build step. The example registers a
  current server route through `EndpointConnectionLifecycle` on one loopback UDP
  address, learns the preferred-address CID/token through server
  transport-parameter bytes, commits that caller-validated preferred-address CID
  on a second server address through the lifecycle owner, proves the old route
  is retired, routes the preferred CID on the preferred path, rejects the same
  CID on a stray path under active-migration-disabled policy, and verifies the
  preferred-address reset token remains available after retirement.
- 2026-05-25: Added `examples/udp_zero_cid_loopback.zig` and the
  `run-udp-zero-cid-loopback` build step. The example registers two
  zero-length destination CID routes through `EndpointConnectionLifecycle` on
  separate UDP tuples, proves short and long datagrams are routed by tuple
  identity over loopback sockets, rejects an unregistered tuple before update,
  retires one zero-CID route by path through the lifecycle owner, then updates
  the remaining route to the previously unknown peer port and verifies routing
  there.
- 2026-05-25: Added `examples/udp_path_validation_loopback.zig` and the
  `run-udp-path-validation-loopback` build step. The example sends a protected
  PATH_CHALLENGE over loopback UDP to a new client port, proves a protected
  pre-validation PING on that new path does not update the endpoint route,
  routes the protected PATH_RESPONSE back through the server endpoint with
  `path_changed = true`, validates the response at the connection layer through
  the close-propagating route-update helper, then commits the endpoint route
  update and proves subsequent routing no longer reports a path change.
- 2026-05-25: Added `examples/udp_retry_loopback.zig` and the
  `run-udp-retry-loopback` build step. The example sends an Initial-like
  datagram over loopback UDP, issues a server Retry with an address-bound
  endpoint token, routes the Retry back to the client through the lifecycle
  owner, switches the server pending route to the Retry Source CID, validates
  the follow-up Initial token with replay rejection, consumes the one-time Retry
  token, exchanges protected Initial CRYPTO on the Retry-derived keys, and
  validates the Retry-related transport parameters.
- 2026-05-25: Extended `examples/udp_endpoint_loopback.zig` so the real
  loopback UDP Version Negotiation response is passed into
  `Connection.processVersionNegotiationDatagram()`. The example now proves
  lifecycle-owned endpoint VN response delivery and client-side mutual-version
  selection in the same socket-backed flow.
- 2026-05-25: Added `examples/udp_close_lifecycle_loopback.zig` and the
  `run-udp-close-lifecycle-loopback` build step. The example delivers a
  protected CONNECTION_CLOSE over loopback UDP with client and server route
  state held by `EndpointConnectionLifecycle`, routes it through the active
  endpoint CID, demonstrates lifecycle-routed protected receive auto-close for
  an authenticated malformed short packet, applies close/drain timeout-driven
  lifecycle route cleanup, retires the connection handle's routes after the
  server enters draining, then answers a later packet for the inactive CID with
  a stateless reset using the retained token.
- 2026-05-23: Added an explicit RFC coverage status table for the current
  transport-core plan. The table marks RFC 8999, RFC 9000, RFC 9001, and
  RFC 9002 as `Partial` with concrete repository evidence and remaining proof,
  while RFC 9221, RFC 9368, HTTP/3, QPACK, and multipath work remain
  `Deferred` outside the first core scope.
- 2026-05-23: Added RFC 9369 QUIC v2 Initial secret/key/IV/header-protection
  key derivation with the v2 Initial salt and `quicv2` packet-protection labels.
  Tests cover Appendix A.1 vectors, and `examples/initial_keys.zig` prints both
  v1 and v2 Initial key material from the same client Initial DCID.
- 2026-05-23: Added RFC 9369 QUIC v2 long-header packet type bit mapping for
  Initial, 0-RTT, Handshake, and Retry. The packet codec now serializes and
  parses v2 Initial/Handshake and Retry wire type bits, protected long-prefix
  peeking uses the same version-aware mapping, and `examples/codec_roundtrip.zig`
  prints the v2 type bytes.
- 2026-05-23: Added RFC 9369 QUIC v2 Retry Integrity Tag support. The existing
  Retry integrity helpers now infer the Retry version from transmitted bytes
  and choose the RFC 9001 or RFC 9369 fixed key/nonce. Tests cover Appendix A.4
  vectors for both versions, and `examples/retry_token.zig` verifies a v2 Retry
  packet at the protection layer while the connection-level Retry flow remains
  QUIC v1.
- 2026-05-23: Added originating-version binding to address-validation tokens
  for RFC 9369 token separation. Tokens now serialize and authenticate the
  version that caused issuance; `validateForVersion()` and the endpoint and
  connection `*ForVersion()` wrappers reject cross-version reuse before replay
  state changes. Tests cover v1 defaults, v2 success, v1/v2 mismatch rejection,
  rotated-secret validation, endpoint replay boundaries, and connection-level
  NEW_TOKEN address validation. `examples/address_validation.zig` now
  demonstrates a v2-bound NEW_TOKEN that is rejected by v1 validation and
  accepted by v2 validation.
- 2026-05-23: Added RFC 9368 `version_information` transport parameter support.
  The typed transport-parameter codec now serializes/parses chosen and
  available QUIC versions, rejects malformed lengths and zero versions, and the
  connection layer exports local version information while validating client-
  and server-sent peer information according to the endpoint role. RFC 9368
  `VERSION_NEGOTIATION_ERROR` is now exposed in `transport_error.zig`.
  `examples/codec_roundtrip.zig` prints the version-information count. Full
  incompatible/compatible negotiation state and endpoint ownership remain
  pending.
- 2026-05-23: Added endpoint-level RFC 8999 Version Negotiation response
  generation for unsupported long-header versions. The helper peeks the
  version-independent long-header connection IDs, ignores short headers,
  supported versions, and Version Negotiation packets, and writes a response
  that echoes the received Source CID as Destination CID and the received
  Destination CID as Source CID. `EndpointRouter.handleDatagramWithVersionNegotiation()`
  can now classify one datagram as route, version negotiation, stateless reset,
  or drop. Full socket-owned accept loops and incompatible VN retry state remain
  pending.
- 2026-05-23: Added client-side Version Negotiation packet handling state.
  `Connection.processVersionNegotiationDatagram()` validates the RFC 8999
  connection-ID echo, ignores packets that contain the client's Original Version
  or mismatched CIDs, selects a mutual version from local `available_versions`,
  records that this connection attempt already reacted to VN, and exposes the
  result through `versionNegotiationSelectedVersion()`. Later helpers now
  derive the follow-up config, replace endpoint routes, and hand off the
  follow-up client connection; full socket-owned retry-loop integration remains
  pending.
- 2026-05-23: Added RFC 9368 server Version Information downgrade checks after
  a client reacts to Version Negotiation. Follow-up client connections can carry
  `Config.version_negotiation_selected_version`; peer transport-parameter
  validation then requires the server Chosen Version to match that selection,
  rejects empty server Available Versions, checks that the client would still
  select the same version from server Available Versions plus the negotiated
  version, and preserves the QUIC v1 missing-`version_information` exception.
  Later endpoint lifecycle helpers now hand off the follow-up connection object;
  full socket-owned incompatible-version retry-loop integration remains pending.
- 2026-05-22: Added an RFC 8999 Version Negotiation packet codec. It supports
  0..255-byte connection IDs, ignores the unused low 7 bits of the first byte
  on parse, rejects empty or truncated supported-version lists, and preserves
  allocation failures in tests.
- 2026-05-22: Added RFC 9000 packet number reconstruction with the Appendix A.3
  sample vector, closest-window behavior, QUIC's 2^62-1 packet-number limit,
  and invalid length/value tests.
- 2026-05-22: Added RFC 9000 packet number encoding selection through
  `packet.encodePacketNumberForHeader()`. It chooses the 1..4 byte truncated
  wire length from the outgoing packet number and largest acknowledged packet,
  covers the Appendix A.2 sample, no-ACK boundaries, invalid ranges, and
  `examples/codec_roundtrip.zig` output.
- 2026-05-22: Added header-level packet number truncation/reconstruction APIs:
  `encodeLongHeaderWithPacketNumberEncoding()`,
  `encodeShortHeaderWithPacketNumberEncoding()`,
  `parseLongHeaderWithExpectedPacketNumber()`,
  `parseShortHeaderWithExpectedPacketNumber()`, and
  `parseLongPacketWithExpectedPacketNumber()`. Tests cover long and short
  headers, long-packet envelope parsing, invalid encodings, and RFC 9000
  Appendix A-style reconstruction vectors.
- 2026-05-23: Tightened RFC 9000 frame-type decoding. `decodeFrame()` now reads
  the Frame Type field as a QUIC varint, rejects non-shortest frame-type
  encodings, and returns `UnsupportedFrameType` for unknown one-byte and
  multi-byte frame type values. Tests cover non-shortest PING and unknown type
  inputs.
- 2026-05-22: Added an RFC 9000 long-packet envelope codec. `LongPacket`,
  `encodeLongPacket()`, and `parseLongPacket()` serialize Initial/Handshake/0-RTT
  style long packets with opaque payload bytes, derive and validate the QUIC
  Length field, return the consumed datagram length for coalesced packets, and
  cover truncation plus allocation-failure tests. Packet protection remains
  pending.
- 2026-05-22: Added an RFC 9000 short-packet envelope codec. `ShortPacket`,
  `encodeShortPacket()`, and `parseShortPacket()` serialize 1-RTT-style short
  packets with opaque payload bytes. Because short headers do not carry a
  payload length, the parser consumes the remaining datagram bytes after DCID
  and packet number. Tests cover roundtrip, explicit packet-number
  reconstruction, and payload allocation failures. Packet protection remains
  pending.
- 2026-05-22: Added RFC 9000 short-header spin-bit preservation. `ShortHeader`
  now carries the byte-0 spin bit, and the short-header plus short-packet tests
  cover encoding, parsing, and explicit packet-number reconstruction with the
  spin bit set.
- 2026-05-23: Added configurable single-path runtime spin-bit policy for
  protected 1-RTT short packets. `Config.enable_spin_bit` defaults to the prior
  deterministic false wire behavior; when enabled, servers reflect the latest
  successfully accepted peer spin bit, clients invert the latest server spin
  bit, `nextOutgoingSpinBit()` exposes the next short-header value, and
  `resetSpinBitForPath()` resets state after a future path or CID change.
  `protection.peekShortPacketSpinBit()` reads the unprotected spin bit without
  authenticating payloads. Tests cover enabled/disabled behavior and invalid
  packet preservation, and `examples/crypto_stream.zig` prints the modeled
  spin-bit turn.
- 2026-05-22: Added a typed RFC 9000 transport parameter codec exposed as
  `quicz.transport_parameters`. It covers defaults, duplicate detection,
  unknown-parameter ignore behavior, value validation, `preferred_address`,
  and allocation-failure tests. TLS handshake wiring is still pending.
- 2026-05-22: Added an RFC 9000 Retry packet codec. It parses and serializes
  Retry packets as complete datagrams, ignores unused bits, rejects zero-length
  tokens and malformed headers, and carries the 16-byte integrity tag for the
  packet-protection layer.
- 2026-05-22: Added typed RFC 9000 transport error code helpers exposed as
  `quicz.transport_error`. They cover the fixed transport error values,
  CRYPTO_ERROR range detection, and TLS alert mapping. Connection-close policy
  and error propagation remain part of the later state-machine work.
- 2026-05-29: Extended `quicz.transport_error` with
  `frameDecodeErrorCode()`, which classifies inbound frame codec failures
  such as unknown frame types, invalid frame values, invalid ACK ranges, and
  truncated frame bodies as `FRAME_ENCODING_ERROR` while leaving local resource
  errors unmapped. Tests cover every mapped frame decode error and
  `examples/codec_roundtrip.zig` prints the mapped close code name.
- 2026-05-29: Extended `quicz.transport_error` with
  `transportParameterErrorCode()`, which classifies transport-parameter parse
  and value-validation failures such as invalid lengths, invalid values,
  duplicate parameters, invalid varints, and truncated extensions as
  `TRANSPORT_PARAMETER_ERROR` while leaving local encode-buffer and allocation
  failures unmapped. Tests cover every mapped codec error and
  `examples/codec_roundtrip.zig` prints the mapped close code name.
- 2026-05-29: Added `framePacketTypeErrorCode()` for RFC 9000 packet-type frame
  validation. It returns `PROTOCOL_VIOLATION` when a syntactically valid frame
  appears in a forbidden Initial, Handshake, or 0-RTT packet context, while
  returning null for permitted packet/frame combinations. Tests cover allowed
  Initial/1-RTT frames and forbidden Initial, Handshake, and 0-RTT frames;
  `examples/codec_roundtrip.zig` prints the mapped packet-type close code.
- 2026-05-29: Added `processDatagramForPacketTypeOrClose()` as an explicit
  close-propagating receive wrapper. It keeps the existing rollback-only
  `processDatagramForPacketType()` behavior unchanged, but can queue transport
  CONNECTION_CLOSE with `FRAME_ENCODING_ERROR` for malformed or unknown frame
  payloads, or `PROTOCOL_VIOLATION` for syntactically valid frames in forbidden
  packet types. Tests cover both close paths and `examples/graceful_close.zig`
  prints the invalid 0-RTT ACK close.
- 2026-05-29: Added default and packet-number-space close-propagating receive
  wrappers: `processDatagramOrClose()` and `processDatagramInSpaceOrClose()`.
  They delegate to the same packet-type close classifier, leaving
  `processDatagram()` and `processDatagramInSpace()` rollback-only. Tests cover
  Application-space frame encoding close and Initial-space forbidden-frame
  protocol violation; `examples/graceful_close.zig` prints both paths.
- 2026-05-30: Added protected receive close-propagation wrappers for
  authenticated long-header and short-header packets. `processProtectedLongDatagramOrClose()`,
  `processProtectedLongDatagramInSpaceOrClose()`,
  `processProtectedZeroRttDatagramOrClose()`, `processProtectedShortDatagramOrClose()`,
  and the installed-key/key-update variants preserve the old success path while
  queueing CONNECTION_CLOSE for classified protected plaintext frame errors.
  Tests cover protected Initial packet-type violation and protected short
  frame-encoding close, and `examples/graceful_close.zig` prints both paths.
- 2026-05-30: Added `EndpointConnectionLifecycle` direct and routed protected
  receive `*OrClose` wrappers for Initial, long-header, 0-RTT, short-header,
  explicit key-phase, and installed-key paths. The old lifecycle receive APIs
  remain rollback-only; socket/lifecycle loops can opt into close propagation
  after route selection succeeds. Tests cover routed protected short
  frame-encoding close and routed protected Initial packet-type close, and
  `examples/graceful_close.zig` prints the lifecycle-routed protected
  auto-close path.
- 2026-05-22: Added `examples/codec_roundtrip.zig` and `zig build run-codec`.
  The example exercises varint, short-packet envelope, coalesced long-packet envelope,
  short-header spin-bit preservation, header packet number
  truncation/reconstruction, packet number encoding, Version Negotiation,
  STREAM frame, transport parameter, connection transport-parameter exposure
  including TLS extension bytes and local ACK delay policy, and transport error
  helper roundtrips including transport-parameter, frame codec, and packet-type
  error classification.
- 2026-05-22: Added `Connection.localTransportParameters()` and
  `applyPeerTransportParameters()`. Local parameters expose configured receive
  limits, local `ack_delay_exponent`/`max_ack_delay`,
  `disable_active_migration`, configured server-only `stateless_reset_token`,
  and configured server-only `preferred_address`,
  while peer parameters update send-side
  connection and stream credit, stream-count limits, ACK delay policy, outbound
  datagram sizing, peer active-migration policy observability, the peer
  `stateless_reset_token`, and peer `preferred_address` fixed-storage
  observability for future endpoint reset/migration policy. Tests cover local
  export, peer application, invalid server-only peer values, preferred-address
  CID validation, active connection ID limit validation, and keeping locally
  exported ACK delay policy separate after peer parameters update recovery.
  `encodeLocalTransportParameters()` serializes the same local parameter view
  as TLS QUIC extension bytes, and `applyPeerTransportParameterBytes()` parses
  peer extension bytes before applying the existing semantic validation. Tests
  cover byte roundtrip, buffer exhaustion, malformed extension rejection,
  invalid server-only extension rejection, and preserving connection state on
  failure; the implementation also avoids exporting server `preferred_address`
  CID slices that borrow from a temporary optional copy. Full TLS backend
  transcript integration, stateless reset endpoint handling beyond read-only
  token exposure, automatic preferred-address socket migration, and UDP
  migration enforcement remain pending; later endpoint bullets cover
  caller-validated preferred-address route commit.
- 2026-05-29: Added `applyPeerTransportParameterBytesOrClose()` as an explicit
  close-propagating wrapper for peer transport-parameter extension bytes. It
  keeps `applyPeerTransportParameterBytes()` rollback-only behavior unchanged,
  but queues transport CONNECTION_CLOSE with `TRANSPORT_PARAMETER_ERROR` and
  CRYPTO frame_type for malformed extensions or invalid peer-parameter
  semantics. Tests cover both parse and semantic-validation close paths, and
  `examples/transport_parameters.zig` prints the auto-close code and frame type.
- 2026-05-28: Added `examples/transport_parameters.zig` and
  `zig build run-transport-parameters`. The example exercises local TLS
  extension byte export, peer extension parse/apply, client omission of
  server-only `stateless_reset_token` and `preferred_address`, client storage of
  server preferred-address/reset-token policy, effective idle-timeout selection,
  peer stream-data limit enforcement, and server rejection of client-sent
  server-only parameters.
- 2026-05-22: Added `Connection.sendPathChallenge()` with outbound
  PATH_CHALLENGE queuing, matching PATH_RESPONSE validation, duplicate or
  mismatched response rejection, and rollback tests for invalid multi-frame
  payloads. Timeout/retry policy is still pending.
- 2026-05-22: Added peer-issued connection ID lifecycle tracking in
  `Connection`. NEW_CONNECTION_ID now stores active peer CIDs, rejects
  inconsistent duplicate sequence numbers, rejects stateless reset token reuse
  across CIDs, enforces the configured active CID limit, applies retire_prior_to
  by queuing RETIRE_CONNECTION_ID, and rolls back partial CID state on invalid
  multi-frame payloads. Local CID issuing and endpoint route registration now
  have a lifecycle-owned bridge; full TLS-owned socket routing remains pending.
- 2026-05-22: Added local connection ID issuing in `Connection`.
  `issueConnectionId()` copies local CID bytes, assigns NEW_CONNECTION_ID
  sequence numbers, enforces peer active CID limits after applying
  `retire_prior_to`, rejects duplicate local CID values and stateless reset
  token reuse, and queues unsent IDs for `pollTx()`. Inbound RETIRE_CONNECTION_ID now
  marks previously sent local CIDs retired and rolls back retirement on invalid
  multi-frame payloads. The endpoint route-table skeleton can store optional
  NEW_CONNECTION_ID sequence numbers and retire routes by sequence or
  retire_prior_to threshold for future RETIRE_CONNECTION_ID wiring; the
  socket-backed replacement-CID route-retirement and caller-owned NEW/RETIRE
  proofs now live in `examples/udp_replacement_cid_loopback.zig` and
  `examples/udp_connection_ids_loopback.zig`, and
  `EndpointConnectionLifecycle.issueConnectionIdRoute()` now bridges local
  issuance with endpoint route registration. Automatic socket-owned replacement
  policy remains pending.
- 2026-05-22: Added `examples/flow_control.zig` and
  `zig build run-flow-control`. The example demonstrates connection data credit,
  stream data credit, and bidirectional stream-count blocking/unblocking using
  MAX_DATA, MAX_STREAM_DATA, and MAX_STREAMS_BIDI.
- 2026-05-22: Added outbound BLOCKED reporting for local credit exhaustion.
  `sendOnStream()` now queues DATA_BLOCKED or STREAM_DATA_BLOCKED before
  returning `FlowControlBlocked`, and stream-count exhaustion queues
  STREAMS_BLOCKED_BIDI/UNI. `pollTx()` skips obsolete BLOCKED frames after MAX
  updates. Tests and `examples/flow_control.zig` cover the emitted frames.
- 2026-05-22: Added peer BLOCKED observability. Inbound DATA_BLOCKED,
  STREAM_DATA_BLOCKED, and STREAMS_BLOCKED_* update highest-observed blocked
  limits exposed by public getters, and invalid multi-frame payloads roll those
  reports back.
- 2026-05-22: Added peer BLOCKED-triggered MAX retransmission for stale receive
  limits. If inbound DATA_BLOCKED, STREAM_DATA_BLOCKED, or STREAMS_BLOCKED_*
  reports a limit below the current receive-side credit, the connection requeues
  the matching MAX_DATA, MAX_STREAM_DATA, or MAX_STREAMS_* frame. Tests and
  `examples/flow_control.zig` cover DATA, per-stream data, stream-count, and
  invalid-payload rollback.
- 2026-05-30: Rejected inbound MAX_STREAMS_BIDI/UNI values above 2^60. The
  compatibility receive API rolls back without updating peer stream limits, and
  `processDatagramOrClose()` maps the same invalid frame to
  FRAME_ENCODING_ERROR as required by RFC 9000. Tests cover both bidi and uni
  receive rollback plus close propagation.
- 2026-05-22: Added receive-side MAX_DATA and MAX_STREAM_DATA refresh after
  `recvOnStream()` consumes bytes. The connection now increases advertised
  connection and per-stream receive credit by the consumed byte count, drops
  obsolete lower queued MAX limits, and `examples/flow_control.zig` demonstrates
  a sender unblocked by refreshed receive credit.
- 2026-05-23: Added optional target receive-window refresh through
  `Config.receive_connection_window` and `Config.receive_stream_window`. When
  configured, `recvOnStream()` advertises MAX_DATA/MAX_STREAM_DATA at least the
  target window beyond the highest bytes already received, while the default
  behavior still replenishes exactly the consumed credit. Tests cover the
  advertised target limits, and `examples/flow_control.zig` now demonstrates
  MAX_DATA=15 and MAX_STREAM_DATA=17 from a 5-byte initial window.
- 2026-05-23: Reused the configured receive-window targets for peer BLOCKED
  growth. When DATA_BLOCKED or STREAM_DATA_BLOCKED reports the current or a
  newer receive limit, the connection grows the matching MAX_DATA or
  MAX_STREAM_DATA to `reported + window` and queues it for retransmission;
  stale reports still re-advertise the current limit, and null receive-window
  configs keep the old no-growth behavior. Tests and `examples/flow_control.zig`
  cover connection data, stream data, duplicate stale reports, and invalid
  payload rollback.
- 2026-05-23: Added optional stream-count growth for peer STREAMS_BLOCKED through
  `Config.receive_stream_count_window`. When STREAMS_BLOCKED_BIDI/UNI reports
  the current or a newer receive stream-count limit, the connection grows the
  matching MAX_STREAMS by the configured count window and queues it for
  retransmission. Null preserves the old no-growth behavior, stale reports still
  re-advertise the current limit, and oversized configured windows are rejected
  at init. Tests and `examples/flow_control.zig` cover BIDI/UNI growth,
  duplicate stale reports, and invalid-payload rollback.
- 2026-05-23: Tightened STREAM_DATA_BLOCKED receive-side stream-state handling.
  The frame now validates the stream direction and receive stream-count limit,
  rejects send-only and unopened local bidirectional stream IDs, and creates
  receive state before any STREAM data when the blocked stream is valid. Tests
  cover pre-STREAM receive-state creation, stale MAX_STREAM_DATA retransmission,
  invalid direction/count rejection, and rollback; `examples/flow_control.zig`
  demonstrates the peer-BLOCKED path without a synthetic empty STREAM first.
- 2026-05-23: Suppressed per-stream MAX refresh after final size is known.
  STREAM_DATA_BLOCKED is now discarded for streams in Size Known or Data Recvd,
  so the connection does not requeue or grow MAX_STREAM_DATA after the receive
  side knows the terminal offset. Tests cover suppression with a configured
  receive window, and `examples/flow_control.zig` demonstrates the no-MAX path.
- 2026-05-23: Dropped pending MAX_STREAM_DATA when a stream leaves Recv before
  the queued frame is transmitted. Packetization now filters per-stream MAX
  frames after STREAM FIN or RESET_STREAM establishes the final size, while
  retaining connection-level MAX_DATA. Tests cover final-size and reset races,
  and `examples/flow_control.zig` demonstrates final-size suppression.
- 2026-05-23: Dropped pending STREAM_DATA_BLOCKED when the matching send side
  finishes or resets before the queued frame is transmitted. Packetization now
  filters per-stream BLOCKED frames after FIN or `RESET_STREAM`, while retaining
  connection-level and stream-count BLOCKED behavior. Tests cover FIN and reset
  races, and `examples/flow_control.zig` demonstrates reset suppression.
- 2026-05-23: Allowed inbound `MAX_STREAM_DATA` and `STOP_SENDING` to open a
  peer-initiated bidirectional stream before any STREAM data. `MAX_STREAM_DATA`
  creates receive/send state so replies can use the advertised credit;
  `STOP_SENDING` creates receive state, resets only the local send side, and
  still accepts later peer STREAM data. Tests cover pre-STREAM creation and
  invalid-payload rollback; `examples/flow_control.zig` and
  `examples/stop_sending.zig` demonstrate the boundaries.
- 2026-05-23: Added implicit lower-numbered receive stream creation. Inbound
  STREAM, RESET_STREAM, STREAM_DATA_BLOCKED, MAX_STREAM_DATA, or STOP_SENDING
  that opens a higher-numbered stream now creates missing lower-numbered streams
  of the same type. Tests cover bidirectional/unidirectional STREAM data,
  pre-STREAM MAX_STREAM_DATA, pre-STREAM STOP_SENDING, idle reads on the lower
  streams, and invalid-payload rollback; `examples/flow_control.zig` and
  `examples/stop_sending.zig` print the implicit-open boundaries.
- 2026-05-23: Ignored inbound MAX_STREAM_DATA after the matching send side has
  sent FIN. The send credit no longer changes in Data Sent/closed send states,
  while unfinished send sides still apply larger limits. Tests cover the FIN
  boundary and post-FIN `StreamClosed` send behavior.
- 2026-06-01: Ignored inbound MAX_STREAM_DATA after the local send side has
  reset. `Connection` now uses one send-side closed predicate for FIN and
  RESET_STREAM, so later credit updates cannot reopen a reset sender and pending
  STREAM_DATA_BLOCKED frames use the same closure boundary. Tests cover the
  reset boundary, and `examples/stream_reset.zig` demonstrates the ignored
  credit update.
- 2026-05-22: Added receive-side MAX_STREAMS_BIDI/UNI refresh for fully
  consumed peer-initiated FIN streams, including zero-length FIN streams observed
  through `recvOnStream()`. The connection releases one receive stream-count
  credit once per completed stream, queues the matching MAX_STREAMS frame, and
  `examples/flow_control.zig` demonstrates a blocked sender opening the next
  bidirectional stream after the refresh.
- 2026-05-23: Released receive stream-count credit for peer-initiated reset
  streams once the application observes the reset through `recvOnStream()`.
  Tests cover bidirectional and unidirectional RESET_STREAM completion paths,
  and `examples/stream_reset.zig` demonstrates a reset-unblocked next stream.
- 2026-05-22: Added `examples/uni_stream.zig` and
  `zig build run-uni-stream`. The example demonstrates client- and
  server-initiated unidirectional stream delivery in the current frame-payload
  skeleton and verifies that a receive-only peer unidirectional stream rejects
  reverse sends.
- 2026-05-22: Added receive-side out-of-order STREAM range buffering in
  `Connection`. Non-overlapping ranges are accounted for when received and
  exposed to `recvOnStream()` only after gaps are filled. Tests cover FIN before
  the missing prefix, overlap rejection, invalid-payload rollback, and
  RESET_STREAM final-size accounting with pending ranges.
- 2026-05-23: Added idempotent receive handling for duplicate STREAM
  retransmissions. Identical bytes already present in the contiguous receive
  buffer are ignored, matching contiguous prefixes are trimmed before appending
  new suffix bytes, and exact duplicate pending ranges are ignored without
  growing receive flow-control accounting. Conflicting or ambiguous overlaps
  still fail as invalid payloads. Tests cover contiguous duplicates, suffix
  trimming, pending duplicate ranges, conflicting overlap rejection, and
  rollback; `examples/uni_stream.zig` demonstrates duplicate retransmission
  discard on a client-initiated unidirectional stream.
- 2026-05-23: Added Data Recvd late-STREAM discard. Once all bytes through the
  final size are buffered, later STREAM frames inside that final size are
  ignored instead of rechecking buffered bytes or growing flow-control
  accounting. Tests cover conflicting late data after FIN while preserving
  final-size violation errors.
- 2026-05-22: Added `recvStreamFinalSize()` and `recvStreamFinished()` so
  callers can observe STREAM FIN final size and successful receive-side
  completion after all bytes are consumed. RESET_STREAM final size remains
  visible but does not count as FIN completion. Tests cover out-of-order FIN
  completion, reset behavior, and invalid receive-only stream directions.
- 2026-05-22: Added `Connection.resetStream()` and
  `examples/stream_reset.zig` with `zig build run-stream-reset`. The API aborts
  opened local send sides and observed peer bidirectional reply sides, queues a
  single RESET_STREAM with the current send offset as final size, rejects
  receive-only directions and unopened streams, and drops unsent STREAM data
  after the reset is emitted.
- 2026-05-23: Made receive-side RESET_STREAM cancellation ignore later STREAM
  data that remains within the established final size, while still rejecting
  STREAM data beyond that final size or FINs that would change it. Tests cover
  ignored late STREAM data, final-size violation rollback, and
  `examples/stream_reset.zig` demonstrates the post-reset ignore path.
- 2026-05-23: Applied same-final-size RESET_STREAM to Size Known receive
  streams that still have gaps. A later reset now accounts the missing final
  size toward connection flow control and closes the receive side, while
  Data Recvd streams still keep readable FIN data. Tests cover the FIN-gap
  abort path, and `examples/stream_reset.zig` demonstrates the boundary.
- 2026-05-22: Added `Connection.stopSending()` and
  `examples/stop_sending.zig` with `zig build run-stop-sending`. The API queues
  STOP_SENDING for opened local bidirectional receive sides and observed
  peer-initiated receive streams, rejects send-only and unobserved streams,
  deduplicates local stop requests, and exercises the peer RESET_STREAM response.
- 2026-05-28: Suppressed ACK-loss STREAM retransmission after the matching send
  side has been reset. `removeAckDrivenLosses()` now skips requeueing lost
  STREAM data once `STOP_SENDING` or local reset has marked the send stream
  `reset_sent`, while preserving RESET_STREAM delivery and ordinary lost STREAM
  retransmission. Tests cover the reset boundary, and
  `examples/stop_sending.zig` demonstrates that the reset response leaves no
  stray STREAM retransmission queued.
- 2026-05-23: Constrained local STOP_SENDING emission to Recv and Size Known
  receive states. `stopSending()` now returns `StreamClosed` once final data has
  already arrived, while streams with a known final size and missing gaps can
  still request STOP_SENDING. Tests cover Data Recvd rejection and Size Known
  success; `examples/stop_sending.zig` demonstrates skipping STOP_SENDING after
  final data.
- 2026-05-23: Dropped queued STOP_SENDING frames that become obsolete before
  transmit. Unencrypted, protected 0-RTT, and protected 1-RTT packetization now
  filter STOP_SENDING once the receive side reaches Data Recvd or Reset Recvd.
  Tests cover final-data and RESET_STREAM races, and
  `examples/stop_sending.zig` demonstrates the reset race.
- 2026-05-22: Added client-side NEW_TOKEN storage in `Connection`.
  Client connections retain opaque token bytes up to `Config.max_stored_new_tokens`
  and expose the newest token via `latestNewToken()`. Tests cover storage,
  capacity, server-side rejection, and invalid-payload rollback. Later bullets
  cover cryptographic token generation and endpoint peer-address binding.
- 2026-05-22: Added local close emission in `Connection` with
  `closeConnection()` and `closeApplication()`. The methods queue
  CONNECTION_CLOSE variants, `pollTx()` emits the close frame while entering
  local closing state, and tests cover payload encoding, API rejection while
  closing, invalid value rejection, and size validation without mutation.
- 2026-05-22: Added an explicit `ConnectionState` model exposed by
  `connectionState()` and `closeDeadlineMillis()`. Local close enters
  `closing`, peer close enters `draining`, and both expire to `closed` after the
  current simplified 3x PTO timeout. Tests cover local close expiry, peer close
  expiry, and invalid-payload rollback to `active`. Later bullets cover
  validated-address send limits.
- 2026-05-23: Added peer close diagnostics through `peerClose()`. Inbound
  transport and application CONNECTION_CLOSE frames now copy the peer error
  code, transport frame type when present, and reason phrase before entering
  draining. Invalid multi-frame payloads roll this diagnostic state back, and
  the recorded peer close remains observable after the drain timer expires.
  `examples/graceful_close.zig` prints the in-memory and protected short-packet
  peer close diagnostics.
- 2026-05-23: Added explicit `HandshakeState` progress observability through
  `handshakeState()`. The connection starts in `initial`, moves to `handshake`
  when Handshake-space traffic is queued or processed, and reaches `confirmed`
  through `confirmHandshake()`, server `sendHandshakeDone()`, or client-side
  HANDSHAKE_DONE receipt. Invalid payloads roll back state transitions. Tests
  cover send-side and receive-side transitions plus rollback, and
  `examples/crypto_stream.zig` prints the modeled handshake state.
- 2026-05-22: Added local close retransmission during `closing`. The connection
  retains the queued CONNECTION_CLOSE/APPLICATION_CLOSE frame until the 3x PTO
  close deadline, `pollTx()` can retransmit it while other public APIs remain
  closed, and expiry releases the retained frame.
- 2026-05-22: Added modeled `max_idle_timeout` handling. `Config.max_idle_timeout_ms`
  is exported through local transport parameters, peer `max_idle_timeout` is
  applied after parameter parsing, and `effectiveIdleTimeoutMillis()` uses the
  shorter non-zero endpoint value. Successful send/receive activity refreshes
  `idleTimeoutDeadlineMillis()`, invalid frame payloads do not refresh it, and
  `checkIdleTimeouts()` closes active connections at the controlled deadline.
- 2026-05-22: Added `examples/idle_timeout.zig` and
  `zig build run-idle-timeout`. The example demonstrates peer/local timeout
  negotiation, activity-based deadline refresh, and active-to-closed expiry.
- 2026-06-02: Added
  `EndpointConnectionLifecycle.checkIdleTimeoutsAndRetireConnection()` so an
  endpoint event loop can apply a connection idle timeout and remove the
  associated destination-CID routes plus recovery timer in the same controlled
  clock step. `examples/idle_timeout.zig` now prints the lifecycle cleanup
  result.
- 2026-06-03: Added `Connection.checkCloseTimeouts()` and
  `EndpointConnectionLifecycle.checkCloseTimeoutsAndRetireConnection()` so an
  endpoint event loop can apply close/drain timeout expiry and remove the
  associated destination-CID routes plus recovery timer in the same controlled
  clock step. Tests cover both local closing and peer draining transitions, and
  `examples/udp_close_lifecycle_loopback.zig` prints the timeout cleanup
  result.
- 2026-05-22: Added modeled RFC 9000 server anti-amplification send limiting.
  Server connections start with an unvalidated peer address, expose
  `recordPeerAddressBytesReceived()`, `antiAmplificationLimitRemaining()`, and
  `validatePeerAddress()`, and enforce the shared 3x send budget in `pollTx()`
  and `pollTxInSpace()` until validation lifts the limit. Tests cover blocked
  sends before any received bytes, budget consumption across packet number
  spaces, validation unblocking, and invalid-payload rollback preserving the
  explicit budget.
- 2026-05-22: Added explicit one-time Retry token validation hooks.
  `issueRetryToken()` registers a server-owned opaque token, and
  `validateRetryToken()` consumes a matching token once while marking the peer
  address validated. Tests cover empty/duplicate token rejection, server-only
  use, invalid-token no-op behavior, successful consumption, anti-amplification
  unblocking, and non-reuse. Authenticated token generation, expiration, and
  endpoint peer-address binding are covered by later address-validation token
  and endpoint helpers.
- 2026-05-22: Added an explicit `PacketNumberSpace` model for Initial,
  Handshake, and Application frame-payload processing. `recordPacketSentInSpace()`,
  `receiveAckInSpace()`, `queueAckForReceivedPacketInSpace()`, and
  `processDatagramInSpace()` keep ACK generation, sent-packet tracking, and
  simplified recovery state isolated per space. `FramePacketType` plus
  `processDatagramForPacketType()` distinguish 0-RTT from 1-RTT frame-type
  validation while both share Application packet number space accounting. Tests
  cover ACK/recovery isolation, receive-side ACK generation isolation, and
  0-RTT forbidden-frame rollback. Protected endpoint routing, automatic
  TLS-triggered key discard, and full endpoint-owned key-state integration
  remain pending.
- 2026-05-22: Added `examples/packet_spaces.zig` and
  `zig build run-packet-spaces`. The example demonstrates that an ACK in the
  Initial packet number space does not acknowledge Application packets and that
  receive-side ACK scheduling is kept separate for Handshake and Application
  frame-payload processing.
- 2026-05-22: Added PTO-driven PATH_CHALLENGE retry and failure observability.
  `checkPathValidationTimeouts()` moves timed-out outstanding challenges back to
  the send queue, `pollTx()` performs that check automatically before emitting
  new payloads, and `failedPathValidationCount()` reports challenges that
  exhausted the current three-transmission budget. Tests cover pre-timeout no-op,
  retry queuing, automatic retry emission, retry exhaustion, and invalid-payload
  rollback preserving outstanding challenge metadata. Endpoint path identity
  binding remains pending until UDP routing exists.
- 2026-05-22: Added `examples/path_validation.zig` and
  `zig build run-path-validation`. The example demonstrates timeout-triggered
  retry, matching PATH_RESPONSE validation after retry, retry-budget
  exhaustion, protected short-header PATH_CHALLENGE/PATH_RESPONSE, and endpoint
  lifecycle route path update after protected PATH_RESPONSE validation.
- 2026-06-02: Added
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramAndUpdatePath()`.
  It commits endpoint route path updates only after routed protected short-packet
  authentication succeeds and the packet consumes an outstanding
  PATH_CHALLENGE through a matching PATH_RESPONSE. `run-path-validation` and
  `run-udp-path-validation-loopback` now use this validation-driven lifecycle
  path update instead of a manual follow-up `updateRoutePath()` call.
- 2026-06-03: Added
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramAndUpdatePathOrClose()`.
  It keeps the same validation-driven success path while queuing
  CONNECTION_CLOSE for authenticated Application frame errors and leaving the
  endpoint route unchanged on failure. Tests cover the no-update close path, and
  `run-udp-path-validation-loopback` now uses the close-propagating helper.
- 2026-05-30: Expanded protected short-header PATH_CHALLENGE and
  PATH_RESPONSE datagrams to at least 1200 bytes when the modeled peer-address
  send budget permits it, matching RFC 9000 path-validation padding while
  keeping anti-amplification-limited fallback small. Tests cover both expanded
  exchange and fallback, and `examples/path_validation.zig` asserts and prints
  the 1200-byte datagram evidence.
- 2026-05-30: Suppressed duplicate pending PATH_RESPONSE entries for repeated
  PATH_CHALLENGE data before the first response is sent. The connection still
  ACKs the receiving packet and retains one response per distinct challenge
  token, preventing repeated challenge frames from growing the pending response
  queue with identical payloads.
- 2026-05-22: Added `examples/connection_ids.zig` and
  `zig build run-connection-ids`. The example demonstrates local
  NEW_CONNECTION_ID issuance, peer RETIRE_CONNECTION_ID handling, and
  lifecycle-owned issue/register endpoint replacement-CID route bridging with
  retire_prior_to.
- 2026-05-22: Added stateless reset helpers in `quicz.packet` and read-only
  connection-level reset detection. `encodeStatelessReset()` serializes a reset
  datagram from caller-provided unpredictable bytes plus a 16-byte token,
  `matchesStatelessReset()` compares the trailing token in constant time, and
  `Connection.detectStatelessReset()` matches active peer-issued CID reset
  tokens while ignoring retired CIDs.
- 2026-05-22: Added `examples/stateless_reset.zig` and
  `zig build run-stateless-reset`. The example demonstrates matching a peer
  stateless reset token, rejecting a false token, and lifecycle-owned
  endpoint-level inactive-CID reset action construction.
- 2026-05-22: Added `quicz.protection.deriveInitialSecrets()` for RFC 9001
  QUIC v1 Initial secrets. It derives the Initial PRK, client/server Initial
  secrets, AEAD_AES_128_GCM keys, IVs, and AES header-protection keys from the
  first client Initial DCID using TLS HKDF-Expand-Label. `aes128HeaderProtectionMask()`
  and `applyHeaderProtectionMask()` now cover the RFC 9001 AES header-protection
  mask and reversible first-byte/packet-number masking. Tests cover RFC 9001
  Appendix A.1 and A.2 vectors, unsupported-version rejection,
  invalid CID length rejection, packet-number length validation, and short-header
  first-byte masking.
- 2026-05-22: Added `packetProtectionNonce()`, `protectAes128Payload()`, and
  `unprotectAes128Payload()` for RFC 9001 AEAD_AES_128_GCM payload protection
  with packet-number XOR nonce construction and associated-data authentication.
  Tests cover the RFC 9001 Appendix A.3 Server Initial protected payload,
  decrypt roundtrip, authentication failure mapping, invalid packet-number
  rejection, and buffer-length validation. Full protected-packet assembly,
  protected-packet routing, real TLS traffic-secret production, key discard, and
  key update remain pending.
- 2026-05-22: Added `protectLongPacketAes128()` and
  `unprotectLongPacketAes128()` to combine long-header serialization,
  AEAD_AES_128_GCM payload protection, authentication tag handling, header
  protection sampling, packet-number unmasking, packet-number reconstruction,
  and authenticated payload opening for one protected long-header packet. Added
  `peekProtectedLongPacketInfo()` to expose the version, packet type, and
  consumed length needed for coalesced protected long-packet receive routing.
  Tests cover the RFC 9001 Appendix A.3 Server Initial final protected packet,
  open roundtrip, authentication failure, too-short header-protection sample
  rejection, and protected long-packet boundary peeking. Endpoint routing,
  real TLS traffic-secret production, key discard, and key update remain pending.
- 2026-05-22: Added `Connection.processInitialProtectedDatagram()`. This
  connection-layer bridge opens one QUIC v1 protected Initial long packet with
  caller-supplied RFC 9001 Initial keys, validates the packet type, packet
  number, and single-packet datagram boundary, then routes the plaintext frame
  payload into the Initial packet number space. Tests cover protected Initial
  CRYPTO delivery, ACK generation, next peer packet-number advancement, and
  tampered-packet rollback. Protected transmit beyond CRYPTO-only long packets,
  TLS traffic secret production, key discard, and key update remain pending.
- 2026-05-22: Added `Connection.pollInitialProtectedDatagram()` for the
  transmit side of the Initial CRYPTO bridge. It emits one protected QUIC v1
  Initial long packet from the Initial CRYPTO send queue, uses the selected
  packet-number encoding, pads only as needed for the header-protection sample,
  and records protected datagram bytes in sent-packet, recovery, anti-amplification,
  and idle-timeout accounting. Tests cover protected send to
  `processInitialProtectedDatagram()`, packet-number advancement, bytes-in-flight
  accounting, and idle behavior when no Initial CRYPTO is queued. ACK-only,
  PING-only, TLS traffic secret production, key
  discard, and key update remain pending.
- 2026-05-22: Added `Connection.processProtectedLongDatagramInSpace()` and
  `pollProtectedLongCryptoDatagramInSpace()` to generalize the protected
  long-packet bridge from Initial to both Initial and Handshake packet number
  spaces. The Initial-specific wrappers remain for compatibility. Tests cover
  protected Handshake CRYPTO emit/decrypt/delivery, packet-number accounting,
  long-packet packet-type mismatch rollback, and Handshake token rejection
  before send-state mutation. `examples/crypto_stream.zig` now sends both the
  Initial and Handshake CRYPTO flights through protected long packets using
  caller-supplied keys. Endpoint Retry policy, 1-RTT protected
  transmit, TLS secret production, key discard, and key update remain pending.
- 2026-05-22: Added `Connection.processProtectedLongDatagram()` and
  `ProtectedLongDatagramKeys` for coalesced protected long datagram receive
  routing. The method peeks each long-header packet boundary, verifies that all
  packet types are supported and have caller-supplied keys before mutation, then
  opens and routes each Initial or Handshake packet into its packet number
  space. Tests cover Initial+Handshake CRYPTO in one coalesced datagram and
  missing Handshake key rejection without earlier Initial-state mutation.
  `examples/crypto_stream.zig` now demonstrates a coalesced server Initial plus
  Handshake flight. Endpoint Retry policy, 1-RTT protected
  transmit, TLS secret production, key discard, and key update remain pending.
- 2026-05-22: Added `Connection.pollProtectedLongDatagram()` for
  coalesced protected long datagram transmit. The method prebuilds the next
  Initial and Handshake protected packet from queued CRYPTO, PING plus optional
  ACK, or ACK-only state, verifies aggregate datagram size, congestion state,
  and anti-amplification budget, then commits packet numbers, sent-packet
  records, recovery bytes, ACK/PING state, and CRYPTO queue removals together.
  Tests cover Initial+Handshake coalesced transmit into
  `processProtectedLongDatagram()`, missing Handshake key rejection without
  send-state mutation, ACK-only packets that advance packet numbers without
  bytes-in-flight, and PING+ACK packets that remain ack-eliciting.
  `examples/crypto_stream.zig` now uses `pollProtectedLongDatagram()` for both
  the coalesced server flight and a coalesced client Initial ACK-only plus
  Handshake PING/ACK probe. Endpoint Retry policy, 1-RTT
  protected transmit, TLS secret production, key discard, and key update remain
  pending.
- 2026-05-22: Added `protectShortPacketAes128()`,
  `unprotectShortPacketAes128()`, `deinitProtectedShortPacket()`, and
  `Connection.processProtectedShortDatagram()` for caller-supplied 1-RTT
  short-header packet receive. The connection API requires caller-provided
  destination-CID length context, opens one protected short datagram, requires
  the packet number to match the next expected Application packet number, and
  then routes plaintext through 1-RTT frame rules. Tests cover protected
  short-packet roundtrip, header-protection sample bounds, PING delivery into
  Application ACK state, packet-number mismatch rollback, and authentication
  failure without state mutation. `examples/crypto_stream.zig` now demonstrates
  a protected 1-RTT PING receive after modeled handshake confirmation. Retry
  routing, TLS secret production, key discard, and key update remain pending.
- 2026-05-22: Added `Connection.pollProtectedShortDatagram()` for
  caller-supplied 1-RTT short-header PING/ACK transmit. The method protects
  Application-space PING plus optional ACK, or ACK-only state, checks
  congestion and anti-amplification budget, advances packet numbers, tracks
  bytes-in-flight only for ack-eliciting packets, and clears committed ACK/PING
  state. Tests cover a protected 1-RTT PING followed by an ACK-only protected
  response that removes the sender's bytes-in-flight. `examples/crypto_stream.zig`
  now demonstrates the protected 1-RTT PING/ACK exchange after modeled
  handshake confirmation. Endpoint Retry policy, TLS secret production, key discard,
  and key update remain pending.
- 2026-05-22: Extended `Connection.pollProtectedShortDatagram()` to protect
  one queued Application-space STREAM frame with an optional ACK in a 1-RTT
  short packet. The commit path now consumes the sent stream frame only after
  packet-number, congestion, and anti-amplification checks pass, and frees the
  prebuilt datagram when those checks block transmission. Tests cover a
  protected STREAM delivery followed by a protected ACK that removes the
  sender's bytes-in-flight, plus an anti-amplification block that preserves the
  queued STREAM for a later send. `examples/crypto_stream.zig` now demonstrates
  caller-keyed protected 1-RTT PING/ACK and STREAM/ACK exchanges after modeled
  handshake confirmation. Endpoint Retry policy, TLS secret production, key discard,
  and key update remain pending.
- 2026-05-22: Extended `Connection.pollProtectedShortDatagram()` to protect
  queued Application-space `RESET_STREAM` and `STOP_SENDING` frames with an
  optional ACK in 1-RTT short packets. The protected path now follows the
  stream-control priority used by `pollTx()`, consumes RESET/STOP queues only
  after send commit, and still drops stale STREAM data after RESET_STREAM has
  been sent. Tests cover protected RESET_STREAM delivery, stale STREAM removal,
  protected ACK cleanup, and protected STOP_SENDING followed by a protected
  RESET_STREAM response. `examples/crypto_stream.zig` now demonstrates
  caller-keyed protected 1-RTT PING/ACK, STREAM/ACK, RESET_STREAM/ACK, and
  STOP_SENDING/RESET_STREAM exchanges. Endpoint Retry policy, TLS secret production,
  key discard, and key update remain pending.
- 2026-05-22: Extended `Connection.pollProtectedShortDatagram()` to protect
  queued Application-space CRYPTO frames with an optional ACK in 1-RTT short
  packets. The protected path consumes the CRYPTO queue only after
  packet-number, congestion, and anti-amplification checks pass, matching the
  existing rollback boundary used by STREAM transmit. Tests cover protected
  CRYPTO delivery followed by protected ACK cleanup, plus an anti-amplification
  block that preserves the queued CRYPTO frame for a later send.
  `examples/crypto_stream.zig` now demonstrates caller-keyed protected 1-RTT
  PING/ACK, CRYPTO/ACK, STREAM/ACK, RESET_STREAM/ACK, and
  STOP_SENDING/RESET_STREAM exchanges. Endpoint Retry policy, TLS secret production,
  key discard, and key update remain pending.
- 2026-05-22: Extended `Connection.pollProtectedShortDatagram()` to protect
  queued Application-space `PATH_RESPONSE` and outbound `PATH_CHALLENGE` frames
  with an optional ACK in 1-RTT short packets. PATH_RESPONSE queues are consumed
  only after send commit, while PATH_CHALLENGE is moved to outstanding
  validation state only after packet-number, congestion, and anti-amplification
  checks pass. Protected PATH_CHALLENGE/PATH_RESPONSE datagrams are expanded to
  at least 1200 bytes when the anti-amplification budget allows it. Tests cover
  a protected PATH_CHALLENGE/PATH_RESPONSE/ACK roundtrip, anti-amplification
  fallback for PATH_RESPONSE padding, plus an anti-amplification block that
  preserves a pending PATH_CHALLENGE. `examples/path_validation.zig` now
  demonstrates the protected short-header path-validation exchange and
  datagram expansion alongside the frame-payload retry examples. Endpoint
  Retry policy, TLS secret production, key discard, and key update remain
  pending.
- 2026-05-23: Added a protected path-validation and endpoint-routing
  integration test. A datagram arriving on a new UDP tuple is first reported as
  `path_changed`; only after the matching protected PATH_RESPONSE is processed
  does caller code commit `EndpointRouter.updateRoutePath()`, after which the
  same tuple routes without a path-change report. `examples/path_validation.zig`
  now prints the endpoint path-change and path-update result. Automatic
  socket-backed path-validation ownership remains pending.
- 2026-05-23: Extended `Connection.pollProtectedShortDatagram()` to protect
  queued Application-space `RETIRE_CONNECTION_ID` frames and unsent local
  `NEW_CONNECTION_ID` frames with an optional ACK in 1-RTT short packets. The
  protected path consumes the RETIRE queue and marks local connection IDs as
  sent only after packet-number, congestion, and anti-amplification checks pass.
  Tests cover protected NEW/ACK, replacement NEW causing protected RETIRE+ACK,
  final ACK cleanup, and an anti-amplification block that preserves an unsent
  NEW_CONNECTION_ID. `examples/connection_ids.zig` now demonstrates
  lifecycle-owned issue/register route bridging and the caller-keyed protected
  1-RTT NEW_CONNECTION_ID/RETIRE_CONNECTION_ID exchange.
  Endpoint Retry policy, TLS secret production, key discard, and key update remain
  pending.
- 2026-05-23: Extended `Connection.pollProtectedShortDatagram()` to protect
  queued Application-space MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS_BIDI/UNI,
  DATA_BLOCKED, STREAM_DATA_BLOCKED, and STREAMS_BLOCKED_BIDI/UNI frames with
  an optional ACK in 1-RTT short packets. The protected path drops obsolete
  MAX/BLOCKED entries before packetization and consumes the queued frame only
  after packet-number, congestion, and anti-amplification checks pass. Tests
  cover protected MAX_DATA/MAX_STREAM_DATA delivery, all protected BLOCKED
  variants, and anti-amplification blocks that preserve queued MAX/BLOCKED
  frames for a later send. `examples/flow_control.zig` now demonstrates a
  caller-keyed protected short STREAM_DATA_BLOCKED plus MAX_DATA/MAX_STREAM_DATA
  exchange that restores stream sending. Endpoint Retry policy, TLS secret production,
  key discard, and key update remain pending.
- 2026-05-23: Extended `Connection.pollProtectedShortDatagram()` to protect
  queued Application-space CONNECTION_CLOSE and APPLICATION_CLOSE frames in
  1-RTT short packets. The protected close path is available while a local
  close is pending or closing, advances packet numbers without tracking
  bytes-in-flight, enters closing only after packet-size and anti-amplification
  checks pass, and retains the close frame for retransmission until close-state
  expiry. Tests cover protected CONNECTION_CLOSE delivery, APPLICATION_CLOSE
  delivery, retransmission, close timeout expiry, and anti-amplification blocks
  that preserve pending close state without committing packet numbers.
  `examples/graceful_close.zig` now demonstrates protected close delivery,
  retransmission, and protected application close delivery. Endpoint Retry policy, TLS
  secret production, key discard, and key update remain pending.
- 2026-05-23: Added server-only `sendHandshakeDone()` and `issueNewToken()`,
  then extended `Connection.pollProtectedShortDatagram()` to protect queued
  HANDSHAKE_DONE and NEW_TOKEN frames in 1-RTT short packets. The protected path
  consumes each queue only after packet-number, congestion, and
  anti-amplification checks pass; tests cover side validation, protected
  HANDSHAKE_DONE delivery and ACK cleanup, protected NEW_TOKEN delivery and
  client storage, and anti-amplification blocks that preserve both queues.
  `examples/address_validation.zig` now demonstrates protected HANDSHAKE_DONE
  confirmation and protected NEW_TOKEN storage. Endpoint Retry policy, TLS secret
  production, key discard, and key update remain pending.
- 2026-05-23: Added caller-keyed protected 0-RTT long-packet routing. The
  `ProtectedLongDatagramKeys.zero_rtt` field lets `processProtectedLongDatagram()`
  route coalesced 0-RTT packets into the shared Application packet number space
  while applying 0-RTT frame restrictions, and `pollProtectedZeroRttDatagram()`
  or `pollProtectedLongDatagram()` can emit one client-side protected 0-RTT
  STREAM, RESET_STREAM, or STOP_SENDING packet without coalescing ACK or CRYPTO.
  Tests cover protected 0-RTT STREAM delivery, Initial+0-RTT coalescing with
  missing-key validation before mutation, and protected 0-RTT ACK rejection.
  `examples/packet_spaces.zig` now demonstrates protected 0-RTT Application
  packet-number sharing plus protected STREAM/RESET_STREAM/STOP_SENDING
  retransmission. Real TLS-backed early-data secret ownership,
  acceptance policy, replay defense, endpoint Retry policy, key discard, and key
  update remain pending.
- 2026-05-23: Added client-side `Connection.processRetryDatagram()` for
  Retry packet routing. It verifies the RFC 9001 Retry Integrity Tag with the
  Original Destination Connection ID, rejects server-side, duplicate, discarded
  Initial-space, and malformed Retry datagrams without state mutation, stores
  `latestRetryToken()` plus `retrySourceConnectionId()`, and automatically uses
  the stored token when later protected Initial packetization receives an empty
  explicit token. Tests cover token/Retry SCID storage, automatic Initial token
  reuse, tamper rejection, duplicate rejection, and server-side rejection.
  `examples/retry_token.zig` now demonstrates the connection-layer Retry
  processing path. Later bullets cover in-memory endpoint-level Retry DCID
  switching and token policy.
- 2026-05-23: Added server-side `Connection.issueRetryDatagram()` for
  connection-layer Retry issuance. It builds a QUIC v1 Retry datagram with the
  RFC 9001 Retry Integrity Tag, registers the opaque token for one-time
  validation, records Original Destination Connection ID plus Retry Source
  Connection ID, and exports both through `localTransportParameters()`. Tests
  cover Retry integrity, local transport-parameter export, client processing,
  token consumption, duplicate issuance rejection, and invalid-input rollback.
  `examples/retry_token.zig` now uses this connection-layer issuance path.
  Later bullets cover the in-memory endpoint-level Retry DCID switching and
  token policy.
- 2026-05-23: Added `quicz.address_validation_token` plus
  `Connection.issueAddressValidationToken()` and
  `validateAddressValidationToken()`. Tokens are HMAC-SHA256 authenticated,
  carry a kind, originating version, issued time, lifetime, and nonce, and bind
  the peer address as MAC input without serializing address bytes into the token. Tests cover
  kind/address/tamper/expiry checks, allocation failure, one-time Retry token
  consumption after cryptographic validation, NEW_TOKEN validation without
  one-time Retry state, and anti-amplification unblocking. `examples/retry_token.zig`
  now uses an address-bound expiring Retry token, and
  `examples/address_validation.zig` validates an address-bound NEW_TOKEN on a
  later server connection.
- 2026-05-23: Added `address_validation_token.ReplayFilter` plus public token
  fingerprints for endpoint-owned NEW_TOKEN replay defense. The filter stores
  only token MAC fingerprints, expects callers to record tokens after
  cryptographic validation succeeds, rejects duplicate use with
  `error.TokenReplay`, and evicts the oldest fingerprint when its configured
  capacity is full. Tests cover duplicate rejection, invalid token shape, and
  bounded-capacity eviction. `examples/address_validation.zig` now records a
  validated NEW_TOKEN before lifting anti-amplification for a later server
  connection and rejects a second use through the replay filter. Full endpoint
  ownership is covered by the later `AddressValidationPolicy`; later bullets
  cover replay-filter snapshot export/restore.
- 2026-05-23: Added `address_validation_token.validateAnySecret()`,
  `validateAnySecretAndRemember()`, and
  `Connection.validateAddressValidationTokenWithSecrets()`. Callers can
  validate address tokens against an ordered current/previous secret set so
  tokens issued before a secret rotation remain usable until their encoded
  lifetime expires. The validate-then-remember helper records a token in
  `ReplayFilter` only after MAC, kind, address, and lifetime checks pass, and
  duplicate use returns `TokenReplay`. Tests cover old-secret issuance validated
  by a rotated secret set, empty/current-only secret rejection, preserved expiry
  errors, replay recording, and connection-level NEW_TOKEN anti-amplification
  unblocking.
- 2026-05-23: Added `endpoint.Udp4Address.addressValidationBinding()` and
  `Udp4Tuple.peerAddressValidationBinding()`. Endpoint policy can now pass a
  stable six-byte remote IPv4 address plus UDP port value as the
  address-validation token `peer_address` input, avoiding text-formatting
  differences. The local address stays in routing policy and is not encoded
  into this peer-address token binding. Tests cover token reuse for the same
  remote peer across a different local address and token rejection when the
  remote port or address changes. `examples/address_validation.zig` and
  `examples/retry_token.zig` now use this endpoint binding and demonstrate that
  a wrong remote port does not unblock anti-amplification or consume a Retry
  token.
- 2026-05-23: Added `endpoint.AddressValidationPolicy`, an in-memory endpoint
  policy that owns the active token secret, a bounded set of retained previous
  secrets, and a bounded replay filter. It can issue path-bound Retry/NEW_TOKEN
  values, rotate secrets while keeping already-issued tokens valid until expiry,
  validate against current/previous secrets, and record replay state only after
  successful validation. Tests cover rotated-token validation, wrong-path
  rejection, replay rejection, and dropping the oldest retained secret after the
  configured rotation limit. `examples/address_validation.zig` now uses this
  policy for NEW_TOKEN issue/validate/replay, and `examples/retry_token.zig`
  uses it for Retry token issue/path validation before connection-level
  one-time token consumption. Persistent secret distribution and replay-filter
  snapshot persistence are covered by later bullets.
- 2026-05-23: Added `endpoint.AddressValidationSecretSet`,
  `AddressValidationPolicy.exportSecretSet()`, and
  `AddressValidationPolicy.initWithSecretSet()`. Endpoint policy can now
  snapshot active/previous token secrets for external persistence or worker
  distribution and restore them in another policy while trimming previous
  secrets to the configured retention limit. Replay-filter snapshot persistence
  is covered by the next bullet. Tests cover restored validation and retention trimming, and
  `examples/address_validation.zig` now validates a stored NEW_TOKEN through a
  restored policy.
- 2026-05-23: Added `address_validation_token.ReplayFilterSnapshot`,
  `ReplayFilter.exportSnapshot()`, `ReplayFilter.initWithSnapshot()`,
  `AddressValidationPolicy.exportReplayFilter()`, and
  `AddressValidationPolicy.initWithSecretSetAndReplayFilter()`. Endpoint
  policy can now snapshot validated-token fingerprints for external storage or
  worker distribution, restore them alongside token secrets, trim them to
  `max_replay_entries`, and keep rejecting already-used tokens after restore.
  Tests cover replay snapshot restore, retention trimming, and policy-level
  replay rejection across restore. `examples/address_validation.zig` now prints
  restored replay-entry count and rejects a persisted replay through a restored
  policy. Production shared storage, cross-worker merge semantics, and durable
  retention scheduling remain external.
- 2026-05-23: Added
  `EndpointRouter.switchInitialDestinationConnectionIdAfterRetry()` for
  endpoint-level Retry DCID switching. After a server sends Retry, the helper
  replaces the active Initial route's original Destination Connection ID with
  the Retry Source Connection ID while preserving the caller-owned connection
  handle and UDP path. It rejects duplicate target CIDs, stale path input, and
  NEW_CONNECTION_ID sequence routes. Tests and `examples/endpoint_routing.zig`
  cover old-DCID retirement and routing of the subsequent Initial by Retry SCID.
- 2026-05-23: Added `EndpointRouter.commitPreferredAddressMigration()` for
  caller-validated migration to a server preferred address. The helper installs
  the preferred-address connection ID on the preferred UDP tuple, preserves the
  same caller-owned connection handle, carries the preferred-address stateless
  reset token, and retires the previous active route. Tests and
  `examples/endpoint_routing.zig` cover duplicate target rejection, stale-path
  rejection, zero-length preferred CID rejection, old-route retirement, active
  route reset-token suppression, retired preferred-CID reset-token lookup, and
  route preservation of active-migration-disabled policy. Automatic
  socket-backed preferred-address migration remains pending; the UDP loopback
  now learns the preferred CID/token through server preferred_address
  transport-parameter bytes before committing the caller-validated route.
- 2026-05-23: `applyPeerTransportParameters()` now validates the server's
  `original_destination_connection_id` against the DCID used by the first sent
  client Initial, and validates `retry_source_connection_id` against the Retry
  Source Connection ID stored by `processRetryDatagram()` when Retry was used.
  A client that did not process Retry rejects an unexpected
  `retry_source_connection_id`; a client that did process Retry requires both
  parameters and rejects mismatches before mutating peer limits.
  Tests cover the no-Retry `original_destination_connection_id` missing,
  mismatch, and success paths. `examples/retry_token.zig` demonstrates the
  Retry missing-parameter failure and matching-parameter success path.
- 2026-05-23: Protected Initial receive now stores the peer's first Initial
  Source Connection ID in `peerInitialSourceConnectionId()`, and
  `applyPeerTransportParameters()` validates peer `initial_source_connection_id`
  before mutating limits once that SCID is known. Tests cover protected Initial
  storage, tampered-packet rollback, missing parameter rejection, mismatch
  rejection, and successful matching application. `examples/crypto_stream.zig`
  now demonstrates the missing-parameter failure and matching
  `initial_source_connection_id` success path.
- 2026-05-23: Protected Initial transmit now records the endpoint's first sent
  Initial Source Connection ID in `localInitialSourceConnectionId()`, and
  `localTransportParameters()` exports it as `initial_source_connection_id`
  once available. Tests cover idle no-export behavior plus both compatibility
  Initial CRYPTO and coalesced Initial+Handshake transmit paths.
  `examples/crypto_stream.zig` now uses the server's exported local transport
  parameters when the client validates the server Initial SCID. TLS transcript
  integration for those exported parameters remains pending.
- 2026-05-23: Server connections now record the Original Destination Connection
  ID from the first successfully opened protected client Initial and export it
  through `localTransportParameters().original_destination_connection_id`.
  `examples/crypto_stream.zig` now demonstrates no-Retry Original DCID export
  and client-side validation together with Initial SCID validation.
- 2026-05-25: Tightened protected Initial packet DCID/token validation. First
  client Initial packetization and server receive now reject Destination
  Connection IDs shorter than 8 bytes, client Initial packetization preserves
  the recorded Original DCID before Retry, the Retry Source CID after Retry,
  and the peer Initial SCID after a server Initial is received. Server Initial
  packetization plus client receive reject non-empty Initial tokens. Tests
  cover send/receive rollback, post-server-Initial client DCID selection, and
  the coalesced Initial+0-RTT test now uses a valid 8-byte first client Initial
  DCID.
- 2026-05-25: Added RFC 9000 Initial UDP datagram size handling. Client Initial
  datagrams and server ack-eliciting Initial datagrams are padded to at least
  1200 bytes, coalesced Initial datagrams pad only enough for the whole UDP
  datagram to meet the limit, server ACK-only Initial datagrams stay compact,
  and server Initial receive rejects UDP datagrams below 1200 bytes before
  packet-number or CRYPTO state changes. Tests cover small-datagram rejection,
  client/server expansion, ACK-only non-expansion, bytes-in-flight accounting,
  and rollback.
- 2026-05-22: Added `retryIntegrityTag()`, `verifyRetryIntegrityTag()`,
  `encodeRetryPacketWithIntegrity()`, and `parseRetryPacketWithIntegrity()` for
  Retry Packet Integrity. The lower-level helper builds the Retry
  pseudo-packet from the Original Destination Connection ID and the transmitted
  Retry bytes without the final tag, then computes the version-specific fixed-key
  AEAD_AES_128_GCM tag. The integrated helpers serialize a QUIC Retry packet
  with a valid tag and verify before parsing. Tests cover the RFC 9001 and
  RFC 9369 Appendix A.4 Retry vectors, integrated encode/verify/parse, tamper rejection, invalid
  Original DCID length, unsupported version rejection, and too-short Retry
  datagrams. Production endpoint token-secret storage/distribution around
  exported secret/replay snapshots remains pending.
- 2026-05-22: Added `examples/initial_keys.zig` and
  `zig build run-initial-keys`. The example prints the RFC 9001 Appendix A
  v1 Initial client/server key, IV, AES header-protection mask, and protected
  packet number values for the sample DCID, then seals and opens a small
  protected server Initial long-header packet with the derived AEAD and header
  protection keys.
- 2026-05-23: Added `nextAes128TrafficSecret()` and
  `nextAes128PacketProtectionKeys()` for RFC 9001 key update derivation with
  the `quic ku` HKDF label. The helper updates the traffic secret, AEAD key,
  and IV while retaining the header protection key. Tests cover fixed
  `quic ku` output derived from the RFC 9001 Appendix A client Initial secret
  and verify that header protection is stable across updates. `examples/initial_keys.zig`
  now prints the next traffic secret, key, IV, and retained-header-protection
  check. TLS-produced 1-RTT secret integration remains pending.
- 2026-05-23: Added caller-owned key-phase state handling for protected 1-RTT
  short packets. `peekShortPacketKeyPhaseAes128()` reveals the wire key phase
  after header protection, `unprotectShortPacketAes128WithKeyUpdate()` selects
  current or next packet protection keys, `Aes128KeyPhaseState` tracks current
  and next keys for one direction, `pollProtectedShortDatagramWithKeyPhase()`
  and `pollProtectedShortDatagramWithKeyPhaseState()` emit short packets with
  explicit key phases, and `processProtectedShortDatagramWithKeyUpdate()` plus
  `processProtectedShortDatagramWithKeyPhaseState()` process packets protected
  with either phase. Tests cover next-key authentication, rejection by the old
  single-key API, packet-number and key-phase state preservation on failure,
  and successful Application-space ACK scheduling after the key phase flips.
  `examples/crypto_stream.zig` now demonstrates a protected 1-RTT key-update
  PING through caller-owned key-phase state. TLS-triggered automatic key-update
  confirmation and old-key discard remain pending.
- 2026-05-23: Added ACK-gated installed-key 1-RTT key-update initiation.
  `initiateOneRttKeyUpdate()` now requires modeled handshake confirmation,
  rejects a second local update until an Application ACK covers a packet number
  sent with the new key phase, and rolls that ACK-confirmation state back if a
  later frame in the same payload is invalid. Tests cover pre-confirmation
  rejection, immediate repeat rejection, ACK-driven re-enable, and
  invalid-payload rollback. `examples/crypto_stream.zig` now confirms the
  modeled handshake before the installed-key key-update PING. Full TLS-owned
  live endpoint key-update scheduling and old-key discard remain pending.
- 2026-05-23: Added `quic/endpoint.zig` with an in-memory
  `EndpointRouter`. The router registers destination connection IDs against
  caller-owned connection handles and IPv4 UDP tuples, routes long-header
  datagrams by their encoded DCID, routes short-header datagrams by registered
  CID prefix matching, routes zero-length CIDs by exact UDP tuple, rejects
  duplicate/unknown/ambiguous CIDs, rejects stateless reset token reuse across
  different CIDs, stores optional NEW_CONNECTION_ID sequence numbers, supports
  route retirement by CID, sequence, or retire_prior_to
  threshold, lets callers update a route to a newly validated UDP tuple, and
  reports or rejects path changes according to
  `active_migration_disabled`. It can retain stateless reset tokens for
  inactive or retired destination CIDs, expose the matching token for a later
  unknown-CID response, and write stateless reset datagrams with
  caller-supplied unpredictable bytes while suppressing reset tokens for active
  routes and requiring the reset datagram to be smaller than the triggering
  datagram. `handleDatagram()` now classifies one received datagram as an
  active route delivery, stateless reset response, or drop.
  `switchInitialDestinationConnectionIdAfterRetry()` replaces an Initial route
  with a Retry Source CID after Retry, and
  `commitPreferredAddressMigration()` registers the preferred-address CID and
  retires the old route after caller-owned path validation, while preserving
  the connection handle and preferred stateless reset token.
  `registerReplacementConnectionId()` registers a replacement CID, validates
  Retire Prior To against the replacement sequence, and retires older sequence
  routes as one endpoint policy operation. This routing skeleton now has a
  socket-backed caller-owned proof for replacement CID retirement; connection
  object ownership, socket-owned endpoint Retry issuance/accept loops,
  automatic path validation, and full path-migration policy remain pending.
- 2026-05-25: Added endpoint classification for supported-version unknown-DCID
  client Initial datagrams. `peekInitialAcceptDatagram()` parses the
  version-independent long header plus Initial token/length fields without
  allocation, returns borrowed Original DCID, client Source CID, token, version,
  and UDP path metadata for a future server accept loop, ignores short headers,
  Version Negotiation packets, non-Initial long headers, and unsupported
  versions, and rejects malformed Initial headers before state mutation.
  `handleDatagramWithVersionNegotiation()` now returns `accept_initial` after
  route, Version Negotiation, and stateless-reset handling do not apply. Tests
  cover accept metadata, route precedence, ignored packet classes, malformed
  Initial rejection, and `examples/endpoint_routing.zig` prints the new action.
- 2026-05-25: Added
  `EndpointRouter.registerAcceptedInitialConnectionIds()` for the next server
  accept-loop step. After a caller accepts an Initial and creates the server
  connection, the helper installs the client's Original Destination Connection
  ID for Initial retransmissions and the server's first Initial Source
  Connection ID as sequence 0 for later peer packets, carrying optional
  stateless reset token policy. Duplicate/invalid route failures roll back the
  Original DCID route so the endpoint does not keep partial accept state. Tests
  and `examples/endpoint_routing.zig` cover route precedence after accept,
  server-SCID routing, sequence retirement, inactive-token lookup, and rollback.
- 2026-05-25: Added
  `EndpointRouter.registerClientInitialSourceConnectionId()` for the client
  connect side of endpoint routing. Before a client sends its Initial, callers
  can install the client Source CID as an inbound route so server Initial and
  Version Negotiation responses route back to the caller-owned connection. The
  helper also supports zero-length client SCIDs through tuple routing and keeps
  duplicate/too-long CID failures free of partial writes. Tests and
  `examples/endpoint_routing.zig` cover server-response routing, active
  migration rejection, zero-length tuple routing, and duplicate rollback.
- 2026-05-25: Added `EndpointRouter.retireConnectionRoutes()` for endpoint
  connection lifecycle cleanup. A caller can now remove all active routes for a
  closed connection handle while retaining stateless reset tokens for inactive
  CID handling. Tests and `examples/endpoint_routing.zig` cover multi-route
  retirement, preservation of other connections, inactive-token lookup after
  close, and active-route token suppression before close.
- 2026-05-25: Added `examples/udp_endpoint_loopback.zig` and
  `zig build run-udp-endpoint-loopback`. The example binds two loopback UDP
  sockets, sends a QUIC-like unsupported-version Initial through the endpoint
  Version Negotiation path, sends a supported Initial through the server accept
  classification path, registers the accepted server Initial Source CID and
  client Initial Source CID routes through `EndpointConnectionLifecycle`, and
  verifies a short-header follow-up over the same real UDP sockets. It
  deliberately stops at endpoint routing; real protected-packet/TLS socket
  ownership remains pending.
- 2026-05-25: Added `examples/udp_protected_loopback.zig` and
  `zig build run-udp-protected-loopback`. The example sends caller-keyed
  protected client Initial and server Initial datagrams over real loopback UDP
  sockets, registers endpoint routes from the accepted Initial metadata through
  the lifecycle owner, then routes and processes a protected 1-RTT PING/ACK
  exchange over the same sockets. This proves protected packet delivery through
  socket-backed endpoint lifecycle routing, while TLS-owned key production
  remains pending.
- 2026-05-25: Added `examples/udp_stateless_reset_loopback.zig` and
  `zig build run-udp-stateless-reset-loopback`. The example binds two loopback
  UDP sockets, first proves the active CID routes normally and suppresses its
  reset token, proves an unknown CID is dropped without a reset, then retires
  the CID while retaining the stateless reset token, delivers the same trigger
  datagram to the server socket, lets
  `EndpointConnectionLifecycle.handleDatagram()` classify it as a reset response
  through the lifecycle-owned route state, sends the reset datagram back, and
  verifies the client can match the retained token. Full TLS-owned connection
  lifecycle integration remains pending.
- 2026-05-22: Added per-packet-number-space ECN validation state to
  `Connection`. `recordEcnPacketSentInSpace()` records modeled ECT(0) or
  ECT(1) sent packets for deterministic tests, ACK_ECN counters are validated
  against newly acknowledged ECT packets and cumulative sent totals, regular
  ACKs for newly acknowledged ECT packets disable ECN validation, and reordered
  ACKs whose largest acknowledged packet number does not increase cannot fail
  validation. Invalid multi-frame payloads roll ECN validation state back.
- 2026-05-23: Added `endpoint.EcnPathPolicy`, an in-memory endpoint policy that
  stores ECN validation state by `Udp4Tuple`. It lets a migrated path start
  from `unknown` instead of inheriting another path's capable or failed state,
  and exposes `mayUseEct()` so endpoint packetization can stop setting ECT on a
  failed path. Real IP-header ECN marking remains pending.
- 2026-05-22: Added `examples/ecn_validation.zig` and
  `zig build run-ecn-validation`. The example demonstrates ECT(0) ACK_ECN
  validation, missing-counter failure, and endpoint path-identity isolation.
- 2026-05-22: Added simplified RFC 9002 packet-threshold loss detection in
  `Connection` ACK processing. When the largest acknowledged packet number
  is at least three packet numbers ahead of an unacknowledged sent packet in the
  same packet number space, that older packet is removed from sent tracking and
  reported to the recovery state as lost. Invalid multi-frame payloads roll
  packet-threshold loss state back.
- 2026-05-22: Added RFC 9002 time-threshold loss delay calculation,
  ACK-driven time-threshold loss detection, and a deterministic
  `checkLossDetectionTimeouts()` hook. The current skeleton uses
  `9/8 * max(latest_rtt, smoothed_rtt)` with a 1ms granularity floor, records
  the next loss deadline per packet number space, removes older unacknowledged
  packets whose send-time deadline has elapsed, and rolls the loss state back
  on invalid multi-frame payloads. Later updates add protected-packet sidecar
  retransmission and aggregate timer deadline selection; socket-owned
  protected-packet loss/PTO timer lifecycle integration remains pending.
- 2026-05-22: Added `examples/loss_recovery.zig` and
  `zig build run-loss-recovery`. The example demonstrates ACK-driven
  packet-threshold and time-threshold loss removal.
- 2026-05-22: Added RFC 9002 persistent congestion duration and response. The
  frame-payload recovery model records the first RTT sample's packet send time,
  treats contiguous lost packets sent after that sample as persistent congestion
  candidates, reduces the congestion window to the minimum window when their
  send-time span reaches the persistent congestion duration, and rolls that
  reduction back on invalid multi-frame payloads. `examples/loss_recovery.zig`
  demonstrates the resulting congestion-window reduction.
- 2026-05-22: Added a NewReno-style congestion recovery period to the
  frame-payload recovery model. Losses of packets sent before the current
  recovery period started no longer reduce the congestion window again, and ACKs
  for packets sent before recovery do not grow the congestion window. Tests
  cover direct recovery-state behavior and connection-level ACK/loss handling;
  `examples/loss_recovery.zig` demonstrates repeated loss suppression.
- 2026-05-22: Added `ptoDeadlineMillis()` and `checkPtoTimeouts()` for
  deterministic packet-number-space PTO hooks. When the simplified PTO deadline
  expires and a packet is in flight, the hook now services the earliest due
  non-discarded Initial, Handshake, or Application packet number space, advances
  connection-level PTO backoff, and queues peer probes for other in-flight
  spaces. Later updates make Application PTO reuse queued or in-flight STREAM
  data before falling back to PING.
- 2026-05-23: Made `checkPtoTimeouts()` prefer already queued ack-eliciting
  data before adding a PING probe. A due PTO still advances connection-level
  backoff, but queued Application STREAM data, per-space CRYPTO, or other
  pending ack-eliciting frames can serve as the probe packet. Tests cover queued
  STREAM probe selection without adding a PING; later updates also cover cloning
  ACK-lost and PTO-probed 1-RTT STREAM data, protected CRYPTO data, protected
  0-RTT STREAM data, protected 0-RTT RESET_STREAM/STOP_SENDING control data,
  and ACK-lost frame-payload CRYPTO data.
- 2026-05-25: Adjusted packet-number-space PTO calculation so Initial and
  Handshake spaces omit `max_ack_delay` while Application PTO keeps the existing
  peer-delay term. `recovery.Recovery.ptoMsWithoutMaxAckDelay()` exposes the
  timer basis, `ptoDeadlineMillis(.initial/.handshake)` now uses it, and
  `examples/pto_recovery.zig` prints the 310ms/320ms controlled-clock
  deadlines for 100ms initial RTT packets sent at 10ms/20ms.
- 2026-05-22: Added `examples/pto_recovery.zig` and
  `zig build run-pto-recovery`. The example demonstrates pre-confirmation
  Application PTO gating, deadline gating, PTO-triggered PING queuing,
  Application PING emission through `pollTx()`, queued STREAM data and
  in-flight STREAM data serving as PTO probes, and Initial/Handshake PING
  emission through `pollTxInSpace()`.
- 2026-05-22: Added modeled handshake confirmation via client-side
  HANDSHAKE_DONE and `confirmHandshake()`. RTT updates now ignore Initial and
  Handshake ACK Delay, share valid RTT samples across packet number spaces,
  decode ACK Delay using the peer `ack_delay_exponent`, and cap decoded ACK
  Delay by peer `max_ack_delay` after handshake confirmation. Unit tests cover
  direct ACK-delay calculation, RTT effect, shared-RTT rollback, and
  invalid-payload rollback. `examples/loss_recovery.zig` demonstrates the
  post-confirmation cap and `examples/pto_recovery.zig` demonstrates
  cross-space RTT sharing.
- 2026-05-22: Added `discardPacketNumberSpace()` for modeled Initial and
  Handshake packet number space discard. The hook clears pending ACK,
  largest-acknowledged state, sent-packet tracking, queued/received CRYPTO
  state, bytes in flight, loss deadline, and PTO backoff for the discarded
  space, rejects later use of that frame-payload space, and keeps Application
  state intact. `run-packet-spaces` demonstrates the cleanup. Later bullets
  extend this hook to installed-key cleanup and RFC 9001 Handshake-boundary
  Initial discard; remaining TLS backend-driven key lifecycle scheduling
  remains pending.
- 2026-05-22: Added RFC 9000 frame-type validation to
  `processDatagramInSpace()` and `processDatagramForPacketType()`. Initial and
  Handshake frame-payload packet types now accept only frame types that are valid
  for those packet types in RFC 9000 Table 3. The 0-RTT packet type shares
  Application packet number space accounting but rejects ACK, CRYPTO,
  HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, and RETIRE_CONNECTION_ID frames.
  The RETIRE_CONNECTION_ID rejection follows RFC 9000 Section 12.5's 0-RTT
  protocol-violation allowance even though Table 3 lists the frame for 0/1-RTT
  packet types. 0-RTT still accepts application frames such as RESET_STREAM and
  STOP_SENDING. Invalid multi-frame payloads roll back earlier state such as a
  preceding PING-generated pending ACK or STREAM receive state. `run-packet-spaces`
  demonstrates the shared Application packet number space and 0-RTT filtering.
- 2026-05-29: Added an opt-in close path for those same packet-type frame
  rules. `processDatagramForPacketTypeOrClose()` pre-classifies the frame
  payload before normal receive processing and queues transport CONNECTION_CLOSE
  for frame encoding or packet-type violations; the older receive API still only
  rejects and rolls back invalid payloads.
- 2026-05-23: Added a regression test proving the 0-RTT
  RETIRE_CONNECTION_ID rejection happens before semantic local-CID retirement.
  The test first sends a valid local NEW_CONNECTION_ID, then feeds a 0-RTT
  RETIRE_CONNECTION_ID for that sequence number and verifies the packet is
  rejected without retiring the CID, queuing an ACK, or advancing the
  Application receive packet number.
- 2026-05-22: Added per-packet-number-space CRYPTO send/receive streams through
  `sendCryptoInSpace()`, `recvCryptoInSpace()`, and `pollTxInSpace()`. Initial,
  Handshake, and Application CRYPTO offsets, queues, receive buffers, ACKs, and
  sent-packet tracking are now independently testable. `examples/crypto_stream.zig`
  and `zig build run-crypto-stream` demonstrate the modeled TLS bridge flow;
  the Initial flight now passes through the protected Initial transmit and
  receive bridge. A real TLS backend, real TLS-backed early-data secret ownership,
  complete endpoint datagram routing, and later encryption-level key lifecycle
  remain pending.
- 2026-05-23: Added out-of-order CRYPTO receive buffering per packet number
  space. CRYPTO frames beyond the contiguous receive offset are held pending
  until the gap is filled, identical retransmissions against contiguous or
  pending bytes are ignored, and conflicting overlaps still fail as invalid
  payloads with rollback. Tests cover out-of-order delivery, duplicate
  contiguous and pending data, conflict rejection, and pending-state rollback;
  `examples/crypto_stream.zig` now demonstrates out-of-order Handshake CRYPTO
  reassembly before the protected-packet flow.
- 2026-05-23: Added a pluggable `CryptoBackend` bridge and
  `driveCryptoBackendInSpace()`. The connection can hand local
  transport-parameter extension bytes to a caller-supplied backend, apply peer
  transport-parameter bytes returned by that backend, deliver contiguous
  per-packet-number-space CRYPTO bytes, queue backend-produced bytes through
  `sendCryptoInSpace()`, report `CryptoBackendProgress`, and mark the modeled
  handshake confirmed when the backend reports completion. Tests use a mock
  backend to cover local/peer transport-parameter byte handoff, invalid peer
  transport-parameter rejection before outbound output, close-propagating
  invalid peer transport-parameter handling before outbound output,
  out-of-order Handshake CRYPTO delivery, chunked backend output queuing,
  handshake confirmation, and zero-length scratch-buffer rejection before
  consumption. `examples/crypto_stream.zig` now prints the mock backend bridge
  flow and backend transport-parameter auto-close evidence.
- 2026-05-23: Added mock 1-RTT traffic-secret handoff through `CryptoBackend`
  and connection-installed short-packet key-phase state. `OneRttTrafficSecrets`
  carries local and peer write secrets, `driveCryptoBackendInSpace()` can
  install derived AES-128-GCM packet-protection keys, and
  `pollProtectedShortDatagramWithInstalledKeys()` /
  `processProtectedShortDatagramWithInstalledKeys()` send and receive protected
  1-RTT short packets without caller-supplied keys. Tests cover backend secret
  installation, installed-key PING/ACK exchange, handshake-confirmed and
  ACK-gated local key-update initiation, peer key-phase advancement only after
  successful authentication and frame processing, and failed-packet
  preservation. `examples/crypto_stream.zig` now
  prints installed-key short-packet exchange state. Real TLS 1.3 transcript
  processing, real TLS-backed early-data secret ownership, transport-parameter transcript
  ownership, key discard, and socket-backed local 1-RTT establishment remain
  pending.
- 2026-05-23: Added mock Handshake traffic-secret handoff through
  `CryptoBackend` and installed-key Handshake long-packet helpers.
  `HandshakeTrafficSecrets` carries local and peer write secrets,
  `driveCryptoBackendInSpace()` installs derived AES-128-GCM Handshake keys,
  and `pollProtectedHandshakeDatagramWithInstalledKeys()` /
  `processProtectedHandshakeDatagramWithInstalledKeys()` send and receive
  protected Handshake CRYPTO/ACK/PING packets without caller-supplied keys.
  Tests cover backend secret installation, tampered-packet preservation,
  Handshake CRYPTO delivery, and protected ACK cleanup; `examples/crypto_stream.zig`
  prints the installed-key Handshake exchange. Real TLS 1.3 transcript
  processing, real TLS-backed early-data secret ownership, automatic
  TLS-triggered key discard scheduling, and socket-backed local 1-RTT
  establishment remain pending.
- 2026-05-23: Added backend-confirmed no-output Handshake discard. When
  `driveCryptoBackendInSpace(.handshake, ...)` reports handshake confirmation
  and does not queue outbound Handshake CRYPTO in that call, it now discards
  Handshake recovery/CRYPTO state and installed Handshake keys. If the backend
  still queued outbound Handshake CRYPTO, the space is preserved so the flight
  can be sent first. Tests cover both branches, and `examples/crypto_stream.zig`
  prints `backend_confirmed_no_output ... discarded=true ... keys_present=false`.
  Real TLS transcript ownership and complete endpoint-driven scheduling remain
  pending.
- 2026-05-23: Added mock 0-RTT traffic-secret handoff through `CryptoBackend`
  and installed-key 0-RTT long-packet helpers. `ZeroRttTrafficSecrets` carries
  optional local and peer early-data write secrets, `driveCryptoBackendInSpace()`
  installs derived AES-128-GCM 0-RTT keys, and
  `pollProtectedZeroRttDatagramWithInstalledKeys()` /
  `processProtectedZeroRttDatagramWithInstalledKeys()` send and receive
  protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING packets without
  caller-supplied keys. Tests cover backend secret installation,
  tampered-packet preservation, STREAM delivery, and protected ACK cleanup;
  `examples/crypto_stream.zig` prints the installed-key 0-RTT exchange. Real
  TLS-backed early-data secret ownership, TLS 0-RTT acceptance/replay policy,
  remaining TLS-triggered key lifecycle scheduling, and socket-backed local
  1-RTT establishment remain pending.
- 2026-05-23: Added explicit installed-key 0-RTT accept/reject gates. Installing
  a peer early-data key now leaves it unaccepted; `acceptZeroRtt()` enables
  `processProtectedZeroRttDatagramWithInstalledKeys()`, while `rejectZeroRtt()`
  discards the installed peer key before use. Discarding 0-RTT keys also clears
  the accepted flag. Tests cover rejection before accept, accept-driven receive,
  reject-driven key discard, and discard cleanup. `examples/crypto_stream.zig`
  now explicitly accepts server 0-RTT before the installed-key early-data
  exchange. Full TLS-backed early-data ownership and replay policy remain
  pending.
- 2026-05-23: Added explicit installed-key discard cleanup. Discarding the
  Handshake packet number space now clears connection-installed Handshake
  packet-protection keys in addition to recovery, ACK, and CRYPTO state, and
  `discardZeroRttProtectionKeys()` clears installed early-data keys without
  discarding the shared Application packet number space. Tests cover both
  cleanup paths and verify installed-key helpers reject later use. Remaining
  TLS-triggered Handshake discard scheduling remains pending.
- 2026-05-23: Added modeled 0-RTT key discard at 1-RTT boundaries. Clients now
  clear installed 0-RTT keys when 1-RTT keys are installed; servers preserve
  0-RTT receive keys through 1-RTT key installation and clear them only after a
  protected 1-RTT short packet authenticates and its Application-frame payload
  is accepted. Tests cover client cleanup, server failure preservation, and
  server success cleanup; `examples/crypto_stream.zig` prints
  `client_zero_keys=false` after client 1-RTT install and `server_zero_keys=false`
  after server 1-RTT receive. Full TLS 0-RTT replay policy and
  socket-backed local 1-RTT establishment remain pending.
- 2026-05-23: Connected server-side `sendHandshakeDone()` confirmation to
  Handshake packet-number-space discard. Server HANDSHAKE_DONE queuing now
  clears Handshake recovery/CRYPTO state and installed Handshake keys while
  keeping the 1-RTT HANDSHAKE_DONE frame pending for transmit; reinstalling
  Handshake keys after discard is rejected. Unit tests cover the lifecycle and
  `run-address-validation` prints `server_handshake_discarded=true`. TLS
  backend-driven automatic scheduling remains pending.
- 2026-05-23: Connected client-side HANDSHAKE_DONE confirmation to Handshake
  packet-number-space discard. A valid HANDSHAKE_DONE payload now clears
  Handshake recovery/CRYPTO state and installed Handshake keys only after the
  full payload is accepted; invalid multi-frame payloads roll back confirmation
  and preserve the Handshake space and keys. Protected HANDSHAKE_DONE tests
  cover the same behavior. TLS backend-driven automatic scheduling remains
  pending.
- 2026-05-23: Connected RFC 9001 Initial key discard boundaries to existing
  Handshake packet send/receive paths. Client-side successful Handshake packet
  sends and server-side successful Handshake packet receives now clear Initial
  ACK/recovery/CRYPTO state only after the send/receive commit succeeds;
  blocked sends, small output buffers, invalid payloads, and packet
  authentication failures preserve Initial state. Tests cover frame-payload and
  protected Handshake paths, and `examples/pto_recovery.zig` now demonstrates
  independent Initial/Handshake PTO probes from the server side where sending a
  Handshake packet does not discard Initial state. Remaining TLS backend-driven
  key lifecycle scheduling remains pending.

## Public Interface Plan

The transport implementation should keep the current experimental payload API
usable for focused tests while adding real protected-packet APIs.

Required public or near-public model additions:

- `TransportParameters`
- `TransportError`
- `ConnectionId`
- `ConnectionState`
- `HandshakeState`
- `PacketNumberSpace`
- `EcnCodepoint`
- `EcnValidationState`
- `EndpointRouter`
- `StreamState`
- `CryptoBackend` or `TlsBackend`

TLS must remain behind an interface. The connection state machine must not
hard-code one TLS library or backend.

## Examples Plan

Examples should be added only when the demonstrated capability exists and can be
run from `build.zig`.

| Example | Purpose | Status |
| --- | --- | --- |
| `echo_client` / `echo_server` | Current in-memory frame-payload echo baseline. | Present |
| `codec_roundtrip` | Varint, packet header, RFC 9369 QUIC v2 long-header type-bit mapping, short-header spin-bit preservation, long/short-packet envelope, header packet number truncation/reconstruction, packet number encoding, RFC 8999 Version Negotiation packet codec plus reserved-version skip, client-side VN selection, explicit RFC 9368 compatible-version selection, follow-up config propagation, RFC 9368 downgrade-check state and `VERSION_NEGOTIATION_ERROR` close-code evidence, frame, transport parameter including RFC 9368 `version_information`, connection parameter exposure including TLS extension bytes and server preferred_address, and transport error codec usage including `VERSION_NEGOTIATION_ERROR`, transport-parameter `TRANSPORT_PARAMETER_ERROR`, frame decode `FRAME_ENCODING_ERROR`, and packet-type `PROTOCOL_VIOLATION` classification. | Present |
| `transport_parameters` | Dedicated transport-parameter usage: local TLS extension byte export, reserved-parameter greasing/ignore, peer byte parse/apply, server-only parameter role filtering, compatible-version selection apply with peer Version Information snapshot, transport-parameter auto-close, preferred-address/reset-token storage, effective idle timeout, peer max_udp_payload_size recovery max_datagram_size/initial-cwnd resync, and peer stream limit enforcement. | Present |
| `crypto_stream` | Current out-of-order Handshake CRYPTO reassembly, ACK-driven frame-payload Handshake CRYPTO loss requeue/retransmission, mock `CryptoBackend` bridge delivery/output queuing/local-peer-TP handoff/compatible peer Version Information handoff progress/peer-TP protected auto-close/Handshake, 0-RTT, and 1-RTT secret handoff/confirmation, backend-confirmed no-output and post-final-outbound-CRYPTO Handshake discard, explicit handshake-state observability, protected Initial and Handshake CRYPTO transmit/receive bridge with valid first-client-Initial DCID and 1200-byte Initial datagram flows, installed-key Handshake and explicitly accepted 0-RTT long-packet exchanges, no-Retry Original DCID export/validation, local Initial SCID export through `localTransportParameters()`, coalesced server Initial+Handshake transmit/receive, peer Initial SCID capture with `initial_source_connection_id` validation, protected client Initial ACK-only plus Handshake PING/ACK probe, modeled handshake confirmation, caller-keyed protected 1-RTT PING/ACK, CRYPTO/ACK, STREAM/ACK, RESET_STREAM/ACK, STOP_SENDING/RESET_STREAM exchanges, ACK-gated installed-key 1-RTT key-update PING, caller-owned key-phase-state key-update PING, and configurable short-header spin-bit state. | Present |
| `tls_backend_adapter` | Runnable C-ABI `TlsBackend` adapter contract check: local/peer transport-parameter byte handoff, inbound/outbound CRYPTO byte delivery, Handshake traffic-secret installation, and handshake confirmation through the existing `CryptoBackend` drive path before binding a concrete C TLS library. | Present |
| `tls_c_abi_adapter` | Runnable C-object-backed `TlsBackend` check: a C-compiled callback object drives the same transport-parameter, CRYPTO byte, Handshake-secret, and confirmation path through the Zig adapter before replacing the demo object with a mature C TLS library binding. | Present |
| `tls_openssl_probe` | Runnable OpenSSL QUIC TLS API/link probe: uses `pkg-config` OpenSSL, creates OpenSSL's full QUIC client method object, sets QUIC TLS callbacks and local transport parameters on the callback-mode TLS object, and prints the dispatch IDs needed for crypto send, secret yield, and peer transport-parameter callbacks. | Present |
| `tls_openssl_pair_transcript` | Runnable OpenSSL client/server callback-mode transcript check: a fixed example PSK avoids certificate fixture noise, CRYPTO bytes are routed by OpenSSL protection level, both endpoints complete TLS 1.3 without alerts, peer transport-parameter plus Handshake/1-RTT secret callbacks fire on both endpoints, role-specific quicz-encoded local transport-parameter bytes are configured into OpenSSL and then copied and parsed from peer transport-parameter callbacks, keylog callback count/byte evidence is recorded without printing key material, generated CRYPTO bytes are delivered into quicz Initial/Handshake/Application CRYPTO queues, the client Initial CRYPTO bytes are packetized with quicz protected Initial long-packet helpers and delivered to the server connection, both Initial flights are delivered over loopback UDP through the quicz endpoint lifecycle, a manual OpenSSL context routes live Initial and Handshake TLS CRYPTO bytes in both directions through the same socket/lifecycle boundary, OpenSSL-produced Handshake secrets drive installed-key protected Handshake CRYPTO delivery in both directions including loopback UDP delivery through the same lifecycle, the same manual OpenSSL context drives a 1-RTT STREAM request/echo/final-ACK exchange plus Handshake key discard and protected close/route cleanup through that socket/lifecycle path, and OpenSSL-produced 1-RTT secrets drive an installed-key protected STREAM request/response over short packets plus a loopback UDP STREAM echo through the same lifecycle. | Present |
| `tls_openssl_backend_adapter` | Runnable OpenSSL-backed `TlsBackend` wrapper check: the endpoint lifecycle-owned backend drive sets quicz local transport parameters on an OpenSSL TLS object, drives `SSL_do_handshake()` to emit the first TLS CRYPTO flight, routes that adapter-generated Initial CRYPTO flight through a protected Initial datagram over loopback UDP, consumes quicz-encoded pair-transcript server transport parameters through the wrapper, delivers real pair-transcript Handshake/1-RTT secrets through OpenSSL callback boundaries, routes real pair-transcript Handshake CRYPTO through a protected Handshake datagram over loopback UDP before feeding it back through the adapter, verifies OpenSSL recv/release callback consumption of inbound Handshake CRYPTO before backend confirmation, then drives loopback UDP 1-RTT STREAM echo with adapter-installed client keys plus matching peer transcript secrets, services Application PTO and routes the protected probe through the same lifecycle owner, reports `backend_confirmed=true` through the OpenSSL-backed `handshake_confirmed` callback, prints matching `peer_tp_bytes` and `transcript_tp`, transcript keylog evidence, and the current wrapper keylog boundary, discards the client Handshake packet-number space and keys through a lifecycle-owned backend-confirmed no-output Handshake drive that refreshes aggregate recovery timers, uses the server connection probe to pull real pair-transcript 1-RTT secrets through the backend, record OpenSSL secret callbacks, confirm the server connection, prove peer stream-count limit enforcement from the applied transport parameters, and discard server Handshake packet-number-space keys, uses the paired loopback server backend to consume client Handshake CRYPTO over loopback UDP, pull peer transport parameters plus Handshake/1-RTT secrets, confirm, and clear Handshake keys, and completes protected close delivery plus route cleanup through one socket/lifecycle loop owner. | Present |
| `initial_keys` | RFC 9001 QUIC v1 and RFC 9369 QUIC v2 Initial secret/key/IV/header-protection key derivation, RFC 9001 `quic ku` key-update derivation, protected Initial long-packet seal/open, configured v2 connection Initial packetization, and AES header-protection masking from a client Initial DCID. | Present |
| `endpoint_routing` | Current in-memory endpoint DCID/IPv4 UDP tuple routing, long-header DCID peeking, unsupported-version RFC 8999 Version Negotiation response generation, client Initial Source CID route registration, supported-version unknown-DCID Initial accept classification, accepted Initial Original DCID/server Initial SCID route registration, short-header registered-CID matching, zero-length CID tuple routing, Retry Source CID route switching, caller-validated preferred-address migration commit, sequence/retire-prior-to/connection-handle route retirement, stateless reset token reuse rejection, caller-validated path update, active-migration-disabled rejection, route retirement, stateless reset token lookup for inactive CIDs, reset datagram construction with caller-supplied unpredictable bytes, and route/version-negotiation/reset/drop/accept receive action classification. | Present |
| `endpoint_recovery_timers` | Endpoint-owned recovery timer scheduling across caller-owned connection handles: endpoint lifecycle route ownership, earliest aggregate timer selection, before-deadline no-op refresh, PTO service/re-arm, ACK-driven disarm, loss-time service, final timer disarm, connection-handle route retirement, routed protected long-header receive timer refresh with processed-count preservation, client Initial ACK anti-deadlock Handshake PTO preservation, caller-keyed and installed-key Handshake/0-RTT protected long-header recovery timer service plus PTO probe polling, protected long-header send timer refresh, routed caller-keyed Handshake CRYPTO-space and 0-RTT long-packet receive timer refresh, caller-keyed Initial/Handshake CRYPTO-space and 0-RTT long-packet send timer refresh, caller-keyed protected 1-RTT short-packet receive timer refresh, caller-keyed protected 1-RTT short-packet send timer refresh, installed-key protected 1-RTT recovery timer service plus PTO probe polling, routed explicit key-phase/key-update short-packet receive timer refresh, caller-owned key-phase-state short-packet send timer refresh, routed installed-key Handshake/0-RTT long-packet receive timer refresh, installed-key Handshake/0-RTT long-packet send timer refresh, and installed-key protected 1-RTT short-packet send/receive timer refresh. | Present |
| `udp_endpoint_loopback` | Socket-backed loopback UDP exercise for endpoint routing: lifecycle-owned unsupported-version Initial to Version Negotiation response delivery, client-side VN selection, protected follow-up Initial emission with follow-up Original DCID and recovery-timer evidence, lifecycle-owned accepted protected Initial processing, protected server Initial response emission and routed client-side processing, server transport-parameter byte validation plus malformed-byte `TRANSPORT_PARAMETER_ERROR` close classification on the follow-up client, server-side follow-up Initial CRYPTO receive, client Initial Source CID response routing, accepted server Initial Source CID registration, and short-header registered-CID routing. | Present |
| `udp_zero_cid_loopback` | Socket-backed loopback UDP zero-length CID exercise: lifecycle-owned short and long datagram routing by UDP tuple identity, unregistered tuple rejection before update, path-specific zero-CID retirement, and route path update to a new tuple. | Present |
| `udp_preferred_address_loopback` | Socket-backed loopback UDP preferred-address exercise: server preferred_address transport-parameter byte handoff, lifecycle-owned caller-validated preferred route commit, old-route retirement, preferred CID routing on the preferred server address, active-migration-disabled rejection on a stray path, and retained reset-token lookup after retirement. | Present |
| `udp_replacement_cid_loopback` | Socket-backed loopback UDP replacement CID exercise: lifecycle-owned NEW_CONNECTION_ID-style replacement route registration, retire_prior_to route retirement, inactive old-CID reset-token lookup, active replacement token suppression, invalid retire_prior_to rejection, and active-migration-disabled stray-path rejection. | Present |
| `udp_connection_ids_loopback` | Socket-backed loopback UDP connection ID exercise: lifecycle-routed protected NEW_CONNECTION_ID delivery, lifecycle-owned issue/register endpoint route update, inactive old-CID reset-token lookup, active replacement CID route probing, lifecycle-routed protected RETIRE_CONNECTION_ID through the active replacement CID, lifecycle-routed ACK cleanup, and server-side local CID retirement. | Present |
| `udp_protected_loopback` | Socket-backed loopback UDP lifecycle protected packet exercise: lifecycle-owned caller-keyed protected client Initial route registration, accepted protected Initial authentication before server route registration, anti-amplification budget accounting, protected server Initial response emission and routed client-side processing, routed caller-keyed 1-RTT PING processing, and routed caller-keyed 1-RTT ACK processing. | Present |
| `udp_handshake_keys_loopback` | Socket-backed loopback UDP Handshake-key exercise: lifecycle-routed installed-key Handshake CRYPTO delivery in both directions, serviced installed-key Handshake PTO probe routing with duplicate CRYPTO discard evidence, and routed Handshake ACK cleanup. | Present |
| `udp_crypto_stream_loopback` | Socket-backed loopback UDP CryptoBackend CRYPTO stream exercise: mock `CryptoBackend` Handshake traffic-secret installation, local/peer transport-parameter byte handoff, lifecycle-routed protected Handshake CRYPTO flights, backend receive/output, and routed ACK cleanup. | Present |
| `udp_zero_rtt_loopback` | Socket-backed loopback UDP 0-RTT exercise: lifecycle-routed installed-key 0-RTT STREAM delivery, explicit accept-before-process enforcement, rejection-driven peer key discard, serviced installed-key 0-RTT PTO probe routing with duplicate STREAM discard evidence, accepted early ACK evidence, routed 1-RTT ACK cleanup, and client/server 0-RTT key discard evidence across the 1-RTT boundary. | Present |
| `udp_one_rtt_loopback` | Socket-backed loopback UDP 1-RTT exercise: lifecycle-routed installed-key 1-RTT STREAM delivery after modeled handshake confirmation, serviced installed-key 1-RTT PTO probe routing with duplicate STREAM discard evidence, and routed Application-space ACK cleanup. | Present |
| `udp_echo_loopback` | Socket-backed loopback UDP installed-key 1-RTT echo exercise: lifecycle-routed client STREAM delivery, server bidirectional STREAM echo, request/echo payload equality, serviced server-side 1-RTT PTO probe routing with duplicate STREAM discard evidence, final ACK cleanup, client final-ACK timer-state evidence, and server bytes-in-flight/timer cleanup evidence. | Present |
| `udp_crypto_backend_loopback` | Socket-backed loopback UDP CryptoBackend exercise: mock `CryptoBackend` 1-RTT traffic-secret handoff, modeled handshake confirmation, lifecycle-routed installed-key STREAM echo, serviced client/server installed-key 1-RTT PTO probe routing with duplicate STREAM discard evidence, client/server send-side recovery-timer deadline evidence, final ACK cleanup, client final-ACK timer-state evidence, and server bytes-in-flight/timer cleanup evidence. | Present |
| `udp_handshake_done_loopback` | Socket-backed loopback UDP HANDSHAKE_DONE exercise: lifecycle-routed installed-key HANDSHAKE_DONE confirmation, server/client Handshake key discard evidence, public handshake/connection-state evidence, and routed ACK pending/cleanup evidence. | Present |
| `udp_flow_control_loopback` | Socket-backed loopback UDP flow-control exercise: lifecycle-routed protected STREAM delivery to the receive limit, lifecycle-routed protected STREAM_DATA_BLOCKED routing, lifecycle-routed receive-side MAX_DATA/MAX_STREAM_DATA credit refresh delivery, lifecycle-routed resumed STREAM data with FIN final-size evidence, caller-keyed resumed STREAM PTO probe routing with duplicate discard evidence, and lifecycle-routed final ACK cleanup. | Present |
| `udp_spin_bit_loopback` | Socket-backed loopback UDP spin-bit exercise: enabled single-path spin-bit signaling, lifecycle-routed protected short PING/ACK receive paths, first false spin round, migrated second true-spin PING with `path_changed`, lifecycle-owned route update/reset, reset server ACK/client outgoing spin evidence, and final ACK cleanup. | Present |
| `udp_ecn_validation_loopback` | Socket-backed loopback UDP ECN validation exercise: lifecycle-routed modeled ECT(0) protected short PING routing, lifecycle-routed protected ACK_ECN success, lifecycle-routed ACK_ECN CE-driven NewReno recovery response, lifecycle-owned endpoint ECN state update for the active UDP tuple, and migrated-path ECN isolation without claiming real IP-header ECN marking. | Present |
| `udp_loss_recovery_loopback` | Socket-backed loopback UDP lifecycle loss-recovery exercise: lifecycle-routed protected short PING/ACK receive paths, protected ACK-driven packet-threshold loss, lifecycle timer-driven time-threshold cleanup, and final timer disarm. | Present |
| `udp_congestion_recovery_loopback` | Socket-backed loopback UDP lifecycle congestion-recovery exercise: lifecycle-routed protected short PING/ACK receive paths, explicit NewReno recovery-period repeated-loss suppression evidence, explicit persistent congestion reduction to the minimum congestion window, and modeled ACK_ECN CE-driven one-shot protected STREAM probe routing. | Present |
| `udp_pto_recovery_loopback` | Socket-backed loopback UDP lifecycle PTO recovery exercise: lifecycle-routed protected long/short and installed-key 0-RTT receive paths, lifecycle timer service plus protected long Handshake PTO probe polling, installed-key 0-RTT RESET_STREAM PTO probe polling, and protected short probe polling for ACK-loss PTO, protected long-header PING/ACK delivery, protected 0-RTT retransmission and 1-RTT ACK cleanup, protected short PING fallback probe delivery, queued STREAM data as a protected PTO probe, in-flight STREAM/CRYPTO data as protected PTO probes, duplicate receive/CRYPTO range discard, ACK cleanup, and final timer disarm. | Present |
| `udp_stream_retransmission_loopback` | Socket-backed loopback UDP lifecycle STREAM retransmission exercise: lifecycle-routed sparse protected ACK receive marks a 1-RTT STREAM packet lost, the sender emits a new protected STREAM retransmission packet, the receiver discards the duplicate stream range idempotently, and a final ACK clears bytes in flight. | Present |
| `udp_key_update_loopback` | Socket-backed loopback UDP key-update exercise: lifecycle-owned route selection and protected receive processing with installed 1-RTT traffic secrets, local key update initiation, observable key-update generation count, observable ACK-gate threshold, retained-generation old-key discard evidence, next key-phase PING routing, authenticated peer key-phase advancement, ACK delivery, ACK-gate clearing, second-update packet delivery, serviced second-update PTO probe routing with current key-phase evidence, server generation-2 advancement, stale old-generation packet rejection with state preservation, and second ACK-gate clearing. | Present |
| `udp_path_validation_loopback` | Socket-backed loopback UDP path-validation exercise: lifecycle-routed protected PATH_CHALLENGE delivery to a new peer port, pre-validation protected PING routing with `path_changed` but no route update, lifecycle-routed PATH_RESPONSE routing with `path_changed`, close-propagating validation-driven `EndpointConnectionLifecycle` route path update after PATH_RESPONSE consumes an outstanding challenge, and confirmed routing on the new path. | Present |
| `udp_retry_loopback` | Socket-backed loopback UDP lifecycle Retry/address-validation exercise: lifecycle-owned server Retry delivery, Retry Source CID route switching, lifecycle-owned address-bound token validation and one-time consumption with replay rejection, lifecycle-owned follow-up protected Initial acceptance/processing, and Retry CID transport-parameter validation through TLS extension bytes. | Present |
| `udp_close_lifecycle_loopback` | Socket-backed loopback UDP close lifecycle exercise: lifecycle-owned client/server route registration, lifecycle-routed protected CONNECTION_CLOSE delivery, lifecycle-routed protected receive auto-close for authenticated frame errors, close/drain deadline evidence, timeout-driven endpoint route cleanup after close/drain expiry, connection-handle route retirement with remaining route/reset-token counts, retained inactive-CID stateless reset token lookup, reset emission, and client token match. | Present |
| `udp_stateless_reset_loopback` | Socket-backed loopback UDP stateless reset exercise: active CID route classification with reset-token suppression, unknown-CID drop classification, lifecycle-owned retired-CID route retirement, trigger datagram classification, server reset datagram send, and client token match. | Present |
| `udp_echo_client` / `udp_echo_server` | Real QUIC-over-UDP/TLS stream echo. | Planned |
| `uni_stream` | Current in-memory unidirectional stream send/receive, direction validation, duplicate STREAM retransmission discard, and FIN completion observability. | Present |
| `stream_reset` | Current local RESET_STREAM emission, public stream-state snapshot evidence including reset-read and reset-acked observation, final-size observability, unsent STREAM drop behavior, ignored MAX_STREAM_DATA after reset, and late STREAM ignore after reset. | Present |
| `stop_sending` | Current local STOP_SENDING emission, public stream-state snapshot evidence, peer RESET_STREAM response, Data Recvd suppression, pre-STREAM STOP_SENDING on peer-initiated bidirectional streams, implicit lower-numbered receive stream creation, and ACK-loss STREAM suppression after reset. | Present |
| `flow_control` | Connection, stream, stream-count, receive-side MAX, MAX_STREAMS overflow rejection, configurable target receive windows, completed-stream MAX_STREAMS, peer-BLOCKED MAX retransmission/growth, pre-STREAM MAX_STREAM_DATA on peer-initiated bidirectional streams with implicit lower-numbered receive stream creation, final-size MAX_STREAM_DATA suppression, stale STREAM_DATA_BLOCKED suppression, and caller-keyed protected short MAX/BLOCKED exchange behavior. | Present |
| `graceful_close` | Current in-memory, caller-keyed protected long Initial/Handshake CONNECTION_CLOSE, caller-keyed protected short CONNECTION_CLOSE/APPLICATION_CLOSE send/receive, invalid ACK/ACK_ECN-range close, invalid STREAMS_BLOCKED limit close, semantic frame-error auto-close including flow-control, ACK/ACK_ECN frames that acknowledge unsent packet numbers, conflicting STREAM data, invalid stream-control frames, unmatched PATH_RESPONSE, NEW_CONNECTION_ID limit/reuse, RETIRE_CONNECTION_ID unknown-CID, and role-specific NEW_TOKEN/HANDSHAKE_DONE cases, protected receive auto-close, lifecycle-routed protected receive auto-close, protected long/0-RTT close-state discard, peer close diagnostics, default/space/packet-type invalid frame-payload auto-close, retransmission, and closing/draining state behavior. | Present |
| `idle_timeout` | Current max_idle_timeout transport parameter application, activity deadline refresh, active-to-closed expiry, and endpoint route/timer cleanup. | Present |
| `packet_spaces` | Current frame-payload Initial/Handshake/Application ACK/recovery isolation, RFC 9001 Initial discard, Initial/Handshake discard cleanup including ECN state, 0-RTT packet-type filtering, and caller-keyed protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING delivery plus ACK-loss retransmission. | Present |
| `path_validation` | Current frame-payload PATH_CHALLENGE timeout retry, success, retry exhaustion, duplicate pending PATH_RESPONSE suppression, caller-keyed protected 1-RTT PATH_CHALLENGE/PATH_RESPONSE exchange with 1200-byte datagram expansion and anti-amplification fallback, and `EndpointConnectionLifecycle` route path update after protected PATH_RESPONSE validation. | Present |
| `connection_ids` | Current local NEW_CONNECTION_ID issuing with stateless-reset-token uniqueness checks, peer RETIRE_CONNECTION_ID handling, lifecycle-owned issue/register endpoint route bridging with retire_prior_to route retirement, and caller-keyed protected 1-RTT NEW_CONNECTION_ID/RETIRE_CONNECTION_ID exchange. | Present |
| `stateless_reset` | Current constant-time stateless reset token match, false-positive rejection, and lifecycle-owned endpoint inactive-CID reset action construction. | Present |
| `ecn_validation` | Current frame-payload ECT send modeling, ACK_ECN counter validation, and endpoint path-identity ECN state isolation. | Present |
| `loss_recovery` | Current frame-payload invalid ACK range rejection, largest-acknowledged RTT sampling, cross-space bytes-in-flight congestion admission, packet-threshold loss, time-threshold loss, aggregate loss-time timer service, NewReno underutilized-cwnd suppression, slow-start/congestion-avoidance byte-counted and batched-ACK growth, recovery period, recovery-period ACK accounting without congestion growth, loss/CE-driven new-congestion-event one-packet STREAM recovery probes, minimum-window ssthresh clamp, PTO-backoff-independent persistent congestion, persistent-congestion min-RTT refresh, persistent-congestion recovery-period clearing/re-entry, non-contiguous persistent-congestion suppression, and ACK-delay handling. | Present |
| `pto_recovery` | Current frame-payload Initial/Handshake/Application PTO hooks, including aggregate PTO timer service, Application PTO gating until handshake confirmation, client Initial ACK PTO-backoff reset suppression, client no-in-flight anti-deadlock PTO, anti-amplification-limited server PTO disarm/rearm plus expired-PTO service when new datagrams unblock sending, connection-level RTT sharing and PTO backoff across packet number spaces, Initial/Handshake RTT ACK-delay suppression, Initial/Handshake max_ack_delay suppression, congestion-window bypass for one armed PTO probe, PING fallback probes, cross-space peer probes for other in-flight packet number spaces, queued STREAM data probe selection, in-flight STREAM retransmission probe selection, ACKed RESET_STREAM retransmission suppression, and protected 1-RTT CRYPTO PTO probe selection. | Present |
| `address_validation` | Current modeled server anti-amplification budget, explicit peer-address validation, lifecycle-owned protected HANDSHAKE_DONE/NEW_TOKEN emission/delivery timer evidence, server-side HANDSHAKE_DONE-triggered Handshake discard, endpoint peer-address binding, `AddressValidationPolicy` NEW_TOKEN issue/rotation/originating-version binding/secret-set and replay-filter export/restore/validation/replay rejection, and lifecycle-owned address-validation unblocking. | Present |
| `udp_address_validation_loopback` | Socket-backed loopback UDP address-validation exercise: lifecycle-owned protected HANDSHAKE_DONE/NEW_TOKEN emission/delivery timer evidence, NEW_TOKEN path/version binding with explicit changed-path rejection, secret rotation, replay snapshot restore rejection, and lifecycle-owned server address-validation block/unblock evidence. | Present |
| `retry_token` | Current v1/v2 Retry packet integrity-tag encode/verify/parse, server-side Retry datagram issuance, client-side Retry datagram processing, Retry CID transport-parameter validation/export through TLS extension bytes, endpoint peer-address binding, `AddressValidationPolicy` Retry token issue/path validation, lifecycle-owned one-time Retry token consumption, and address-validation unblocking. | Present |
| `interop_client` | Manual or optional external-server interop check. | Planned |

## Verification Rules

- Every transport behavior change must map to a standard area in this document.
- New codec or state-machine behavior must include normal-path, boundary,
  malformed-input, and rollback tests.
- High-risk logic, including TLS, packet protection, timers, Retry, stateless
  reset, ECN validation, loss recovery, congestion control, and endpoint
  routing, must use deterministic tests with controlled inputs.
- The baseline local verification command set is:

```bash
zig build test --summary all
zig build
zig build run-server
zig build run-client
zig build run-codec
zig build run-transport-parameters
zig build run-flow-control
zig build run-uni-stream
zig build run-stream-reset
zig build run-stop-sending
zig build run-crypto-stream
zig build run-tls-backend-adapter
zig build run-tls-c-abi-adapter
zig build run-tls-openssl-probe
zig build run-tls-openssl-pair-transcript
zig build run-tls-openssl-backend-adapter
zig build run-graceful-close
zig build run-idle-timeout
zig build run-packet-spaces
zig build run-ecn-validation
zig build run-loss-recovery
zig build run-pto-recovery
zig build run-endpoint-recovery-timers
zig build run-path-validation
zig build run-address-validation
zig build run-udp-address-validation-loopback
zig build run-retry-token
zig build run-connection-ids
zig build run-stateless-reset
zig build run-initial-keys
zig build run-endpoint-routing
zig build run-udp-endpoint-loopback
zig build run-udp-zero-cid-loopback
zig build run-udp-preferred-address-loopback
zig build run-udp-replacement-cid-loopback
zig build run-udp-connection-ids-loopback
zig build run-udp-protected-loopback
zig build run-udp-handshake-keys-loopback
zig build run-udp-crypto-stream-loopback
zig build run-udp-zero-rtt-loopback
zig build run-udp-one-rtt-loopback
zig build run-udp-echo-loopback
zig build run-udp-crypto-backend-loopback
zig build run-udp-handshake-done-loopback
zig build run-udp-flow-control-loopback
zig build run-udp-spin-bit-loopback
zig build run-udp-ecn-validation-loopback
zig build run-udp-loss-recovery-loopback
zig build run-udp-congestion-recovery-loopback
zig build run-udp-pto-recovery-loopback
zig build run-udp-key-update-loopback
zig build run-udp-path-validation-loopback
zig build run-udp-retry-loopback
zig build run-udp-close-lifecycle-loopback
zig build run-udp-stateless-reset-loopback
```

- External interop checks are allowed to be optional until the local protected
  UDP client/server path exists, but failures must record peer implementation,
  peer version, and the smallest reproducible trace.

## Milestones

1. Standard matrix and documentation are current.
2. RFC 8999 / 9000 packet, frame, transport parameter, and error-code support is complete.
3. Connection state machine, packet number spaces, and protected datagram APIs exist.
4. RFC 9001 TLS integration and packet protection establish local 1-RTT.
5. RFC 9000 transport behavior covers streams, flow control, connection IDs, Retry/tokens, path validation, and close/reset behavior.
6. RFC 9002 recovery and congestion control pass controlled-clock tests.
7. Layered examples and at least one external interop path are available.
