# QUIC transport implementation tasks

`quicz` aims to implement the IETF QUIC transport protocol in Zig. This task
plan converts that goal into verifiable work items that can be implemented and
tested incrementally.

## Scope

The first implementation scope is the QUIC transport core:

- RFC 8999: Version-Independent Properties of QUIC
- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control

Deferred standards and extensions:

- QUIC v2, RFC 9369
- Compatible Version Negotiation, RFC 9368
- QUIC DATAGRAM, RFC 9221
- HTTP/3 and QPACK
- Multipath and other in-progress QUIC WG drafts

The current codebase is still an experimental frame-payload transport skeleton.
`pollTx` and `processDatagram` move unencrypted QUIC frame payload bytes. The
connection layer now has a narrow Initial CRYPTO protected long-packet
send/receive bridge, but it does not yet fully produce or consume QUIC packets
over UDP.

## Task Matrix

| Area | Current status | Required outcome | Verification |
| --- | --- | --- | --- |
| Standard tracking | Partial | Document each core RFC area as done, partial, missing, or deferred. | Markdown review plus `zig build test`. |
| RFC 8999 / 9000 packet codec | Partial | Complete version-independent packet handling, version negotiation, Retry, long and short headers, packet number handling, and transport error values. | Roundtrip, boundary, truncation, invalid-value, and allocation-failure tests. |
| RFC 9000 frame codec | Frame set present + partial packet-type validation | Cover all RFC 9000 transport frames with strict value validation and stable error mapping. | Per-frame encode/decode tests for valid, truncated, invalid, and unknown inputs. |
| Transport parameters | Partial connection exposure | Add typed transport parameter parsing, serialization, validation, and handshake exposure. | Roundtrip tests, duplicate/invalid parameter tests, connection apply/export tests, and default-value tests. |
| Connection state machine | Partial close-state + idle timeout | Model Initial, Handshake, 0-RTT, 1-RTT, idle timeout, closing, draining, and closed states. | Existing tests cover close/drain transitions, close expiry, idle expiry, and invalid-packet rollback; later protected-packet tests cover key-state transitions. |
| Packet number spaces | Partial frame-payload ACK/recovery + CRYPTO isolation + Initial protected CRYPTO send/receive bridge + frame-type filtering + discard cleanup | Maintain distinct Initial, Handshake, and Application packet number spaces, then route protected packets into the matching space with real TLS key discard rules. | Existing ACK/recovery, CRYPTO isolation, Initial protected send/receive, forbidden-frame, and discard tests prove isolation and cleanup between spaces; later protected coalesced tests prove full routing. |
| Real datagram API | Initial protected CRYPTO send/receive bridge + protected long-packet helper | Add protected QUIC datagram receive/transmit APIs above the existing frame-payload skeleton. | Existing helper tests cover one protected Initial packet; connection tests cover protected Initial CRYPTO emit/decrypt/delivery; later local client/server loopback must exchange protected packets. |
| TLS integration | CRYPTO bridge hooks present, TLS backend missing | Use a pluggable TLS backend interface driven by CRYPTO frames. | Handshake transcript tests and local 1-RTT establishment test. |
| Packet protection | Partial v1 Initial keys + AES-GCM payload/header protection + protected long-packet helpers | Implement Initial, Handshake, 0-RTT, and 1-RTT key derivation, header protection, AEAD protection, key discard, and key update. | RFC-vector or fixed-vector tests for key derivation and packet protection. |
| Streams | Partial receive reassembly + FIN completion + local reset/stop observability | Complete stream state machines, FIN/reset rules, and read/write behavior beyond the current in-memory reassembly skeleton. | Bidirectional, unidirectional, FIN, reset, STOP_SENDING, out-of-order, overlap, rollback, and final-size tests. |
| Flow control | Partial receive MAX and stream-count refresh + BLOCKED observability/retransmission | Complete adaptive MAX/BLOCKED policy reactions. | Blocked/unblocked tests at connection, stream, and stream-count scope. |
| Connection IDs | Partial local/peer lifecycle without DCID routing | Add DCID routing integration and endpoint replacement policy. | Existing tests cover local NEW_CONNECTION_ID issuing, peer RETIRE handling, peer-issued NEW_CONNECTION_ID lifecycle, duplicate, limit, and rollback; later endpoint tests cover routing. |
| Tokens and Retry | Partial codec + Retry Integrity Tag + NEW_TOKEN storage + modeled server anti-amplification send limiting + explicit one-time Retry token validation | Implement cryptographic token generation, expiration, endpoint address binding, and full address validation policy. | Existing tests cover Retry packet codec, RFC 9001 Retry Integrity Tag, NEW_TOKEN storage, modeled 3x anti-amplification limiting, and one-time Retry token consumption; later endpoint tests cover encrypted/address-bound token policy. |
| Path validation | Partial timeout/retry without endpoint identity | Bind validation to endpoint path identity once real UDP routing exists. | Existing tests cover matching, duplicate, mismatched, rollback, timeout retry, and retry exhaustion; later endpoint tests cover path identity. |
| Stateless reset | Partial helper + connection detection | Add endpoint-level unknown-CID stateless reset emission once UDP routing exists. | Existing tests cover reset token match, false-positive rejection, short datagram rejection, and retired-token ignore; later endpoint tests cover unknown-CID emission. |
| ECN validation | Partial frame-payload ACK_ECN validation | Bind ECN validation to real network paths and IP ECN marking once UDP routing exists. | Existing tests cover ECT(0) success, missing ACK_ECN failure, insufficient counters, counter totals exceeding sent ECT packets, reordered ACK handling, and rollback; later endpoint tests cover path identity and IP-header marking. |
| RFC 9002 recovery | Partial ACK delay + packet/time-threshold loss + NewReno recovery period + persistent congestion + packet-space PTO PING hook | Implement full protected-packet PTO/loss timer scheduling and remaining NewReno details. | Existing tests cover ACK, ACK delay exponent scaling, post-confirmation max_ack_delay capping, packet-threshold loss, ACK-driven and timeout-driven time-threshold loss, NewReno recovery-period suppression, persistent congestion, rollback, packet-number-space PTO PING queuing/backoff, and congestion-window arithmetic; later controlled-clock tests cover protected-packet PTO data retransmission. |
| UDP endpoint routing | Missing | Route UDP datagrams by DCID, local/remote address tuple, and connection state. | Endpoint tests for client connect, server accept, migration rejection, and unknown CID. |
| Interop | Missing | Validate a minimal QUIC echo flow against at least one external implementation. | Manual or optional CI script records peer implementation and version. |

## Progress Notes

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
  spin bit set. Runtime spin-bit enablement and update policy remain future
  connection/path-state work.
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
- 2026-05-22: Added `examples/codec_roundtrip.zig` and `zig build run-codec`.
  The example exercises varint, short-packet envelope, coalesced long-packet envelope,
  short-header spin-bit preservation, header packet number
  truncation/reconstruction, packet number encoding, Version Negotiation,
  STREAM frame, transport parameter, connection
  transport-parameter exposure, and transport error helper roundtrips.
- 2026-05-22: Added `QuicConnection.localTransportParameters()` and
  `applyPeerTransportParameters()`. Local parameters expose configured receive
  limits, `disable_active_migration`, and a configured server-only
  `stateless_reset_token`, while peer parameters update send-side
  connection and stream credit, stream-count limits, ACK delay policy, outbound
  datagram sizing, peer active-migration policy observability, and the peer
  `stateless_reset_token` transport parameter for future endpoint reset
  detection. Tests cover local export, peer application, invalid server-only
  peer values, and active connection ID limit validation. TLS transcript
  integration, stateless reset endpoint handling beyond read-only token exposure,
  and UDP migration enforcement
  remain pending.
- 2026-05-22: Added `QuicConnection.sendPathChallenge()` with outbound
  PATH_CHALLENGE queuing, matching PATH_RESPONSE validation, duplicate or
  mismatched response rejection, and rollback tests for invalid multi-frame
  payloads. Timeout/retry policy is still pending.
- 2026-05-22: Added peer-issued connection ID lifecycle tracking in
  `QuicConnection`. NEW_CONNECTION_ID now stores active peer CIDs, rejects
  inconsistent duplicate sequence numbers, enforces the configured active CID
  limit, applies retire_prior_to by queuing RETIRE_CONNECTION_ID, and rolls back
  partial CID state on invalid multi-frame payloads. Local CID issuing and DCID
  routing remain pending.
- 2026-05-22: Added local connection ID issuing in `QuicConnection`.
  `issueConnectionId()` copies local CID bytes, assigns NEW_CONNECTION_ID
  sequence numbers, enforces peer active CID limits, rejects duplicate local CID
  values, and queues unsent IDs for `pollTx()`. Inbound RETIRE_CONNECTION_ID now
  marks previously sent local CIDs retired and rolls back retirement on invalid
  multi-frame payloads. DCID routing and endpoint-level replacement policy
  remain pending.
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
- 2026-05-22: Added receive-side MAX_DATA and MAX_STREAM_DATA refresh after
  `recvOnStream()` consumes bytes. The connection now increases advertised
  connection and per-stream receive credit by the consumed byte count, drops
  obsolete lower queued MAX limits, and `examples/flow_control.zig` demonstrates
  a sender unblocked by refreshed receive credit. Adaptive receive-window
  autotuning remains pending.
- 2026-05-22: Added receive-side MAX_STREAMS_BIDI/UNI refresh for fully
  consumed peer-initiated FIN streams, including zero-length FIN streams observed
  through `recvOnStream()`. The connection releases one receive stream-count
  credit once per completed stream, queues the matching MAX_STREAMS frame, and
  `examples/flow_control.zig` demonstrates a blocked sender opening the next
  bidirectional stream after the refresh.
- 2026-05-22: Added `examples/uni_stream.zig` and
  `zig build run-uni-stream`. The example demonstrates client- and
  server-initiated unidirectional stream delivery in the current frame-payload
  skeleton and verifies that a receive-only peer unidirectional stream rejects
  reverse sends.
- 2026-05-22: Added receive-side out-of-order STREAM range buffering in
  `QuicConnection`. Non-overlapping ranges are accounted for when received and
  exposed to `recvOnStream()` only after gaps are filled. Tests cover FIN before
  the missing prefix, overlap rejection, invalid-payload rollback, and
  RESET_STREAM final-size accounting with pending ranges.
- 2026-05-22: Added `recvStreamFinalSize()` and `recvStreamFinished()` so
  callers can observe STREAM FIN final size and successful receive-side
  completion after all bytes are consumed. RESET_STREAM final size remains
  visible but does not count as FIN completion. Tests cover out-of-order FIN
  completion, reset behavior, and invalid receive-only stream directions.
- 2026-05-22: Added `QuicConnection.resetStream()` and
  `examples/stream_reset.zig` with `zig build run-stream-reset`. The API aborts
  opened local send sides and observed peer bidirectional reply sides, queues a
  single RESET_STREAM with the current send offset as final size, rejects
  receive-only directions and unopened streams, and drops unsent STREAM data
  after the reset is emitted.
- 2026-05-22: Added `QuicConnection.stopSending()` and
  `examples/stop_sending.zig` with `zig build run-stop-sending`. The API queues
  STOP_SENDING for opened local bidirectional receive sides and observed
  peer-initiated receive streams, rejects send-only and unobserved streams,
  deduplicates local stop requests, and exercises the peer RESET_STREAM response.
- 2026-05-22: Added client-side NEW_TOKEN storage in `QuicConnection`.
  Client connections retain opaque token bytes up to `Config.max_stored_new_tokens`
  and expose the newest token via `latestNewToken()`. Tests cover storage,
  capacity, server-side rejection, and invalid-payload rollback. Cryptographic
  token generation and endpoint address-binding policy remain pending.
- 2026-05-22: Added local close emission in `QuicConnection` with
  `closeConnection()` and `closeApplication()`. The methods queue
  CONNECTION_CLOSE variants, `pollTx()` emits the close frame while entering
  local closing state, and tests cover payload encoding, API rejection while
  closing, invalid value rejection, and size validation without mutation.
- 2026-05-22: Added an explicit `ConnectionState` model exposed by
  `connectionState()` and `closeDeadlineMillis()`. Local close enters
  `closing`, peer close enters `draining`, and both expire to `closed` after the
  current simplified 3x PTO timeout. Tests cover local close expiry, peer close
  expiry, and invalid-payload rollback to `active`. Validated-address send
  limits remain pending.
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
  unblocking, and non-reuse. Cryptographic token generation, expiration, and
  UDP endpoint address binding remain pending.
- 2026-05-22: Added an explicit `PacketNumberSpace` model for Initial,
  Handshake, and Application frame-payload processing. `recordPacketSentInSpace()`,
  `receiveAckInSpace()`, `queueAckForReceivedPacketInSpace()`, and
  `processDatagramInSpace()` keep ACK generation, sent-packet tracking, and
  simplified recovery state isolated per space. `FramePacketType` plus
  `processDatagramForPacketType()` distinguish 0-RTT from 1-RTT frame-type
  validation while both share Application packet number space accounting. Tests
  cover ACK/recovery isolation, receive-side ACK generation isolation, and
  0-RTT forbidden-frame rollback. Protected-packet routing, TLS key discard,
  and 0-RTT/1-RTT key-state integration remain pending.
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
  retry, matching PATH_RESPONSE validation after retry, and retry-budget
  exhaustion.
- 2026-05-22: Added `examples/connection_ids.zig` and
  `zig build run-connection-ids`. The example demonstrates local
  NEW_CONNECTION_ID issuance, peer RETIRE_CONNECTION_ID handling, and issuing a
  replacement CID with retire_prior_to.
- 2026-05-22: Added stateless reset helpers in `quicz.packet` and read-only
  connection-level reset detection. `encodeStatelessReset()` serializes a reset
  datagram from caller-provided unpredictable bytes plus a 16-byte token,
  `matchesStatelessReset()` compares the trailing token, and
  `QuicConnection.detectStatelessReset()` matches active peer-issued CID reset
  tokens while ignoring retired CIDs. Endpoint-level unknown-CID emission remains
  pending until UDP routing exists.
- 2026-05-22: Added `examples/stateless_reset.zig` and
  `zig build run-stateless-reset`. The example demonstrates matching a peer
  stateless reset token and rejecting a false token.
- 2026-05-22: Added `quicz.protection.deriveInitialSecrets()` for RFC 9001
  QUIC v1 Initial secrets. It derives the Initial PRK, client/server Initial
  secrets, AEAD_AES_128_GCM keys, IVs, and AES header-protection keys from the
  first client Initial DCID using TLS HKDF-Expand-Label. `aes128HeaderProtectionMask()`
  and `applyHeaderProtectionMask()` now cover the RFC 9001 AES header-protection
  mask and reversible first-byte/packet-number masking. Tests cover RFC 9001
  Appendix A.1 and A.2 vectors, QUIC v2 rejection while v2 remains deferred,
  invalid CID length rejection, packet-number length validation, and short-header
  first-byte masking.
- 2026-05-22: Added `packetProtectionNonce()`, `protectAes128Payload()`, and
  `unprotectAes128Payload()` for RFC 9001 AEAD_AES_128_GCM payload protection
  with packet-number XOR nonce construction and associated-data authentication.
  Tests cover the RFC 9001 Appendix A.3 Server Initial protected payload,
  decrypt roundtrip, authentication failure mapping, invalid packet-number
  rejection, and buffer-length validation. Full protected-packet assembly,
  protected-packet routing, Handshake/1-RTT traffic secrets, key discard, and
  key update remain pending.
- 2026-05-22: Added `protectLongPacketAes128()` and
  `unprotectLongPacketAes128()` to combine long-header serialization,
  AEAD_AES_128_GCM payload protection, authentication tag handling, header
  protection sampling, packet-number unmasking, packet-number reconstruction,
  and authenticated payload opening for one protected long-header packet. Tests
  cover the RFC 9001 Appendix A.3 Server Initial final protected packet, open
  roundtrip, authentication failure, and too-short header-protection sample
  rejection. Endpoint routing, coalesced-packet receive loops, Handshake/1-RTT
  traffic secrets, key discard, and key update remain pending.
- 2026-05-22: Added `QuicConnection.processInitialProtectedDatagram()`. This
  connection-layer bridge opens one QUIC v1 protected Initial long packet with
  caller-supplied RFC 9001 Initial keys, validates the packet type, packet
  number, and single-packet datagram boundary, then routes the plaintext frame
  payload into the Initial packet number space. Tests cover protected Initial
  CRYPTO delivery, ACK generation, next peer packet-number advancement, and
  tampered-packet rollback. Protected transmit packetization, coalesced receive
  loops, Handshake/1-RTT traffic secrets, key discard, and key update remain
  pending.
- 2026-05-22: Added `QuicConnection.pollInitialProtectedDatagram()` for the
  transmit side of the Initial CRYPTO bridge. It emits one protected QUIC v1
  Initial long packet from the Initial CRYPTO send queue, uses the selected
  packet-number encoding, pads only as needed for the header-protection sample,
  and records protected datagram bytes in sent-packet, recovery, anti-amplification,
  and idle-timeout accounting. Tests cover protected send to
  `processInitialProtectedDatagram()`, packet-number advancement, bytes-in-flight
  accounting, and idle behavior when no Initial CRYPTO is queued. ACK-only,
  PING-only, coalesced protected packets, Handshake/1-RTT traffic secrets, key
  discard, and key update remain pending.
- 2026-05-22: Added `retryIntegrityTag()`, `verifyRetryIntegrityTag()`,
  `encodeRetryPacketWithIntegrity()`, and `parseRetryPacketWithIntegrity()` for
  RFC 9001 Retry Packet Integrity. The lower-level helper builds the Retry
  pseudo-packet from the Original Destination Connection ID and the transmitted
  Retry bytes without the final tag, then computes the fixed-key
  AEAD_AES_128_GCM tag. The integrated helpers serialize a QUIC v1 Retry packet
  with a valid tag and verify before parsing. Tests cover the RFC 9001 Appendix
  A.4 Retry vector, integrated encode/verify/parse, tamper rejection, invalid
  Original DCID length, unsupported version rejection, and too-short Retry
  datagrams. Cryptographic Retry token generation, expiration, and address
  binding remain pending endpoint policy.
- 2026-05-22: Added `examples/initial_keys.zig` and
  `zig build run-initial-keys`. The example prints the RFC 9001 Appendix A
  v1 Initial client/server key, IV, AES header-protection mask, and protected
  packet number values for the sample DCID, then seals and opens a small
  protected server Initial long-header packet with the derived AEAD and header
  protection keys.
- 2026-05-22: Added per-packet-number-space ECN validation state to
  `QuicConnection`. `recordEcnPacketSentInSpace()` records modeled ECT(0) or
  ECT(1) sent packets for deterministic tests, ACK_ECN counters are validated
  against newly acknowledged ECT packets and cumulative sent totals, regular
  ACKs for newly acknowledged ECT packets disable ECN validation, and reordered
  ACKs whose largest acknowledged packet number does not increase cannot fail
  validation. Invalid multi-frame payloads roll ECN validation state back.
- 2026-05-22: Added `examples/ecn_validation.zig` and
  `zig build run-ecn-validation`. The example demonstrates ECT(0) ACK_ECN
  validation and missing-counter failure.
- 2026-05-22: Added simplified RFC 9002 packet-threshold loss detection in
  `QuicConnection` ACK processing. When the largest acknowledged packet number
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
  on invalid multi-frame payloads. Full protected-packet PTO/loss timer
  scheduling remains pending.
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
  expires and a packet is in flight, the hook queues a PING probe in each due
  non-discarded Initial, Handshake, or Application packet number space and
  applies per-space PTO backoff. Protected-packet PTO data retransmission
  remains pending.
- 2026-05-22: Added `examples/pto_recovery.zig` and
  `zig build run-pto-recovery`. The example demonstrates deadline gating,
  PTO-triggered PING queuing, Application PING emission through `pollTx()`, and
  Initial/Handshake PING emission through `pollTxInSpace()`.
- 2026-05-22: Added modeled handshake confirmation via client-side
  HANDSHAKE_DONE and `confirmHandshake()`. RTT updates now ignore Initial ACK
  Delay, decode ACK Delay using the peer `ack_delay_exponent`, and cap decoded
  ACK Delay by peer `max_ack_delay` after handshake confirmation. Unit tests
  cover direct ACK-delay calculation, RTT effect, and invalid-payload rollback.
  `examples/loss_recovery.zig` now demonstrates the post-confirmation cap.
- 2026-05-22: Added `discardPacketNumberSpace()` for modeled Initial and
  Handshake packet number space discard. The hook clears pending ACK,
  largest-acknowledged state, sent-packet tracking, queued/received CRYPTO
  state, bytes in flight, loss deadline, and PTO backoff for the discarded
  space, rejects later use of that frame-payload space, and keeps Application
  state intact. `run-packet-spaces` demonstrates the cleanup. Real TLS key
  discard wiring remains pending.
- 2026-05-22: Added RFC 9000 frame-type validation to
  `processDatagramInSpace()` and `processDatagramForPacketType()`. Initial and
  Handshake frame-payload packet types now accept only frame types that are valid
  for those packet types in RFC 9000 Table 3. The 0-RTT packet type shares
  Application packet number space accounting but rejects ACK, CRYPTO,
  HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, and RETIRE_CONNECTION_ID frames,
  while accepting application frames such as RESET_STREAM and STOP_SENDING.
  Invalid multi-frame payloads roll back earlier state such as a preceding
  PING-generated pending ACK or STREAM receive state. `run-packet-spaces`
  demonstrates the shared Application packet number space and 0-RTT filtering.
- 2026-05-22: Added per-packet-number-space CRYPTO send/receive streams through
  `sendCryptoInSpace()`, `recvCryptoInSpace()`, and `pollTxInSpace()`. Initial,
  Handshake, and Application CRYPTO offsets, queues, receive buffers, ACKs, and
  sent-packet tracking are now independently testable. `examples/crypto_stream.zig`
  and `zig build run-crypto-stream` demonstrate the modeled TLS bridge flow;
  the Initial flight now passes through the protected Initial transmit and
  receive bridge. A real TLS backend, protected coalescing, and later encryption
  levels remain pending.

## Public Interface Plan

The transport implementation should keep the current experimental payload API
usable for focused tests while adding real protected-packet APIs.

Required public or near-public model additions:

- `TransportParameters`
- `TransportError`
- `ConnectionId`
- `ConnectionState`
- `PacketNumberSpace`
- `EcnCodepoint`
- `EcnValidationState`
- `StreamState`
- `CryptoBackend` or `TlsBackend`
- an endpoint/datagram layer for UDP tuple and DCID routing

TLS must remain behind an interface. The connection state machine must not
hard-code one TLS library or backend.

## Examples Plan

Examples should be added only when the demonstrated capability exists and can be
run from `build.zig`.

| Example | Purpose | Status |
| --- | --- | --- |
| `echo_client` / `echo_server` | Current in-memory frame-payload echo baseline. | Present |
| `codec_roundtrip` | Varint, packet header, short-header spin-bit preservation, long/short-packet envelope, header packet number truncation/reconstruction, packet number encoding, frame, transport parameter, connection parameter exposure, and transport error codec usage. | Present |
| `crypto_stream` | Current protected Initial CRYPTO transmit/receive bridge, frame-payload Handshake CRYPTO flow, and modeled handshake confirmation. | Present |
| `initial_keys` | RFC 9001 QUIC v1 Initial secret/key/IV/header-protection key derivation, protected Initial long-packet seal/open, and AES header-protection masking from a client Initial DCID. | Present |
| `udp_echo_client` / `udp_echo_server` | Real QUIC-over-UDP/TLS stream echo. | Planned |
| `uni_stream` | Current in-memory unidirectional stream send/receive, direction validation, and FIN completion observability. | Present |
| `stream_reset` | Current local RESET_STREAM emission, final-size observability, and unsent STREAM drop behavior. | Present |
| `stop_sending` | Current local STOP_SENDING emission and peer RESET_STREAM response. | Present |
| `flow_control` | Connection, stream, stream-count, receive-side MAX, completed-stream MAX_STREAMS, and peer-BLOCKED MAX retransmission behavior. | Present |
| `graceful_close` | Current in-memory CONNECTION_CLOSE/APPLICATION_CLOSE send/receive, retransmission, and closing/draining state behavior. | Present |
| `idle_timeout` | Current max_idle_timeout transport parameter application, activity deadline refresh, and active-to-closed expiry. | Present |
| `packet_spaces` | Current frame-payload Initial/Handshake/Application ACK/recovery isolation, Initial/Handshake discard cleanup, and 0-RTT packet-type filtering. | Present |
| `path_validation` | Current frame-payload PATH_CHALLENGE timeout retry, success, and retry exhaustion. | Present |
| `connection_ids` | Current local NEW_CONNECTION_ID issuing and peer RETIRE_CONNECTION_ID handling. | Present |
| `stateless_reset` | Current stateless reset token match and false-positive rejection helpers. | Present |
| `ecn_validation` | Current frame-payload ECT send modeling and ACK_ECN counter validation. | Present |
| `loss_recovery` | Current frame-payload packet-threshold loss, time-threshold loss, NewReno recovery period, persistent congestion, and ACK-delay handling. | Present |
| `pto_recovery` | Current frame-payload Initial/Handshake/Application PTO PING timeout hooks. | Present |
| `address_validation` | Current modeled server anti-amplification budget and explicit peer-address validation. | Present |
| `retry_token` | Current Retry packet integrity-tag encode/verify/parse, token loopback, one-time token consumption, and address-validation unblocking. | Present |
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
zig build run-flow-control
zig build run-uni-stream
zig build run-stream-reset
zig build run-stop-sending
zig build run-crypto-stream
zig build run-graceful-close
zig build run-idle-timeout
zig build run-packet-spaces
zig build run-ecn-validation
zig build run-loss-recovery
zig build run-pto-recovery
zig build run-path-validation
zig build run-address-validation
zig build run-retry-token
zig build run-connection-ids
zig build run-stateless-reset
zig build run-initial-keys
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
