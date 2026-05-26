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

Deferred standards and extensions, except already implemented QUIC v2
packet/key/token and RFC 9368 version-information primitives:

- Full QUIC v2 behavior, RFC 9369
- Full Compatible Version Negotiation, RFC 9368
- QUIC DATAGRAM, RFC 9221
- HTTP/3 and QPACK
- Multipath and other in-progress QUIC WG drafts

## RFC Coverage Status

Status values are `Done`, `Partial`, `Missing`, and `Deferred`. `Partial`
means the repository has code and tests for part of the area, but the
remaining behavior still appears in the task matrix below.

| Standard area | Status | Current evidence | Remaining proof |
| --- | --- | --- | --- |
| RFC 8999 version-independent properties | Partial | Version Negotiation packet codec, endpoint unsupported-version Version Negotiation response helper, client-side Version Negotiation packet validation/selection state, long/short packet envelopes, connection ID length checks including first-client-Initial DCID length enforcement, stateless reset helpers, packet codec/example tests, and socket-backed UDP endpoint routing loopback with client-side Version Negotiation selection. | Full TLS-owned socket-backed packet routing and interop must prove complete version-independent behavior. |
| RFC 9000 transport protocol | Partial | Frame codec, transport parameters, connection state, streams, flow control, connection IDs, Retry/tokens, path validation, close/reset behavior, endpoint routing helpers, caller-keyed protected UDP packet loopback, socket-backed UDP path-validation route-update loopback, socket-backed UDP Retry/address-validation loopback, and examples. | Full protected/TLS socket-backed client/server loopback, complete endpoint lifecycle, and external interop. |
| RFC 9001 TLS and packet protection | Partial | QUIC v1 Initial secret derivation, AEAD/header-protection helpers, Retry Integrity Tag, protected packet helpers, mock CRYPTO backend handoff, installed-key tests, and ACK-gated installed-key key-update initiation. | Real TLS backend transcript integration, TLS-owned traffic-secret production, remaining automatic key discard, and full TLS-owned live key-update scheduling/old-key discard. |
| RFC 9002 loss detection and congestion control | Partial | ACK delay scaling/capping, packet/time-threshold loss, NewReno recovery-period behavior, persistent congestion, packet-space PTO PING/new-data probe hooks with Initial/Handshake max_ack_delay suppression, and ECN validation tests. | Full protected-packet PTO/loss timer scheduling and retransmission behavior with controlled-clock tests. |
| RFC 9221 QUIC DATAGRAM | Deferred | Explicitly outside the first transport-core scope. | Track separately after the core transport loop is functional. |
| RFC 9368 compatible version negotiation | Partial | `version_information` transport parameter codec, connection-level export/application validation including post-VN server Version Information downgrade checks, `VERSION_NEGOTIATION_ERROR` code, and client-side incompatible VN packet validation/selection state are present. | Full incompatible/compatible negotiation state machine, endpoint routing integration, and interop. |
| RFC 9369 QUIC v2 | Partial | Version constant, long-header packet type bit mapping, Retry packet codec mapping, v2 Retry Integrity Tag helpers, address-validation token originating-version binding, RFC 9368 `version_information` transport-parameter support, and RFC 9369 Initial salt plus `quicv2` packet-protection label derivation with Appendix A.1/A.4 vectors. | Remaining full compatible version negotiation state, endpoint routing, and interop. |
| HTTP/3 and QPACK | Deferred | Application protocols are outside this transport-core plan. | Start separate application-layer tasks after transport interop. |

The current codebase is still an experimental frame-payload transport skeleton.
`pollTx` and `processDatagram` move unencrypted QUIC frame payload bytes. The
connection layer now has a narrow Initial/Handshake CRYPTO/ACK/PING protected
long-packet coalesced send/receive bridge, installed-key Handshake long-packet
helpers, first-client-Initial DCID length and server-Initial token validation,
caller-keyed or installed-key 0-RTT STREAM/RESET_STREAM/STOP_SENDING protected long-packet routing, and caller-keyed 1-RTT protected
short-packet PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge with caller-owned and connection-installed key-phase state helpers, plus socket-backed UDP endpoint routing, Retry/address-validation routing, caller-keyed protected packet loopbacks, and caller-committed UDP path-validation route updates, but it does not yet fully
produce or consume TLS-owned QUIC packets over UDP.

## Task Matrix

| Area | Current status | Required outcome | Verification |
| --- | --- | --- | --- |
| Standard tracking | Core/deferred RFC coverage table present | Keep each core RFC area marked as done, partial, missing, or deferred as implementation moves. | Markdown review plus `zig build test`. |
| RFC 8999 / 9000 packet codec | Partial with v2 type-bit awareness + endpoint unsupported-version VN response helper + client-side VN selection state | Complete version-independent packet handling, version negotiation, Retry, long and short headers, packet number handling, and transport error values. | Existing tests cover v1/v2 long-header packet type bit mapping, Retry codec mapping, Version Negotiation response CID echoing, client-side VN CID validation, Original Version ignore, mutual-version selection, first-client-Initial DCID length checks, server-Initial token rejection, Initial UDP datagram 1200-byte expansion/discard checks, roundtrip, boundary, truncation, invalid-value, and allocation-failure behavior; `run-udp-endpoint-loopback` proves socket-backed endpoint routing for Version Negotiation, client-side VN selection, and Initial classification. |
| RFC 9000 frame codec | Frame set present + shortest frame-type varint validation + unknown type rejection + partial packet-type validation | Cover all RFC 9000 transport frames with strict value validation and stable error mapping. | Per-frame encode/decode tests for valid, truncated, invalid, and unknown inputs. |
| Transport parameters | Typed codec + connection exposure + preferred_address export/application + RFC 9368 `version_information` export/application validation, including VN-triggered server downgrade checks + TLS extension byte encode/apply + CryptoBackend byte handoff + configured local ACK delay export separated from peer recovery policy | Add full TLS backend transcript handshake integration for exported parameters and full version-negotiation state ownership. | Existing roundtrip, duplicate/invalid parameter, connection apply/export, TLS extension byte encode/apply, mock-backend local/peer byte handoff, server preferred_address, `version_information`, VN-triggered downgrade checks, default-value, and local-vs-peer ACK delay tests cover the codec and connection surface; later real TLS backend and endpoint tests prove transcript integration and full version negotiation. |
| Connection state machine | Partial close-state + peer close diagnostics + idle timeout + explicit handshake progress state | Model Initial, Handshake, 0-RTT, 1-RTT, idle timeout, closing, draining, and closed states. | Existing tests cover close/drain transitions, peer close diagnostics, close expiry, idle expiry, handshake progress from Initial to Handshake to Confirmed, and invalid-packet rollback; later protected-packet tests cover key-state transitions. |
| Packet number spaces | Partial frame-payload ACK/recovery + CRYPTO isolation and receive reassembly + Initial/Handshake protected CRYPTO/ACK/PING coalesced send/receive bridge with first-client-Initial DCID length, server-Initial token validation, and RFC 9000 Initial UDP datagram size checks + caller-keyed or installed-key 0-RTT protected long STREAM/RESET_STREAM/STOP_SENDING routing + 1-RTT protected short PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge + frame-type filtering + RFC 9001 Initial discard after client Handshake send/server Handshake receive + discard cleanup that clears installed Handshake keys + valid client-side HANDSHAKE_DONE-triggered, server-side sendHandshakeDone-triggered, and backend-confirmed no-output Handshake-space discard | Maintain distinct Initial, Handshake, and Application packet number spaces, then route protected packets into the matching space with the remaining TLS-triggered key discard rules. | Existing ACK/recovery, CRYPTO isolation, out-of-order CRYPTO receive, Initial/Handshake protected send/receive including first-client-Initial DCID rejection, server-Initial token rejection, Initial UDP datagram 1200-byte expansion/discard checks, coalesced send/receive, caller-keyed and installed-key 0-RTT protected STREAM/RESET_STREAM/STOP_SENDING, 1-RTT protected PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive, forbidden-frame, RFC 9001 Initial discard, explicit discard, installed Handshake key cleanup, and valid HANDSHAKE_DONE/backend-confirmed cleanup tests prove isolation and cleanup between spaces; later protected endpoint tests prove full routing. |
| Real datagram API | Initial/Handshake protected CRYPTO/ACK/PING coalesced send/receive bridge with first-client-Initial DCID length, server-Initial token validation, and RFC 9000 Initial UDP datagram size checks + caller-keyed protected Initial/1-RTT short socket loopback + caller-keyed or installed-key 0-RTT protected long STREAM/RESET_STREAM/STOP_SENDING routing + protected 1-RTT short PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge + caller-owned and ACK-gated installed-key key-phase state 1-RTT short-packet bridge + configurable single-path spin-bit policy + protected long/short-packet helper + in-memory endpoint DCID/IPv4-tuple router + socket-backed endpoint routing loopback for VN/Initial/short-header classification + socket-backed zero-length CID tuple-routing loopback + socket-backed preferred-address route-migration loopback + socket-backed replacement-CID route-retirement loopback + socket-backed connection-ID NEW/RETIRE loopback + socket-backed installed-key key-update loopback + socket-backed path-validation route-update loopback + socket-backed Retry/address-validation loopback + socket-backed close-triggered route retirement + zero-length CID tuple routing + sequence/retire-prior-to route retirement + endpoint reset-token uniqueness checks + caller-validated path update + retired-CID stateless reset token lookup/datagram construction + socket-backed retired-CID stateless reset emission loopback + route/reset/drop receive classification | Add protected QUIC datagram receive/transmit APIs above the existing frame-payload skeleton. | Existing helper tests cover protected Initial packets, protected short-packet roundtrip, key-phase short-packet selection, protected long-packet boundary peeking, endpoint DCID routing including zero-length CID tuple routing, sequence/retire-prior-to route retirement, endpoint reset-token reuse rejection, caller-validated path updates, stateless reset token lookup/datagram construction after route retirement, and endpoint receive action classification; `examples/udp_endpoint_loopback.zig` covers real loopback UDP Version Negotiation response delivery, supported Initial accept, client Initial SCID response routing, and server Initial SCID short-header routing; `examples/udp_zero_cid_loopback.zig` covers real loopback UDP short and long datagram routing for zero-length destination CIDs by local/remote tuple, path-specific retirement, and route path update; `examples/udp_preferred_address_loopback.zig` covers real loopback UDP preferred-address migration commit, current-route retirement, preferred CID routing on the preferred server address, active-migration-disabled rejection on a stray path, and retained reset-token lookup after retirement; `examples/udp_replacement_cid_loopback.zig` covers real loopback UDP replacement-CID registration with `retire_prior_to`, inactive reset-token lookup for retired sequence routes, active replacement CID routing, invalid sequence rejection, and active-migration-disabled rejection on a stray path; `examples/udp_connection_ids_loopback.zig` covers real loopback UDP protected NEW_CONNECTION_ID delivery, endpoint route replacement for a newly issued CID, inactive old-CID reset-token lookup, protected RETIRE_CONNECTION_ID routing through the active replacement CID, server-side local CID retirement, and ACK cleanup; `examples/udp_key_update_loopback.zig` covers real loopback UDP installed-key key update initiation, next key-phase packet routing, peer key-phase advancement after authenticated receive, ACK delivery, key-update ACK gating, and second-update re-enable; `examples/udp_protected_loopback.zig` covers real loopback UDP protected client Initial, protected server Initial, routed client 1-RTT PING, and routed server 1-RTT ACK with caller-supplied keys; `examples/udp_path_validation_loopback.zig` covers real loopback UDP PATH_CHALLENGE delivery to a new peer port, PATH_RESPONSE routing with `path_changed`, caller-committed route path update after validation, and confirmed routing on the new path; `examples/udp_retry_loopback.zig` covers real loopback UDP Retry delivery, Retry Source CID route switching, address-bound Retry token validation, replay rejection, follow-up protected Initial routing, and Retry transport-parameter checks; `examples/udp_close_lifecycle_loopback.zig` covers protected close delivery over UDP, connection-handle route retirement, retained inactive-CID reset-token lookup, reset emission, and client-side token matching; `examples/udp_stateless_reset_loopback.zig` covers real loopback UDP reset-trigger receive classification, server reset emission, and client-side token matching; connection tests cover protected Initial/Handshake CRYPTO, first-client-Initial DCID rejection, server-Initial token rejection, Initial UDP datagram 1200-byte expansion/discard checks, ACK-only, PING, caller-keyed and installed-key 0-RTT STREAM/RESET_STREAM/STOP_SENDING, coalesced send/receive, protected 1-RTT PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive, installed-key short PING/ACK exchange, installed-key ACK-gated key-update initiation, key-phase-state PING receive with failure-state preservation, and enabled/disabled spin-bit state updates with invalid-packet preservation; later socket-backed client/server loopback must use TLS-owned keys and endpoint lifecycle ownership. |
| TLS integration | CRYPTO bridge hooks with per-space out-of-order receive buffering plus a pluggable backend drive helper, transport-parameter byte handoff, mock Handshake/0-RTT/1-RTT traffic-secret handoff, backend-confirmed no-output Handshake discard, explicit installed-key 0-RTT accept/reject, and modeled 0-RTT discard at 1-RTT boundaries present, real TLS backend missing | Use a pluggable TLS backend interface driven by CRYPTO frames. | Existing mock-backend tests cover CRYPTO delivery, local/peer transport-parameter byte handoff, backend output queuing and preservation, Handshake, 0-RTT, and 1-RTT traffic-secret installation, handshake confirmation, backend-confirmed no-output Handshake discard, installed-key 0-RTT rejection before accept, accept-driven 0-RTT receive, reject-driven key discard, client 0-RTT cleanup on 1-RTT key install, server 0-RTT cleanup after accepted 1-RTT receive, and scratch-buffer boundaries; later real TLS transcript tests and a local 1-RTT establishment test prove full integration. |
| Packet protection | Partial v1/v2 Initial keys + AES-GCM payload/header protection + protected long/short-packet helpers + caller-keyed protected UDP loopback + socket-backed installed-key key-update loopback + unprotected spin-bit peek + v1/v2 Retry Integrity Tag helpers + `quic ku` key-update derivation + connection-installed Handshake and 0-RTT long-packet keys + explicit installed-key 0-RTT accept/reject + RFC 9001 Initial discard at Handshake send/receive boundaries + explicit installed Handshake/0-RTT key discard hooks + client-side HANDSHAKE_DONE-triggered, server-side sendHandshakeDone-triggered, and backend-confirmed no-output Handshake key discard + client/server 0-RTT key discard at modeled 1-RTT boundaries + caller-owned and connection-installed 1-RTT key-phase state helpers, ACK-gated installed-key update initiation, and explicit short-packet key-phase send/receive | Implement real TLS-backed early-data secret ownership, real TLS Handshake/1-RTT secret production, header protection, AEAD protection, remaining TLS-triggered Handshake key discard, full TLS 0-RTT acceptance/replay policy, full TLS-owned live key-update scheduling/old-key discard, and the rest of RFC 9369 packet protection behavior beyond Initial keys and Retry integrity helpers. | Existing RFC-vector and fixed-vector tests cover v1 and v2 Initial derivation, header protection, AEAD protection, protected packets, v1 and v2 Retry Integrity Tag, spin-bit peeking, `quic ku` key-update derivation, caller-owned key-phase state transitions, caller-keyed key-phase packet selection, mock Handshake/0-RTT/1-RTT traffic-secret installation, RFC 9001 Initial discard after Handshake send/receive, installed-key Handshake long-packet exchange, installed-key 0-RTT long-packet exchange, installed-key 0-RTT rejection before accept, accept-driven 0-RTT receive, reject-driven key discard, explicit installed-key discard cleanup, valid HANDSHAKE_DONE and backend-confirmed no-output cleanup, client 0-RTT cleanup on 1-RTT key install, server 0-RTT failure preservation and success cleanup after 1-RTT receive, installed-key short-packet exchange, installed-key key-phase advancement after successful receive, installed-key key-update rejection before handshake confirmation, ACK-gated repeat rejection, ACK-driven re-enable, invalid-payload rollback, `run-udp-protected-loopback` socket delivery, and `run-udp-key-update-loopback` installed-key key update over real loopback UDP sockets; later TLS/endpoint tests cover real traffic-secret use, remaining automatic Handshake key discard, and full TLS-owned live key-update scheduling. |
| Streams | Partial receive reassembly with duplicate retransmission discard + FIN completion + local reset/stop observability + implicit lower-numbered receive stream creation + pre-STREAM peer-bidirectional STOP_SENDING handling | Complete stream state machines, FIN/reset rules, and read/write behavior beyond the current in-memory reassembly skeleton. | Bidirectional, unidirectional, FIN, reset, STOP_SENDING, out-of-order, duplicate retransmission, conflict overlap, rollback, and final-size tests. |
| Flow control | Partial receive MAX and stream-count refresh + configurable receive data/stream-count windows + BLOCKED observability/retransmission/growth + implicit lower-numbered receive stream creation + STREAM_DATA_BLOCKED receive-state validation + pre-STREAM peer-bidirectional MAX_STREAM_DATA handling | Complete remaining adaptive MAX/BLOCKED policy reactions. | Blocked/unblocked tests at connection, stream, and stream-count scope, including target receive-window refresh, peer-BLOCKED growth, stream-count-window growth, and receive-side stream-state validation. |
| Connection IDs | Partial local/peer lifecycle + stateless-reset-token uniqueness checks + endpoint sequence/retire-prior-to DCID route table + endpoint replacement-CID registration helper + connection-handle route retirement + socket-backed replacement-CID route-retirement loopback + socket-backed connection-ID NEW/RETIRE loopback | Add full socket-owned connection lifecycle integration around DCID routing and replacement policy. | Existing tests cover local NEW_CONNECTION_ID issuing, peer RETIRE handling, peer-issued NEW_CONNECTION_ID lifecycle, duplicate CID/token rejection, limit, rollback, endpoint route registration, endpoint reset-token reuse rejection, endpoint replacement-CID registration with retire_prior_to application, route retirement by CID, sequence number, retire_prior_to threshold, or connection handle, and unknown/ambiguous CID rejection; `run-udp-replacement-cid-loopback` proves replacement route registration, retire_prior_to retirement, inactive reset-token lookup, active replacement routing, invalid sequence rejection, and active-migration-disabled rejection over real loopback UDP sockets; `run-udp-connection-ids-loopback` proves protected NEW_CONNECTION_ID delivery, replacement route installation, protected RETIRE_CONNECTION_ID routing through the active replacement CID, server local-CID retirement, and ACK cleanup over real loopback UDP sockets; later endpoint tests cover full socket-owned connection lifecycle integration. |
| Tokens and Retry | Partial codec + v1/v2 Retry Integrity Tag helpers + server-side NEW_TOKEN issuing + client-side NEW_TOKEN storage + modeled server anti-amplification send limiting + HMAC-SHA256 address-bound expiring token generation/validation with originating-version binding + endpoint IPv4 peer-address token binding + in-memory endpoint address-validation policy with rotated secrets, secret-set export/restore, replay-filter snapshot export/restore, and replay rejection + explicit one-time Retry token validation + server-side Retry datagram issuance + client-side Retry datagram processing and handshake CID transport-parameter validation/export + socket-backed UDP Retry/address-validation loopback | Add production endpoint token-secret storage/distribution around exported secret/replay snapshots and integrate it with socket-owned endpoint lifecycle. | Existing tests cover Retry packet codec, RFC 9001 and RFC 9369 Retry Integrity Tag vectors, protected NEW_TOKEN issuing/storage, modeled 3x anti-amplification limiting, HMAC address-token kind/address/tamper/expiry/version mismatch checks, endpoint remote IPv4/port token binding, in-memory endpoint secret rotation, secret-set export/restore with retention trimming, replay-filter snapshot export/restore with retention trimming, bounded replay-filter duplicate/capacity behavior, validated-token replay fingerprint recording, one-time Retry token consumption, server-side Retry datagram issuance, client-side Retry datagram processing, `initial_source_connection_id`, `original_destination_connection_id`, and `retry_source_connection_id` validation/export; `run-udp-retry-loopback` proves real UDP Retry delivery, address-bound token validation, replay rejection, token consumption, and Retry CID transport-parameter validation; later endpoint tests cover production secret/replay storage integration. |
| Path validation | Partial timeout/retry + protected exchange + caller-committed endpoint route update after PATH_RESPONSE validation + socket-backed UDP path-validation route-update loopback | Bind validation automatically to endpoint path identity once real UDP routing owns connection paths. | Existing tests cover matching, duplicate, mismatched, rollback, timeout retry, retry exhaustion, protected PATH_CHALLENGE/PATH_RESPONSE exchange, and endpoint route path update after protected PATH_RESPONSE validation; `run-udp-path-validation-loopback` proves the same route-update flow over loopback UDP sockets with a new peer port; later endpoint tests cover automatic path identity ownership. |
| Stateless reset | Partial helper + constant-time token match + connection detection + NEW_CONNECTION_ID token uniqueness checks + endpoint inactive-CID reset datagram construction + route/reset/drop receive classification + socket-backed UDP reset emission loopback + socket-backed close-triggered route retirement/reset loopback | Integrate reset emission into socket-owned endpoint lifecycle and connection close/drop policy. | Existing tests cover reset token match, false-positive rejection, short datagram rejection, duplicate-token rejection across CIDs, retired-token ignore, active-route token suppression, retired-route token lookup, inactive-route reset datagram construction, smaller-than-trigger sizing, route/reset/drop receive action classification, and ambiguous reset-token CID rejection; `run-stateless-reset` demonstrates endpoint inactive-CID reset action; `run-udp-stateless-reset-loopback` demonstrates real UDP trigger delivery, reset emission, and client token matching; `run-udp-close-lifecycle-loopback` demonstrates protected close delivery, connection-handle route retirement, retained reset token lookup, reset emission, and client token matching; later endpoint tests cover full TLS-owned lifecycle integration. |
| ECN validation | Partial frame-payload ACK_ECN validation + endpoint UDP-path ECN state policy | Bind ECN validation to real IP ECN marking once socket packetization exists. | Existing tests cover ECT(0) success, missing ACK_ECN failure, insufficient counters, counter totals exceeding sent ECT packets, reordered ACK handling, rollback, and endpoint path-identity state isolation; later endpoint tests cover real IP-header marking. |
| RFC 9002 recovery | Partial ACK delay + packet/time-threshold loss + NewReno recovery period + persistent congestion + packet-space PTO PING/new-data probe hook with Initial/Handshake max_ack_delay suppression | Implement full protected-packet PTO/loss timer scheduling and remaining NewReno details. | Existing tests cover ACK, ACK delay exponent scaling, post-confirmation max_ack_delay capping, packet-threshold loss, ACK-driven and timeout-driven time-threshold loss, NewReno recovery-period suppression, persistent congestion, rollback, packet-number-space PTO PING queuing/backoff, Initial/Handshake PTO deadline calculation without max_ack_delay, queued STREAM data probe selection, and congestion-window arithmetic; later controlled-clock tests cover protected-packet PTO data retransmission. |
| UDP endpoint routing | Partial in-memory DCID/IPv4 tuple router + socket-backed UDP endpoint routing loopback with client-side VN selection + socket-backed zero-length CID tuple-routing loopback + socket-backed preferred-address route-migration loopback + socket-backed replacement-CID route-retirement loopback + socket-backed connection-ID NEW/RETIRE loopback + socket-backed installed-key key-update loopback + socket-backed path-validation route-update loopback + socket-backed Retry route-switch/address-validation loopback + socket-backed close-triggered route retirement/reset loopback + socket-backed stateless reset emission loopback + unsupported-version VN response helper + client-side VN selection state + client Initial Source CID route registration + supported-version unknown-DCID Initial accept classification + accepted Initial Original DCID/server Initial SCID route registration + zero-length CID tuple routing + Retry DCID switch helper + caller-validated preferred-address migration commit + sequence/retire-prior-to/connection-handle route retirement + endpoint reset-token uniqueness checks + caller-validated path update + retired-CID stateless reset token lookup/datagram construction + route/version-negotiation/reset/drop/accept receive classification | Route UDP datagrams by DCID, local/remote address tuple, version support, and connection state. | Existing deterministic endpoint tests cover long-header DCID routing, unsupported-version Version Negotiation response generation with CID echoing, client Initial Source CID route registration for server Initial/VN responses, supported-version unknown-DCID Initial accept metadata, accepted Initial route registration and rollback, client-side VN selection/ignore/reject state, short-header registered-CID matching, zero-length CID tuple routing, duplicate route rejection, duplicate sequence rejection, stateless reset token reuse rejection, Retry Source CID route switching, caller-validated preferred-address route migration, unknown CID rejection, ambiguous short-header CID rejection, path-specific zero-CID retirement, sequence-number route retirement for RETIRE_CONNECTION_ID wiring, retire_prior_to threshold retirement, connection-handle route retirement, caller-validated route path updates, stale path-update rejection, active-migration-disabled path rejection, stateless reset token lookup for inactive routes, reset datagram construction for inactive routes, and route/version-negotiation/reset/drop/accept receive action classification; `run-udp-endpoint-loopback` covers routing decisions and client-side VN selection over real loopback UDP sockets; `run-udp-zero-cid-loopback` covers zero-length CID tuple routing, long-header zero-DCID routing, path-specific retirement, and route path update over real loopback UDP sockets; `run-udp-preferred-address-loopback` covers caller-committed preferred-address route migration, preferred CID routing, current-route retirement, active-migration-disabled stray-path rejection, and retained reset-token lookup over real loopback UDP sockets; `run-udp-replacement-cid-loopback` covers replacement-CID route registration, retire_prior_to sequence retirement, inactive reset-token lookup, active replacement routing, invalid replacement sequence rejection, and active-migration-disabled stray-path rejection over real loopback UDP sockets; `run-udp-connection-ids-loopback` covers protected NEW_CONNECTION_ID and RETIRE_CONNECTION_ID exchange through endpoint routes, replacement CID routing, inactive reset-token lookup, and active replacement token suppression over real loopback UDP sockets; `run-udp-key-update-loopback` covers installed-key key phase routing, peer key-phase advancement, and ACK-gated second-update re-enable over real loopback UDP sockets; `run-udp-path-validation-loopback` covers new-peer-port path_changed routing followed by caller-committed path update and confirmed routing on the new path; `run-udp-retry-loopback` covers Retry response routing, Retry Source CID route switching, follow-up Initial routing, and accepted server Initial response routing over loopback UDP sockets; `run-udp-close-lifecycle-loopback` covers close-triggered connection-handle route retirement and follow-up inactive-CID reset emission over loopback UDP sockets; `run-udp-stateless-reset-loopback` covers socket-backed stateless reset emission for an inactive CID; later tests cover protected client/server integration. |
| Interop | Missing | Validate a minimal QUIC echo flow against at least one external implementation. | Manual or optional CI script records peer implementation and version. |

## Progress Notes

- 2026-05-26: Added `examples/udp_key_update_loopback.zig` and the
  `run-udp-key-update-loopback` build step. The example installs modeled
  1-RTT traffic secrets into client and server connections, initiates an
  installed-key update, sends the next key-phase PING over loopback UDP,
  verifies server peer key-phase advancement after authenticated receive, sends
  an ACK back over UDP, and proves the ACK gate re-enables the next local key
  update.
- 2026-05-26: Added `examples/udp_connection_ids_loopback.zig` and the
  `run-udp-connection-ids-loopback` build step. The example delivers protected
  NEW_CONNECTION_ID frames over loopback UDP, updates endpoint routes for the
  replacement CID, proves the old CID only exposes an inactive reset token,
  routes protected RETIRE_CONNECTION_ID through the active replacement CID, and
  verifies server-side local CID retirement plus ACK cleanup.
- 2026-05-26: Added `examples/udp_replacement_cid_loopback.zig` and the
  `run-udp-replacement-cid-loopback` build step. The example registers an
  initial route, installs replacement CIDs with `retire_prior_to` over loopback
  UDP, proves retired sequence routes expose inactive reset tokens while active
  replacement CIDs suppress reset tokens, rejects invalid replacement sequence
  metadata, and rejects a stray path under active-migration-disabled policy.
- 2026-05-26: Added `examples/udp_preferred_address_loopback.zig` and the
  `run-udp-preferred-address-loopback` build step. The example registers a
  current server route on one loopback UDP address, commits a caller-validated
  preferred-address CID on a second server address, proves the old route is
  retired, routes the preferred CID on the preferred path, rejects the same CID
  on a stray path under active-migration-disabled policy, and verifies the
  preferred-address reset token remains available after retirement.
- 2026-05-25: Added `examples/udp_zero_cid_loopback.zig` and the
  `run-udp-zero-cid-loopback` build step. The example registers two
  zero-length destination CID routes on separate UDP tuples, proves short and
  long datagrams are routed by tuple identity over loopback sockets, retires
  one zero-CID route by path, then updates the remaining route to a new peer
  port and verifies routing there.
- 2026-05-25: Added `examples/udp_path_validation_loopback.zig` and the
  `run-udp-path-validation-loopback` build step. The example sends a protected
  PATH_CHALLENGE over loopback UDP to a new client port, routes the protected
  PATH_RESPONSE back through the server endpoint with `path_changed = true`,
  validates the response at the connection layer, then commits the endpoint
  route update and proves subsequent routing no longer reports a path change.
- 2026-05-25: Added `examples/udp_retry_loopback.zig` and the
  `run-udp-retry-loopback` build step. The example sends an Initial-like
  datagram over loopback UDP, issues a server Retry with an address-bound
  endpoint token, routes the Retry back to the client, switches the server
  pending route to the Retry Source CID, validates the follow-up Initial token
  with replay rejection, consumes the one-time Retry token, exchanges protected
  Initial CRYPTO on the Retry-derived keys, and validates the Retry-related
  transport parameters.
- 2026-05-25: Extended `examples/udp_endpoint_loopback.zig` so the real
  loopback UDP Version Negotiation response is passed into
  `QuicConnection.processVersionNegotiationDatagram()`. The example now proves
  endpoint VN response delivery and client-side mutual-version selection in the
  same socket-backed flow.
- 2026-05-25: Added `examples/udp_close_lifecycle_loopback.zig` and the
  `run-udp-close-lifecycle-loopback` build step. The example delivers a
  protected CONNECTION_CLOSE over loopback UDP, routes it through the active
  endpoint CID, retires the connection handle's routes after the server enters
  draining, then answers a later packet for the inactive CID with a stateless
  reset using the retained token.
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
  `QuicConnection.processVersionNegotiationDatagram()` validates the RFC 8999
  connection-ID echo, ignores packets that contain the client's Original Version
  or mismatched CIDs, selects a mutual version from local `available_versions`,
  records that this connection attempt already reacted to VN, and exposes the
  result through `versionNegotiationSelectedVersion()`. Starting the follow-up
  incompatible-version connection and validating the later authenticated RFC
  9368 server Version Information remain pending.
- 2026-05-23: Added RFC 9368 server Version Information downgrade checks after
  a client reacts to Version Negotiation. Follow-up client connections can carry
  `Config.version_negotiation_selected_version`; peer transport-parameter
  validation then requires the server Chosen Version to match that selection,
  rejects empty server Available Versions, checks that the client would still
  select the same version from server Available Versions plus the negotiated
  version, and preserves the QUIC v1 missing-`version_information` exception.
  Full follow-up connection orchestration remains caller-owned.
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
- 2026-05-22: Added `examples/codec_roundtrip.zig` and `zig build run-codec`.
  The example exercises varint, short-packet envelope, coalesced long-packet envelope,
  short-header spin-bit preservation, header packet number
  truncation/reconstruction, packet number encoding, Version Negotiation,
  STREAM frame, transport parameter, connection transport-parameter exposure
  including TLS extension bytes and local ACK delay policy, and transport error
  helper roundtrips.
- 2026-05-22: Added `QuicConnection.localTransportParameters()` and
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
- 2026-05-22: Added `QuicConnection.sendPathChallenge()` with outbound
  PATH_CHALLENGE queuing, matching PATH_RESPONSE validation, duplicate or
  mismatched response rejection, and rollback tests for invalid multi-frame
  payloads. Timeout/retry policy is still pending.
- 2026-05-22: Added peer-issued connection ID lifecycle tracking in
  `QuicConnection`. NEW_CONNECTION_ID now stores active peer CIDs, rejects
  inconsistent duplicate sequence numbers, rejects stateless reset token reuse
  across CIDs, enforces the configured active CID limit, applies retire_prior_to
  by queuing RETIRE_CONNECTION_ID, and rolls back partial CID state on invalid
  multi-frame payloads. Local CID issuing and full endpoint DCID routing
  lifecycle remain pending.
- 2026-05-22: Added local connection ID issuing in `QuicConnection`.
  `issueConnectionId()` copies local CID bytes, assigns NEW_CONNECTION_ID
  sequence numbers, enforces peer active CID limits, rejects duplicate local CID
  values and stateless reset token reuse, and queues unsent IDs for `pollTx()`. Inbound RETIRE_CONNECTION_ID now
  marks previously sent local CIDs retired and rolls back retirement on invalid
  multi-frame payloads. The endpoint route-table skeleton can store optional
  NEW_CONNECTION_ID sequence numbers and retire routes by sequence or
  retire_prior_to threshold for future RETIRE_CONNECTION_ID wiring; the
  socket-backed replacement-CID route-retirement and caller-owned NEW/RETIRE
  proofs now live in `examples/udp_replacement_cid_loopback.zig` and
  `examples/udp_connection_ids_loopback.zig`, while full connection lifecycle
  wiring and socket-owned replacement policy remain pending.
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
  `QuicConnection`. Non-overlapping ranges are accounted for when received and
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
- 2026-05-22: Added `QuicConnection.resetStream()` and
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
- 2026-05-22: Added `QuicConnection.stopSending()` and
  `examples/stop_sending.zig` with `zig build run-stop-sending`. The API queues
  STOP_SENDING for opened local bidirectional receive sides and observed
  peer-initiated receive streams, rejects send-only and unobserved streams,
  deduplicates local stop requests, and exercises the peer RESET_STREAM response.
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
- 2026-05-22: Added client-side NEW_TOKEN storage in `QuicConnection`.
  Client connections retain opaque token bytes up to `Config.max_stored_new_tokens`
  and expose the newest token via `latestNewToken()`. Tests cover storage,
  capacity, server-side rejection, and invalid-payload rollback. Later bullets
  cover cryptographic token generation and endpoint peer-address binding.
- 2026-05-22: Added local close emission in `QuicConnection` with
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
  route path update after protected PATH_RESPONSE validation.
- 2026-05-22: Added `examples/connection_ids.zig` and
  `zig build run-connection-ids`. The example demonstrates local
  NEW_CONNECTION_ID issuance, peer RETIRE_CONNECTION_ID handling, and issuing a
  replacement CID with retire_prior_to.
- 2026-05-22: Added stateless reset helpers in `quicz.packet` and read-only
  connection-level reset detection. `encodeStatelessReset()` serializes a reset
  datagram from caller-provided unpredictable bytes plus a 16-byte token,
  `matchesStatelessReset()` compares the trailing token in constant time, and
  `QuicConnection.detectStatelessReset()` matches active peer-issued CID reset
  tokens while ignoring retired CIDs.
- 2026-05-22: Added `examples/stateless_reset.zig` and
  `zig build run-stateless-reset`. The example demonstrates matching a peer
  stateless reset token, rejecting a false token, and endpoint-level inactive-CID
  reset action construction.
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
- 2026-05-22: Added `QuicConnection.processInitialProtectedDatagram()`. This
  connection-layer bridge opens one QUIC v1 protected Initial long packet with
  caller-supplied RFC 9001 Initial keys, validates the packet type, packet
  number, and single-packet datagram boundary, then routes the plaintext frame
  payload into the Initial packet number space. Tests cover protected Initial
  CRYPTO delivery, ACK generation, next peer packet-number advancement, and
  tampered-packet rollback. Protected transmit beyond CRYPTO-only long packets,
  TLS traffic secret production, key discard, and key update remain pending.
- 2026-05-22: Added `QuicConnection.pollInitialProtectedDatagram()` for the
  transmit side of the Initial CRYPTO bridge. It emits one protected QUIC v1
  Initial long packet from the Initial CRYPTO send queue, uses the selected
  packet-number encoding, pads only as needed for the header-protection sample,
  and records protected datagram bytes in sent-packet, recovery, anti-amplification,
  and idle-timeout accounting. Tests cover protected send to
  `processInitialProtectedDatagram()`, packet-number advancement, bytes-in-flight
  accounting, and idle behavior when no Initial CRYPTO is queued. ACK-only,
  PING-only, TLS traffic secret production, key
  discard, and key update remain pending.
- 2026-05-22: Added `QuicConnection.processProtectedLongDatagramInSpace()` and
  `pollProtectedLongCryptoDatagramInSpace()` to generalize the protected
  long-packet bridge from Initial to both Initial and Handshake packet number
  spaces. The Initial-specific wrappers remain for compatibility. Tests cover
  protected Handshake CRYPTO emit/decrypt/delivery, packet-number accounting,
  long-packet packet-type mismatch rollback, and Handshake token rejection
  before send-state mutation. `examples/crypto_stream.zig` now sends both the
  Initial and Handshake CRYPTO flights through protected long packets using
  caller-supplied keys. Endpoint Retry policy, 1-RTT protected
  transmit, TLS secret production, key discard, and key update remain pending.
- 2026-05-22: Added `QuicConnection.processProtectedLongDatagram()` and
  `ProtectedLongDatagramKeys` for coalesced protected long datagram receive
  routing. The method peeks each long-header packet boundary, verifies that all
  packet types are supported and have caller-supplied keys before mutation, then
  opens and routes each Initial or Handshake packet into its packet number
  space. Tests cover Initial+Handshake CRYPTO in one coalesced datagram and
  missing Handshake key rejection without earlier Initial-state mutation.
  `examples/crypto_stream.zig` now demonstrates a coalesced server Initial plus
  Handshake flight. Endpoint Retry policy, 1-RTT protected
  transmit, TLS secret production, key discard, and key update remain pending.
- 2026-05-22: Added `QuicConnection.pollProtectedLongDatagram()` for
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
  `QuicConnection.processProtectedShortDatagram()` for caller-supplied 1-RTT
  short-header packet receive. The connection API requires caller-provided
  destination-CID length context, opens one protected short datagram, requires
  the packet number to match the next expected Application packet number, and
  then routes plaintext through 1-RTT frame rules. Tests cover protected
  short-packet roundtrip, header-protection sample bounds, PING delivery into
  Application ACK state, packet-number mismatch rollback, and authentication
  failure without state mutation. `examples/crypto_stream.zig` now demonstrates
  a protected 1-RTT PING receive after modeled handshake confirmation. Retry
  routing, TLS secret production, key discard, and key update remain pending.
- 2026-05-22: Added `QuicConnection.pollProtectedShortDatagram()` for
  caller-supplied 1-RTT short-header PING/ACK transmit. The method protects
  Application-space PING plus optional ACK, or ACK-only state, checks
  congestion and anti-amplification budget, advances packet numbers, tracks
  bytes-in-flight only for ack-eliciting packets, and clears committed ACK/PING
  state. Tests cover a protected 1-RTT PING followed by an ACK-only protected
  response that removes the sender's bytes-in-flight. `examples/crypto_stream.zig`
  now demonstrates the protected 1-RTT PING/ACK exchange after modeled
  handshake confirmation. Endpoint Retry policy, TLS secret production, key discard,
  and key update remain pending.
- 2026-05-22: Extended `QuicConnection.pollProtectedShortDatagram()` to protect
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
- 2026-05-22: Extended `QuicConnection.pollProtectedShortDatagram()` to protect
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
- 2026-05-22: Extended `QuicConnection.pollProtectedShortDatagram()` to protect
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
- 2026-05-22: Extended `QuicConnection.pollProtectedShortDatagram()` to protect
  queued Application-space `PATH_RESPONSE` and outbound `PATH_CHALLENGE` frames
  with an optional ACK in 1-RTT short packets. PATH_RESPONSE queues are consumed
  only after send commit, while PATH_CHALLENGE is moved to outstanding
  validation state only after packet-number, congestion, and anti-amplification
  checks pass. Tests cover a protected PATH_CHALLENGE/PATH_RESPONSE/ACK
  roundtrip plus an anti-amplification block that preserves a pending
  PATH_CHALLENGE. `examples/path_validation.zig` now demonstrates the protected
  short-header path-validation exchange alongside the frame-payload retry
  examples. Endpoint Retry policy, TLS secret production, key discard, and key update
  remain pending.
- 2026-05-23: Added a protected path-validation and endpoint-routing
  integration test. A datagram arriving on a new UDP tuple is first reported as
  `path_changed`; only after the matching protected PATH_RESPONSE is processed
  does caller code commit `EndpointRouter.updateRoutePath()`, after which the
  same tuple routes without a path-change report. `examples/path_validation.zig`
  now prints the endpoint path-change and path-update result. Automatic
  socket-backed path-validation ownership remains pending.
- 2026-05-23: Extended `QuicConnection.pollProtectedShortDatagram()` to protect
  queued Application-space `RETIRE_CONNECTION_ID` frames and unsent local
  `NEW_CONNECTION_ID` frames with an optional ACK in 1-RTT short packets. The
  protected path consumes the RETIRE queue and marks local connection IDs as
  sent only after packet-number, congestion, and anti-amplification checks pass.
  Tests cover protected NEW/ACK, replacement NEW causing protected RETIRE+ACK,
  final ACK cleanup, and an anti-amplification block that preserves an unsent
  NEW_CONNECTION_ID. `examples/connection_ids.zig` now demonstrates the
  caller-keyed protected 1-RTT NEW_CONNECTION_ID/RETIRE_CONNECTION_ID exchange.
  Endpoint Retry policy, TLS secret production, key discard, and key update remain
  pending.
- 2026-05-23: Extended `QuicConnection.pollProtectedShortDatagram()` to protect
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
- 2026-05-23: Extended `QuicConnection.pollProtectedShortDatagram()` to protect
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
  then extended `QuicConnection.pollProtectedShortDatagram()` to protect queued
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
  packet-number sharing. Real TLS-backed early-data secret ownership,
  acceptance policy, replay defense, endpoint Retry policy, key discard, and key
  update remain pending.
- 2026-05-23: Added client-side `QuicConnection.processRetryDatagram()` for
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
- 2026-05-23: Added server-side `QuicConnection.issueRetryDatagram()` for
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
  `QuicConnection.issueAddressValidationToken()` and
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
  `QuicConnection.validateAddressValidationTokenWithSecrets()`. Callers can
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
  socket-backed preferred-address migration remains pending.
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
  client Initial Source CID routes, and verifies a short-header follow-up over
  the same real UDP sockets. It deliberately stops at endpoint routing; real
  protected-packet/TLS socket ownership remains pending.
- 2026-05-25: Added `examples/udp_protected_loopback.zig` and
  `zig build run-udp-protected-loopback`. The example sends caller-keyed
  protected client Initial and server Initial datagrams over real loopback UDP
  sockets, registers endpoint routes from the accepted Initial metadata, then
  routes and processes a protected 1-RTT PING/ACK exchange over the same
  sockets. This proves protected packet delivery through socket-backed endpoint
  routing, while TLS-owned key production and connection lifecycle ownership
  remain pending.
- 2026-05-25: Added `examples/udp_stateless_reset_loopback.zig` and
  `zig build run-udp-stateless-reset-loopback`. The example binds two loopback
  UDP sockets, retires a registered CID while retaining its stateless reset
  token, delivers a trigger datagram to the server socket, lets
  `EndpointRouter.handleDatagram()` classify it as a reset response, sends the
  reset datagram back, and verifies the client can match the retained token.
  Full socket-owned connection lifecycle integration remains pending.
- 2026-05-22: Added per-packet-number-space ECN validation state to
  `QuicConnection`. `recordEcnPacketSentInSpace()` records modeled ECT(0) or
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
- 2026-05-23: Made `checkPtoTimeouts()` prefer already queued ack-eliciting
  data before adding a PING probe. Due spaces still apply PTO backoff, but
  queued Application STREAM data, per-space CRYPTO, or other pending
  ack-eliciting frames can serve as the probe packet. Tests cover queued STREAM
  probe selection without adding a PING; full cloning of already-sent protected
  data for retransmission remains pending.
- 2026-05-25: Adjusted packet-number-space PTO calculation so Initial and
  Handshake spaces omit `max_ack_delay` while Application PTO keeps the existing
  peer-delay term. `recovery.Recovery.ptoMsWithoutMaxAckDelay()` exposes the
  timer basis, `ptoDeadlineMillis(.initial/.handshake)` now uses it, and
  `examples/pto_recovery.zig` prints the 310ms/320ms controlled-clock
  deadlines for 100ms initial RTT packets sent at 10ms/20ms.
- 2026-05-22: Added `examples/pto_recovery.zig` and
  `zig build run-pto-recovery`. The example demonstrates deadline gating,
  PTO-triggered PING queuing, Application PING emission through `pollTx()`,
  queued STREAM data serving as a PTO probe, and Initial/Handshake PING emission
  through `pollTxInSpace()`.
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
  transport-parameter rejection before outbound output, out-of-order Handshake
  CRYPTO delivery, chunked backend output queuing, handshake confirmation, and
  zero-length scratch-buffer rejection before consumption.
  `examples/crypto_stream.zig` now prints the mock backend bridge flow.
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
| `codec_roundtrip` | Varint, packet header, RFC 9369 QUIC v2 long-header type-bit mapping, short-header spin-bit preservation, long/short-packet envelope, header packet number truncation/reconstruction, packet number encoding, RFC 8999 Version Negotiation packet codec plus client-side VN selection and RFC 9368 downgrade-check state, frame, transport parameter including RFC 9368 `version_information`, connection parameter exposure including TLS extension bytes and server preferred_address, and transport error codec usage including `VERSION_NEGOTIATION_ERROR`. | Present |
| `crypto_stream` | Current out-of-order Handshake CRYPTO reassembly, mock `CryptoBackend` bridge delivery/output queuing/local-peer-TP handoff/Handshake, 0-RTT, and 1-RTT secret handoff/confirmation, backend-confirmed no-output Handshake discard, explicit handshake-state observability, protected Initial and Handshake CRYPTO transmit/receive bridge with valid first-client-Initial DCID and 1200-byte Initial datagram flows, installed-key Handshake and explicitly accepted 0-RTT long-packet exchanges, no-Retry Original DCID export/validation, local Initial SCID export through `localTransportParameters()`, coalesced server Initial+Handshake transmit/receive, peer Initial SCID capture with `initial_source_connection_id` validation, protected client Initial ACK-only plus Handshake PING/ACK probe, modeled handshake confirmation, caller-keyed protected 1-RTT PING/ACK, CRYPTO/ACK, STREAM/ACK, RESET_STREAM/ACK, STOP_SENDING/RESET_STREAM exchanges, ACK-gated installed-key 1-RTT key-update PING, caller-owned key-phase-state key-update PING, and configurable short-header spin-bit state. | Present |
| `initial_keys` | RFC 9001 QUIC v1 and RFC 9369 QUIC v2 Initial secret/key/IV/header-protection key derivation, RFC 9001 `quic ku` key-update derivation, protected Initial long-packet seal/open, and AES header-protection masking from a client Initial DCID. | Present |
| `endpoint_routing` | Current in-memory endpoint DCID/IPv4 UDP tuple routing, long-header DCID peeking, unsupported-version RFC 8999 Version Negotiation response generation, client Initial Source CID route registration, supported-version unknown-DCID Initial accept classification, accepted Initial Original DCID/server Initial SCID route registration, short-header registered-CID matching, zero-length CID tuple routing, Retry Source CID route switching, caller-validated preferred-address migration commit, sequence/retire-prior-to/connection-handle route retirement, stateless reset token reuse rejection, caller-validated path update, active-migration-disabled rejection, route retirement, stateless reset token lookup for inactive CIDs, reset datagram construction with caller-supplied unpredictable bytes, and route/version-negotiation/reset/drop/accept receive action classification. | Present |
| `udp_endpoint_loopback` | Socket-backed loopback UDP exercise for endpoint routing: unsupported-version Initial to Version Negotiation response delivery, client-side VN selection, supported Initial accept classification, client Initial Source CID response routing, accepted server Initial Source CID registration, and short-header registered-CID routing. | Present |
| `udp_zero_cid_loopback` | Socket-backed loopback UDP zero-length CID exercise: short and long datagram routing by UDP tuple identity, path-specific zero-CID retirement, and route path update to a new tuple. | Present |
| `udp_preferred_address_loopback` | Socket-backed loopback UDP preferred-address exercise: caller-validated preferred route commit, old-route retirement, preferred CID routing on the preferred server address, active-migration-disabled rejection on a stray path, and retained reset-token lookup after retirement. | Present |
| `udp_replacement_cid_loopback` | Socket-backed loopback UDP replacement CID exercise: NEW_CONNECTION_ID-style replacement route registration, retire_prior_to route retirement, inactive old-CID reset-token lookup, active replacement token suppression, invalid retire_prior_to rejection, and active-migration-disabled stray-path rejection. | Present |
| `udp_connection_ids_loopback` | Socket-backed loopback UDP connection ID exercise: protected NEW_CONNECTION_ID delivery, endpoint replacement route update, inactive old-CID reset-token lookup, protected RETIRE_CONNECTION_ID routed through the active replacement CID, server-side local CID retirement, and ACK cleanup. | Present |
| `udp_protected_loopback` | Socket-backed loopback UDP protected packet exercise: caller-keyed protected client Initial, server accept route registration, caller-keyed protected server Initial response, routed 1-RTT PING, and routed 1-RTT ACK. | Present |
| `udp_key_update_loopback` | Socket-backed loopback UDP key-update exercise: installed 1-RTT traffic secrets, local key update initiation, next key-phase PING routing, authenticated peer key-phase advancement, ACK delivery, and ACK-gated second-update re-enable. | Present |
| `udp_path_validation_loopback` | Socket-backed loopback UDP path-validation exercise: protected PATH_CHALLENGE delivery to a new peer port, PATH_RESPONSE routing with `path_changed`, caller-committed route path update after validation, and confirmed routing on the new path. | Present |
| `udp_retry_loopback` | Socket-backed loopback UDP Retry/address-validation exercise: server Retry delivery, Retry Source CID route switching, address-bound token validation with replay rejection, follow-up protected Initial routing, and Retry CID transport-parameter validation. | Present |
| `udp_close_lifecycle_loopback` | Socket-backed loopback UDP close lifecycle exercise: protected CONNECTION_CLOSE delivery, endpoint connection-handle route retirement, retained inactive-CID stateless reset token lookup, reset emission, and client token match. | Present |
| `udp_stateless_reset_loopback` | Socket-backed loopback UDP stateless reset exercise: trigger datagram for a retired CID, endpoint reset classification, server reset datagram send, and client token match. | Present |
| `udp_echo_client` / `udp_echo_server` | Real QUIC-over-UDP/TLS stream echo. | Planned |
| `uni_stream` | Current in-memory unidirectional stream send/receive, direction validation, duplicate STREAM retransmission discard, and FIN completion observability. | Present |
| `stream_reset` | Current local RESET_STREAM emission, final-size observability, unsent STREAM drop behavior, and late STREAM ignore after reset. | Present |
| `stop_sending` | Current local STOP_SENDING emission, peer RESET_STREAM response, Data Recvd suppression, pre-STREAM STOP_SENDING on peer-initiated bidirectional streams, and implicit lower-numbered receive stream creation. | Present |
| `flow_control` | Connection, stream, stream-count, receive-side MAX, configurable target receive windows, completed-stream MAX_STREAMS, peer-BLOCKED MAX retransmission/growth, pre-STREAM MAX_STREAM_DATA on peer-initiated bidirectional streams with implicit lower-numbered receive stream creation, final-size MAX_STREAM_DATA suppression, stale STREAM_DATA_BLOCKED suppression, and caller-keyed protected short MAX/BLOCKED exchange behavior. | Present |
| `graceful_close` | Current in-memory and caller-keyed protected short CONNECTION_CLOSE/APPLICATION_CLOSE send/receive, peer close diagnostics, retransmission, and closing/draining state behavior. | Present |
| `idle_timeout` | Current max_idle_timeout transport parameter application, activity deadline refresh, and active-to-closed expiry. | Present |
| `packet_spaces` | Current frame-payload Initial/Handshake/Application ACK/recovery isolation, RFC 9001 Initial discard, Initial/Handshake discard cleanup, 0-RTT packet-type filtering, and caller-keyed protected 0-RTT STREAM delivery. | Present |
| `path_validation` | Current frame-payload PATH_CHALLENGE timeout retry, success, retry exhaustion, caller-keyed protected 1-RTT PATH_CHALLENGE/PATH_RESPONSE exchange, and endpoint route path update after protected PATH_RESPONSE validation. | Present |
| `connection_ids` | Current local NEW_CONNECTION_ID issuing with stateless-reset-token uniqueness checks, peer RETIRE_CONNECTION_ID handling, endpoint replacement-CID registration with retire_prior_to route retirement, and caller-keyed protected 1-RTT NEW_CONNECTION_ID/RETIRE_CONNECTION_ID exchange. | Present |
| `stateless_reset` | Current constant-time stateless reset token match, false-positive rejection, and endpoint inactive-CID reset action construction. | Present |
| `ecn_validation` | Current frame-payload ECT send modeling, ACK_ECN counter validation, and endpoint path-identity ECN state isolation. | Present |
| `loss_recovery` | Current frame-payload packet-threshold loss, time-threshold loss, NewReno recovery period, persistent congestion, and ACK-delay handling. | Present |
| `pto_recovery` | Current frame-payload Initial/Handshake/Application PTO hooks, including Initial/Handshake max_ack_delay suppression, PING fallback probes, and queued STREAM data probe selection. | Present |
| `address_validation` | Current modeled server anti-amplification budget, explicit peer-address validation, protected HANDSHAKE_DONE/NEW_TOKEN delivery, server-side HANDSHAKE_DONE-triggered Handshake discard, endpoint peer-address binding, `AddressValidationPolicy` NEW_TOKEN issue/rotation/originating-version binding/secret-set and replay-filter export/restore/validation/replay rejection, and address-validation unblocking. | Present |
| `retry_token` | Current v1/v2 Retry packet integrity-tag encode/verify/parse, server-side Retry datagram issuance, client-side Retry datagram processing, Retry CID transport-parameter validation/export, endpoint peer-address binding, `AddressValidationPolicy` Retry token issue/path validation, one-time Retry token consumption, and address-validation unblocking. | Present |
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
zig build run-endpoint-routing
zig build run-udp-endpoint-loopback
zig build run-udp-zero-cid-loopback
zig build run-udp-preferred-address-loopback
zig build run-udp-replacement-cid-loopback
zig build run-udp-connection-ids-loopback
zig build run-udp-protected-loopback
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
