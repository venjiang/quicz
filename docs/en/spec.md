# quicz implementation scope

`quicz` aims to implement the IETF QUIC transport protocol as defined by the QUIC WG at <https://quicwg.org/>.

Initial target documents:

- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control
- RFC 9369: QUIC Version 2

## Phase 1: Minimal but correct subset

- Single-path, IPv4 only
- Fixed QUIC version for now
- Basic packet/header parsing and serialization
- One connection per UDP 4-tuple
- Basic stream support, send-side STREAM fragmentation, inbound RESET_STREAM and STOP_SENDING handling, minimal PATH_CHALLENGE/PATH_RESPONSE handling, client-side HANDSHAKE_DONE handling, flow-control and stream-count limits, strict stream direction validation, and close-state handling
- Transactional processing for malformed in-memory frame payloads so partial receive, recovery, flow-control, and close-state updates roll back on failure
- Simplified loss detection and congestion control with automatic ACK generation, ACK range handling, unsent-packet ACK rejection, and sent-packet tracking

## Current implementation status

- Implemented: QUIC varint helpers, minimal long/short header codecs, and basic frame codecs for STREAM, CRYPTO, PADDING, PING, ACK/ACK_ECN with additional ranges, RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS_BIDI/UNI, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED_BIDI/UNI, NEW_TOKEN, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE/PATH_RESPONSE, HANDSHAKE_DONE, and connection-close variants.
- `QuicConnection` implements an in-memory stream send/receive skeleton with send-side STREAM fragmentation, contiguous receive buffers, inbound RESET_STREAM handling, STOP_SENDING-to-RESET_STREAM response handling, minimal PATH_CHALLENGE response queuing, HANDSHAKE_DONE role validation, basic connection and stream flow control, bidirectional and unidirectional stream-count limits, close-state handling for CONNECTION_CLOSE/APPLICATION_CLOSE, automatic ACK generation for ACK-eliciting payloads, ACK-only emission, ACK coalescing with STREAM/PATH_RESPONSE/RESET_STREAM frames when space allows, ACK-driven sent-packet tracking, and a simplified recovery/congestion state object.
- Locally initiated bidirectional streams must be created with `openStream()` before `sendOnStream()`. `openStream()` enforces the peer's bidirectional stream limit until a larger MAX_STREAMS_BIDI frame is received.
- Locally initiated unidirectional streams must be created with `openUniStream()` before `sendOnStream()`. `openUniStream()` enforces the peer's unidirectional stream limit until a larger MAX_STREAMS_UNI frame is received.
- `sendOnStream()` accepts observed peer-initiated bidirectional streams so the in-memory echo examples can reply on the peer's stream, and it accepts opened locally initiated unidirectional streams. It rejects unobserved peer-initiated streams, locally initiated streams that were not opened, peer-initiated unidirectional stream IDs, streams that already sent FIN, and flow-control-blocked writes.
- `processDatagram()` accepts modeled bidirectional STREAM/RESET_STREAM receive state and peer-initiated unidirectional STREAM/RESET_STREAM receive state. It rejects inbound local bidirectional stream IDs that were not opened, inbound local unidirectional stream IDs, peer-initiated streams beyond receive stream-count limits, out-of-order new stream data, data after final size, inconsistent RESET_STREAM final sizes, oversized frame payloads, and ACKs for packet numbers that were never sent.
- Inbound `STOP_SENDING` is accepted only for streams where this endpoint has a send side. It closes that send side, queues a `RESET_STREAM` with the current final size, drops unsent queued STREAM data for that stream after the reset is emitted, and ignores duplicate stop requests once a reset is queued.
- Inbound `HANDSHAKE_DONE` is accepted only by client connections. Server-side receipt fails the payload as invalid and rolls back any earlier changes from that payload.
- Invalid multi-frame payloads roll back state changed earlier in that payload, including receive buffers, RESET_STREAM state, queued PATH_RESPONSE/RESET_STREAM values, MAX_DATA/MAX_STREAMS_BIDI/UNI updates, pending ACK state, sent-packet recovery state, and close-state changes.
- Current `pollTx` / `processDatagram` behavior moves unencrypted QUIC frame payload bytes. `pollTx` may emit ACK-only payloads, queued PATH_RESPONSE or RESET_STREAM payloads, or coalesce a pending ACK with STREAM/PATH_RESPONSE/RESET_STREAM data, but it does not yet produce or consume protected QUIC packets over UDP.
- Not implemented yet: TLS 1.3 integration, packet protection, distinct packet number spaces, full RFC 9002 loss timers and packet-threshold loss detection, UDP 4-tuple connection ownership, out-of-order stream reassembly, QUIC v2 behavior, full path migration policy, and stateless reset.

Further phases will extend towards full RFC coverage.
