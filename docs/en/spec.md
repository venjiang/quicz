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
- Basic stream support and flow-control limits
- Simplified loss detection and congestion control with sent-packet tracking

## Current implementation status

- Implemented: QUIC varint helpers, minimal long/short header codecs, basic frame codecs (STREAM, CRYPTO, PADDING, PING, ACK with additional ranges, RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS_BIDI/UNI, and connection-close variants), an in-memory `QuicConnection` stream send/receive skeleton, basic connection/stream flow control, ACK-driven sent-packet tracking, and a simplified recovery/congestion state object.
- Current `pollTx` / `processDatagram` behavior moves unencrypted QUIC frame payload bytes. It does not yet produce or consume protected QUIC packets over UDP.
- Not implemented yet: TLS 1.3 integration, packet protection, distinct packet number spaces, full RFC 9002 loss timers and packet-threshold loss detection, UDP 4-tuple connection ownership, QUIC v2 behavior, path migration, and stateless reset.

Further phases will extend towards full RFC coverage.
