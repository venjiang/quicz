# quicz implementation scope

`quicz` aims to implement the IETF QUIC transport protocol as defined by the QUIC WG at <https://quicwg.org/>.

Initial target documents:

- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control

## Phase 1: Minimal but correct subset

- Single-path, IPv4 only
- Fixed QUIC version for now
- Basic packet/header parsing and serialization
- One connection per UDP 4-tuple
- Basic stream support
- Simplified loss detection and congestion control

Further phases will extend towards full RFC coverage.
