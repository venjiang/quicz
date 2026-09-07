# P2P Connectivity Spike

Status: experimental; not a production NAT-traversal API.

## Goal

Keep QUIC transport separate from connectivity discovery while proving that
quicz can provide the data plane for mobile peer-to-peer applications.

```text
application control plane
        |
connectivity: candidates, STUN, hole punching, relay fallback
        |
quicz: TLS 1.3, QUIC streams, recovery, migration, multipath
```

Application identities, sessions, authorization, and payload semantics remain
outside quicz.

## Implemented in the first checkpoint

- `mobile-static` builds an arm64 iOS static library and installs
  `quicz_mobile.h`.
- ABI v1 exposes version/capability negotiation and blocking verified TLS
  client lifecycle: create, connect, discover, open stream, send, receive,
  close, and destroy. Swift callers must run blocking operations off the main
  thread.
- Swift can import the C header when compiling for iPhoneOS.
- `connectivity.path_selector` selects the first validated path, migrates to a
  meaningfully faster path, falls back when the active path fails, and applies
  RTT hysteresis to avoid flapping.
- `connectivity.stun` encodes RFC 8489 Binding requests and decodes matching
  IPv4/IPv6 XOR-MAPPED-ADDRESS success responses.
- `connectivity.stun_transaction` runs a bounded Binding transaction with at
  most five attempts on a caller-owned socket.
- `connectivity.punch_wire` authenticates idempotent probe/ack packets with a
  short-lived rendezvous key and rejects tampering before path routing.
- `runtime.Client.initWithSocket` takes ownership of a caller-bound IPv4 UDP
  socket, preserving the NAT mapping created during discovery.
- The shared-socket loopback proves STUN discovery and a QUIC
  stream echo use the same client UDP port.
- The P2P loopback proves both peers send authenticated probes before receive,
  validate acknowledgements, transfer those sockets into the QUIC client and
  server, verify the server certificate, and exchange a stream without port
  changes.

Build the mobile boundary:

```bash
zig build mobile-static \
  -Dtarget=aarch64-ios \
  -Doptimize=ReleaseSafe \
  --prefix /tmp/quicz-ios
```

## Deliberately not implemented yet

- Real STUN service and cellular-network validation.
- Candidate-pair scheduling and full UDP hole-punch orchestration.
- Rendezvous and relay datagram protocols.
- An iOS API for transferring a discovery-owned socket into QUIC.
- iOS lifecycle and real cellular-network validation.
- Seamless migration of an established application stream between relay and
  direct paths.

The capability mask must not advertise these unfinished features.

## Acceptance sequence

1. Preserve the complete QUIC regression suite and UDP path-validation demo.
2. Compile and import the arm64 iOS static library from Swift.
3. Add an owned UDP socket that can run STUN and then drive QUIC on the same
   local port. Completed in the loopback spike.
4. Prove authenticated stream echo across iPhone and Host.
5. Add bounded direct probing with immediate relay fallback.
6. Compare connection success and latency against an isolated Iroh reference
   under the same LAN, Wi-Fi, cellular, CGNAT, UDP-blocked, and network-change
   matrix.

References: [RFC 8489](https://www.rfc-editor.org/info/rfc8489/),
[RFC 8445](https://www.rfc-editor.org/info/rfc8445/), and
[RFC 9000](https://www.rfc-editor.org/info/rfc9000/).
