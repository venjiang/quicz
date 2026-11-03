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
- ABI v1 exposes version/capability negotiation and a blocking verified TLS
  client lifecycle: create, bounded connect, discover, open stream, send,
  receive, close, and destroy. Swift callers must run blocking operations off
  the main thread. P2P candidates must use `connect_timeout` so a silent UDP
  path cannot retain a route-race task forever.
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
- `connectivity.punch_attempt` requires authenticated traffic in both
  directions, rejects stale attempts and wrong nonces, and applies an
  exponential retry schedule capped at five probes.
- `connectivity.punch_driver` drives that state machine against one remote
  endpoint without taking socket ownership.
- `connectivity.ephemeral_identity` creates a 15-minute self-signed Ed25519
  identity entirely in memory, without an external certificate tool, and
  clears its private seed on release. `runtime.Server` accepts an explicit
  private-key algorithm, and the P2P loopback verifies the exact DER trust
  anchor for this short-lived identity.
- `connectivity.candidate` validates bounded host/reflexive/relay candidate
  sets, rejects wildcard and multicast endpoints, creates only same-family
  pairs, applies the RFC 8445 pair-priority formula, and caps pair growth.
- `runtime.Client.initWithSocket` takes ownership of a caller-bound IPv4 UDP
  socket, preserving the NAT mapping created during discovery.
- The shared-socket loopback proves STUN discovery and a QUIC
  stream echo use the same client UDP port.
- The P2P loopback proves both peers send authenticated probes before receive,
  validate acknowledgements, transfer those sockets into the QUIC client and
  server, verify the freshly generated short-lived server certificate exactly,
  and exchange a stream without port changes. One macOS loopback sample
  measured 229 microseconds for the bidirectional probe and 29.686 milliseconds
  for QUIC handshake plus echo;
  these are regression evidence, not real-network performance claims.
- A Swift benchmark running in iOS Simulator used the XCFramework C ABI to
  connect to a real Host listener, verify its certificate, and complete 100
  serial 8-byte echoes on one bidirectional stream. One Debug sample measured
  53.524 ms for the handshake and 9.863/18.339/23.116 ms for p50/p95/p99 RTT.
- A Swift benchmark on a physical iPhone 14 Pro used the same XCFramework C
  ABI to complete authenticated bidirectional probes on both peers' UDP
  sockets, transfer those sockets directly into verified QUIC, complete 100
  serial 8-byte echoes, close, and release the Host connection state. One
  Debug Wi-Fi sample measured 6.882 ms for the probe, 21.458 ms for the
  handshake, and 13.030/17.551/22.583 ms for p50/p95/p99 RTT.

The original iPhoneOS Debug binary copied the roughly 190 KiB `Client` value
through a roughly 512 KiB Swift concurrency worker stack during
`quicz_mobile_client_create`, causing SIGBUS. The C ABI now uses a short-lived
internal 8 MiB thread only for construction. The same 512 KiB stack regression
test changed from a deterministic crash to passing, and the physical-iPhone
benchmark now passes from a normal Swift Task. The public ABI and Client
lifecycle are unchanged.

Build the mobile boundary:

```bash
zig build mobile-static \
  -Dtarget=aarch64-ios \
  -Doptimize=ReleaseSafe \
  --prefix /tmp/quicz-ios
```

Build an XCFramework containing arm64 iPhoneOS and arm64 Simulator slices:

```bash
scripts/build_mobile_xcframework.sh zig-out/QuiczMobile.xcframework
```

The generated XCFramework contains separate `ios-arm64` and
`ios-arm64-simulator` slices with the same public header.

For the physical-device benchmark, the Host waits for a probe authenticated by
the short-lived key and attempt ID, learns the Device endpoint only from that
valid packet, sends the reverse probe, and starts QUIC on the same socket:

```bash
zig build run-mobile-latency-server -- 4433 passive-punch
```

The bound-endpoint ABI can return `0.0.0.0` for a wildcard socket. Platform
candidate gathering must combine the bound port with reachable interface
addresses; it must never advertise the wildcard address to a peer.

## Active-session Migration Hardening

Status: in progress. The initiation guard is locally tested. These slices
do not establish production roaming.

The first slice targets automatic challenge initiation in the installed-key
lifecycle feed. Connection already authenticates and deduplicates packets,
but its receive call can succeed after silently discarding a replay. The
feed must not treat that return alone as new migration traffic.

The Application receive cursor must advance before a changed tuple can
start an automatic challenge. Exact replays and older packet numbers must
not start validation. Ordinary receive processing remains responsible for
ordered stream delivery, ACKs and deduplication. Fresh highest packets must
still enter the existing validation flow.

Acceptance checks cover literal ciphertext replay, reordered authenticated
STREAM data and a fresh-highest positive control. The replay regression
failed before the guard and passed after it. Reordered data is still
delivered once. The fresh positive control still queues a challenge without
committing an unvalidated route. Related path/response checks passed 27/27,
and the local complete suite passed 2025/2025.

The existing controlled-NAT matrix also completed: unchanged-path controls,
five replacement-port trials and the loss control passed. The old pinned
runtime's rebind and the candidate's blackhole control timed out as expected.
This is local regression evidence, not a new physical-network acceptance.

This guard uses existing receive state. It adds no candidate table, retry
engine or public interface.

Automatic candidate ownership is the next slice below. Explicit manual
probes still use their prior count-based commit policy. Probing-only
packet rules, retry output, amplification and CID coherence need later
slices before production integration. The local reference
[quic-go path manager](https://github.com/quic-go/quic-go/blob/add7529015e46cda13441129d3081020f1baddc1/path_manager.go)
associates tokens with path records, then separately decides whether to
switch. It does not justify committing the tuple carrying any matching
response. No reference source code is copied into this implementation.

### Automatic Validation Ownership

Status: local validation and independent review passed. Production
integration remains pending. The explicit-commit regression failed before
the correction and passed after it.

[RFC 9000 sections 8.2.2 and 8.2.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.3)
allow a matching response on any path. That response validates the path
where the challenge was sent. Its source does not acquire that validation.
The earlier plan to reject every response from a different tuple was
incorrect. Candidate ownership must survive such a response.

The installed-key feed retains one automatic candidate per connection
handle: its tuple, token and validation state. Connection retains the
existing challenge queues, retry count and PTO. Its scoped receive
observation reports consumption of one exact token. Multiple response
frames cannot replace an earlier match. The observation ends when receive
returns, including errors. No second parser or retry engine is added.

| Input while B is the candidate | Validation | Route |
| --- | --- | --- |
| B's matching response arrives on B with a new highest number. | B succeeds. | Commit B. |
| B's matching response arrives on A or C. | B succeeds. | Keep A. |
| B later sends a new highest packet. | Retain B's success. | Commit B. |
| A replay or lower packet number arrives on B. | Keep its existing status. | Keep A. |
| Another probe's valid response arrives. | Do not validate B. | Keep A. |
| Authentication or frame processing fails. | Do not record success. | Keep A. |
| B's challenge enters the existing retry queue. | Retain B and its token. | Keep A. |
| B's retries expire. | Remove B before processing the next input. | Keep A. |
| An explicit commit selects D while B is validated. | Remove B's success. | Keep D. |
| An explicit commit selects D while B is pending. | Mark B superseded until its token is consumed or expires. | Keep D. |
| A superseded B response arrives, even with a new highest number. | Consume the old token without starting a candidate. | Keep D. |
| The connection is retired. | Remove its candidate. | Retire its routes. |

The caller supplies fresh unpredictable tokens for distinct attempts.
Candidate storage is bounded by connection handles. Capacity is reserved
before a challenge is queued. The shared successful route-commit helper
supersedes earlier automatic ownership. It leaves unrelated probes intact.
Without an automatic owner, manual probes retain their prior feed policy.
Explicit lower-level migration helpers keep their compatibility behavior. Timer-only cleanup,
candidate output policy and multiple CID commits remain separate work.
These checks do not establish production roaming or physical-network
acceptance, and they do not change Mons dependency pins.

Final related checks passed 32/32. The complete suite passed 2029/2029.
The actual multi-connection example completed all four handlers and
reclaimed every runtime connection. The controlled-NAT matrix passed its
eight positive cases. Both negative controls timed out as expected.

## Deliberately not implemented yet

- Real STUN service and cellular-network validation.
- Relay-mediated candidate exchange and real-NAT hole-punch validation.
- Rendezvous and relay datagram protocols.
- Physical-iPhone lifecycle and real cellular-network validation.
- Seamless migration of an established application stream between relay and
  direct paths.

The capability mask must not advertise these unfinished features.

## Acceptance sequence

1. Preserve the complete QUIC regression suite and UDP path-validation demo.
2. Compile and import the arm64 iOS static library from Swift.
3. Add an owned UDP socket that can run STUN and then drive QUIC on the same
   local port. Completed in the loopback spike.
4. Prove authenticated stream echo across iPhone and Host. Completed.
5. Add bounded direct probing with immediate relay fallback. Same-socket direct
   probing is complete; parallel Relay fallback remains open.
6. Compare connection success and latency against the Mons WSS Relay baseline
   under the same LAN, Wi-Fi, cellular, CGNAT, UDP-blocked, and network-change
   matrix.

References: [RFC 8489](https://www.rfc-editor.org/info/rfc8489/),
[RFC 8445](https://www.rfc-editor.org/info/rfc8445/), and
[RFC 9000](https://www.rfc-editor.org/info/rfc9000/).
