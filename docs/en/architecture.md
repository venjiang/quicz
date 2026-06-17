# quicz Architecture and Terminology

This document explains quicz terminology, module boundaries, core protocol
flows, and extension entry points. The verifiable task plan is in
[`quic_transport_tasks.md`](quic_transport_tasks.md), and detailed per-feature
notes are in [`spec.md`](spec.md).

## Current Scope

quicz currently focuses on the QUIC transport core: connection state, packet
protection, CRYPTO/STREAM frames, transport parameters, ACK/loss/PTO,
congestion control, connection IDs, path validation, Retry, stateless reset,
and endpoint lifecycle. TLS is integrated through a narrow adapter around an
external C TLS library. quicz does not implement TLS in-tree.

In this document, "core protocol flow" means internal transport state changes.
It does not refer to an application domain. HTTP/3, QPACK, DATAGRAM, the full
interop matrix, and a production socket API remain tracked in the task plan.

## Key Terms

- Endpoint: the UDP endpoint and connection lifecycle owner. It routes datagrams
  by connection ID and path, and owns route cleanup, timers, and stateless reset
  state.
- Connection: one QUIC transport state machine. It handles packet number spaces,
  frames, streams, transport parameters, close state, and recovery state.
- Connection ID: the QUIC routing identifier. DCID means destination connection
  ID on a packet; SCID means source connection ID.
- Path: the local/remote UDP address pair plus its validation state. Path
  validation, migration, Retry, and address validation are built around this
  boundary.
- Packet number space: Initial, Handshake, or Application. Each space owns
  independent ACK, CRYPTO data, and key lifecycle state.
- CRYPTO stream: the QUIC transport carrier for TLS handshake bytes. It is not
  an application stream, but it uses stream-like offsets for reassembly.
- Stream: an application data channel, bidirectional or unidirectional, governed
  by flow control, reset, STOP_SENDING, and the stream state machine.
- Transport parameters: QUIC handshake configuration such as stream limits,
  ACK delay, max UDP payload size, preferred_address, and version information.
- TLS backend: the adapter around the external TLS library. The backend owns the
  TLS transcript, traffic secrets, and QUIC TLS callbacks. quicz packetizes
  CRYPTO bytes, installs packet protection keys, and drives transport state.
- Traffic secrets: TLS-produced inputs for Handshake and 1-RTT packet protection
  keys. quicz derives packet protection keys from them and does not print key
  material.
- Packet protection: QUIC AEAD encryption and header protection. quicz has
  helpers for Initial, Handshake, 1-RTT, Retry integrity, and key update paths.
- Recovery: ACK, loss detection, PTO, and congestion control. The current model
  is covered by deterministic tests for key branches.
- Stateless reset: a short-packet mechanism that lets an endpoint stop a peer
  when no connection is found but a reset token can be matched.
- Handshake recording: the OpenSSL client/server record used by examples to
  verify TLS callbacks, transport-parameter bytes, traffic secrets, and CRYPTO
  handoff. It is internal verification evidence, not user logging and not a
  full packet capture format.

## System Architecture

### Public Library Layer

The public library layer exposes `Connection`, configuration, stream APIs, frame
codec, transport-parameter codec, and recovery state. It should keep transport
semantics explicit and avoid leaking concrete TLS-library details, socket
scheduling policy, or example fixtures into core APIs.

`src/lib.zig` is the root source file for the public `quicz` module. It should
remain the public aggregation point for exported names and compatibility aliases.
Implementation code moves under `src/quic/` by responsibility; for example,
`src/quic/transport_types.zig` owns shared transport state enums and version
compatibility helpers, `src/quic/crypto_types.zig` owns shared TLS
traffic-secret and backend-progress types, `src/quic/endpoint_types.zig` owns
endpoint lifecycle result, deadline, drain, feed, and datagram option contracts,
`src/quic/connection_config.zig` owns public connection configuration and
fixed-storage transport-parameter values that do not need access to the
connection state machine,
`src/quic/connection_state.zig` owns internal connection bookkeeping records
such as pending STREAM/CRYPTO frames, sent-packet metadata, pending close and
flow-control frames, path-challenge state, RTT/PTO snapshots, and connection-ID
rollback snapshots,
`src/quic/connection_version.zig` owns version-list selection and local
RFC 9368 version-information validation policy,
`src/quic/packet_context.zig` owns packet-type context, caller-supplied
protected long-packet key bundles, and modeled ECN validation enums,
`src/quic/protocol_limits.zig` owns shared QUIC scalar limits such as varint,
stream-count, connection-ID, Initial datagram, path-validation, and
anti-amplification bounds,
`src/quic/wire_len.zig` owns QUIC varint, protected datagram, and frame
wire-length budgeting used by send-path padding, coalescing, and bounded output
sizing,
and `src/quic/tls_backend.zig` owns the C-ABI TLS adapter while `lib.zig`
re-exports the stable public surface.

When moving implementation code out of `src/lib.zig`, keep the public module
root stable and add explicit `test` imports for files whose tests must be
discovered by `zig build test`. This preserves `@import("quicz")` call sites
while letting implementation modules grow by transport responsibility.

### Module Split Policy

Zig source files are namespaces, and the build script decides the public module
root. quicz therefore keeps `src/lib.zig` as the stable root and re-export
layer, while implementation files under `src/quic/` own coherent transport
responsibilities. A split is appropriate when a group of types and functions has
one protocol owner, stable internal dependencies, and tests that can be moved
with it without changing the public `@import("quicz")` surface.

Recommended split order:

1. Move pure helpers and data contracts first, such as wire-length helpers,
   stream bookkeeping types, recovery snapshots, and packet-context helpers.
2. Move stateful subdomains after their data contracts are isolated, such as
   stream send/receive state, connection ID state, path validation, ECN, and
   loss recovery.
3. Move endpoint lifecycle orchestration last, because it ties connection
   storage views, route state, timers, backend drive, and output polling
   together.
4. Keep tests next to the implementation they validate, and keep root-level
   test imports in `src/lib.zig` so `zig build test` continues to discover them.

Avoid catch-all files such as `utils.zig`, `helpers.zig`, or `state.zig`.
Names should be meaningful in their fully-qualified Zig namespace.

### Packet Protection Layer

The packet protection layer owns long/short packet coding, AEAD, header
protection, Retry integrity, installed-key packet send/receive helpers, and key
phase state. It consumes already installed keys and does not care whether those
keys came from a mock backend or a C TLS backend.

### TLS Integration Boundary

The TLS boundary is made of the Zig `TlsBackend`/`CryptoBackend` wrappers and
translate-c generated C bindings. The build uses Zig 0.16's recommended
`addTranslateC` + `@import("c")` path, rather than handwritten C ABI
`extern fn` or `extern struct` declarations.

The TLS backend is responsible for:

- accepting quicz-encoded local transport parameters;
- consuming TLS handshake bytes from QUIC CRYPTO frames;
- producing the next TLS CRYPTO bytes;
- exposing peer transport parameters and traffic secrets through callbacks;
- notifying quicz when TLS considers the handshake confirmed.

quicz is responsible for:

- packetizing TLS CRYPTO bytes into the right packet number space;
- installing packet protection keys from traffic secrets;
- applying peer transport parameters to connection state;
- managing ACK, loss, PTO, streams, close, and route cleanup.

### Endpoint Lifecycle Layer

The endpoint layer owns the socket-facing lifecycle: connection lookup by DCID
and path, route creation and retirement, connection timer service, stateless
reset delivery, and closed-connection cleanup. The production socket API is
still in progress, while loopback examples already cover several key paths.

### Examples and Verifiers

The `examples/` directory verifies that core capabilities can run
independently. Each example should print stable evidence lines that can be
checked without exposing key material. When adding a feature, land the core
implementation and unit coverage first, then use a verifier to prove the same
behavior runs end to end.

## Core Protocol Flows

### Datagram Receive Path

1. The endpoint receives a UDP datagram.
2. The endpoint resolves DCID/path routing or enters the Retry, stateless-reset,
   or unknown-CID branch.
3. The connection removes packet protection and dispatches frames by packet
   number space.
4. CRYPTO frames go to the TLS backend; STREAM, ACK, RESET, and close frames
   update transport state.
5. Recovery updates ACK, loss, PTO, and congestion state.
6. The caller or endpoint lifecycle polls outbound datagrams.

### TLS Handshake Path

1. quicz exports local transport parameters and configures the TLS backend.
2. The TLS backend produces Initial CRYPTO bytes.
3. quicz sends those CRYPTO bytes in an Initial packet.
4. When peer CRYPTO arrives, quicz delivers it to the TLS backend for that
   packet number space.
5. The TLS backend calls back with peer transport parameters, Handshake secrets,
   1-RTT secrets, and handshake confirmation.
6. quicz applies peer transport parameters, installs packet protection keys, and
   discards old packet number spaces when the boundary is reached.

### 1-RTT Stream Path

1. The application or example opens a stream and writes data.
2. The connection emits STREAM frames according to flow control and stream state.
3. The packet protection layer creates a short packet.
4. The endpoint sends the datagram and recovery tracks in-flight bytes.
5. The peer removes protection, reassembles stream data, ACKs it, and can emit a
   response STREAM frame.

### Close and Cleanup Path

1. The connection enters application close, transport close, idle timeout, or
   stateless reset handling.
2. quicz emits CONNECTION_CLOSE or reset-related output.
3. The endpoint suppresses routes that must not send again and removes routing
   state for the closed connection.
4. Recovery and timers stop producing send-side effects for cleaned-up routes.

## Extension Entry Points

- New transport frame or parameter: start with `src/frame.zig`, the transport
  parameter codec, and the matching entry in `docs/en/quic_transport_tasks.md`.
- New endpoint behavior: start with endpoint lifecycle code, route cleanup,
  stateless reset, and loopback examples.
- New TLS backend capability: keep the C TLS library behind the adapter
  boundary; extend the `TlsBackend` wrapper and OpenSSL verifier before changing
  transport core.
- New recovery behavior: define a deterministic test first, then add example
  evidence. Do not add retries to non-idempotent send paths without a clear
  basis.
- New documentation: README is for user-facing entry points; `docs/` is for
  developer design, terminology, troubleshooting, and module boundaries.

## Troubleshooting Entry Points

- Build or test failures: run `zig build test --summary all`, then narrow to the
  relevant `run-*` example.
- TLS/OpenSSL failures: start with `zig build run-tls-openssl-probe`,
  `zig build run-tls-openssl-pair-transcript`, and
  `zig build run-tls-openssl-backend-adapter`.
- Packet protection failures: check whether Initial, Handshake, and 1-RTT keys
  are installed in the correct packet number space.
- Endpoint routing failures: check DCID, route retirement, path identity, and
  stateless reset token state.
- Recovery failures: check ACK generation, in-flight bytes, PTO timer, and the
  congestion window.
