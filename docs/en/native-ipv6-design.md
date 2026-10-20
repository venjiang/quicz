# Native IPv6 with IPv4 source compatibility

## Goal and boundaries

Add a native IPv6 QUIC path for Mons. Keep every existing IPv4 Zig entry point, field type, result type, runtime configuration, and C ABI source compatible. In particular, existing code that reads `client.path.remote.octets` must continue to compile with four octets.

Use one implementation for each routing, lifecycle, TLS endpoint, and runtime algorithm. Parameterize the address-dependent types at compile time. Keep the existing public names as IPv4 specializations. Add explicit IPv6 specializations. Do not duplicate the QUIC stack or keep a second, fabricated IPv4 path beside an active IPv6 path.

This phase does not add cross-family connection migration, IPv6 HTTP/3, a new relay, or a second TLS implementation. Mons will select between separate IPv4 and IPv6 transports before consuming its stream authorization. Existing HTTP/3 entry points continue to use the original IPv4 specialization.

## Existing behavior and reference audit

The baseline is `193776feadcf64a2a47eb9dfbb5a1a49f2218acc`. Its endpoint path is `Udp4Tuple`. Runtime constructors reject IPv6 sockets, and receive and send paths reconstruct IPv4 addresses. Candidate discovery and punch code already carry IPv6 addresses. Their support does not make the QUIC endpoint IPv6 capable.

The audit used local quic-go revision `add7529015e46cda13441129d3081020f1baddc1`. Its path identity includes peer IP and port. Its receive path retains the local destination and interface. Its token binding differs from quicz, so that policy will not be copied.

[RFC 9000 section 8.1.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4) defines token integrity requirements. The existing quicz IPv4 binding remains the same six network-order bytes. [Section 8.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2) requires path validation before a new path is trusted. [Section 14.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1) requires Initial datagrams of at least 1200 bytes. The earlier 56-byte cellular UDP result cannot satisfy QUIC acceptance.

The unmodified full baseline passed 1948 of 1950 tests. The retransmitted-ACK test failed with `Timeout` and failed again in isolation. The peer-learning deadline test expected two probes but observed one in the full run, then passed in isolation. These failures predate this change. Their logs are under `/private/tmp/quicz-cellular-ipv6.nIR61g/`. Do not classify a later unchanged failure as an IPv6 regression.

The new runtime tests also make the old client probe test reachable from the library test root. That test sent packets to the wildcard bind address `0.0.0.0` and failed with `HostUnreachable`. An untouched source export of the baseline reproduced the same failure. The test now sends to loopback at the bound port. Production IPv4 binding remains unchanged.

The runtime fixtures reuse the existing PEM decoder. This makes its eight existing tests reachable as well. One test still called the pre-0.16 zero-argument key generator. It now passes `testing.io` as required by Zig 0.16. No PEM production code changes.

## Address and type ownership

Keep `Udp4Address`, `Udp4Tuple`, and their methods unchanged. Add `Udp6Address` with sixteen octets, a UDP port, and a scope ID. Add `Udp6Tuple` with one local and one remote address. Equality includes all octets, both ports, and each scope ID. IPv4-mapped IPv6 addresses remain IPv6 values. No implicit mapping or truncation is allowed.

The IPv6 peer token binding is a family marker, sixteen octets, a network-order UDP port, and a network-order scope ID. Its distinct length prevents an IPv4 binding from matching it. Local destination addresses remain part of route identity and do not enter the peer token binding. Token codecs, secret rotation, expiry, replay limits, and amplification limits retain their existing behavior.

Address-dependent factories accept the tuple type. Their IPv4 instance supplies the old public names. Their IPv6 instance supplies new names. Path-independent types remain shared. Existing result aliases must refer to the exact IPv4 instance used by the legacy lifecycle and TLS endpoints. A wrapper must not return a structurally similar but distinct result type.

Dependencies flow from address and endpoint policy to result types, lifecycle, registry, TLS endpoints, and runtime. Factories must not create a cycle through `lib.zig`. Existing protocol packets, frames, protection, streams, recovery, and TLS state remain outside this parameterization unless their actual type dependencies require a change.

## Socket and runtime contract

The IPv4 runtime keeps its current configuration and public fields. A new IPv6 runtime uses the IPv6 endpoint specialization. A handed-off socket transfers ownership only after initialization succeeds. On failure, the caller retains it. Shutdown waits for native calls and runtime tasks before releasing socket or endpoint storage.

An IPv6 runtime must reject the wrong socket family. The first supported IPv6 path uses an explicitly bound local address and a fixed peer path. It must not report `::` as an actual received destination. The client drops packets from a different peer. The server advertises disabled active migration and registers fixed-path routes. Connection migration remains available to callers of the core specialization under the existing caller-controlled validation contract. The initial runtime path does not extend that contract. Replies use the validated output tuple and retain the local source. IPv6 output uses a conservative 1200-byte UDP payload cap until a larger size is established. The old IPv4 cap and migration defaults stay unchanged.

Existing IPv4 HTTP/3 drivers retain their public types and behavior. A runtime factory may reference those drivers only for the IPv4 specialization. The IPv6 QUIC stream path must compile without instantiating an IPv4-only HTTP/3 adapter.

## State and failure matrix

| State or input | Required behavior |
| --- | --- |
| Existing IPv4 caller | The same source compiles and the old successful path remains available. |
| IPv6 socket passed to the old IPv4 runtime | Preserve the existing family rejection. |
| Explicit IPv6 socket passed to the new runtime | Keep its address and port, then perform normal TLS and QUIC processing. |
| Initial from an unvalidated peer | Keep existing Retry, token, and amplification policy. |
| Different local address, peer address, port, or scope | Treat it as a different path. Do not inherit validation or ECN state. |
| Unknown CID or zero-length CID | Apply the corresponding existing routing policy to the complete IPv6 tuple. |
| Wrong PATH_RESPONSE source or challenge | Do not validate or switch the path. |
| Runtime initialization or cancellation fails | Release only resources owned by this attempt. Preserve borrowed socket ownership on initialization failure. |
| IPv6 attempt fails in Mons | Keep the existing WSS service and IPv4 candidate available. Never reuse an authorization after its preface might have been sent. |

The generic lifecycle retains its existing caller-controlled challenge contract. It does not independently associate an outstanding challenge with a candidate tuple. The new IPv6 runtime therefore stays on a fixed peer path. It must not claim autonomous migration validation. A future runtime migration feature requires a separate path-bound challenge design and regression matrix.

## Runtime server trust regression

The new real-socket tests exposed an existing trust wiring error in both runtime families. `Client.Config.ca_bundle` documents the server trust bundle, but the runtime passed it to `TlsConfig.client_ca_bundle`. The server certificate verifier reads `TlsConfig.ca_bundle`. With an unrelated trust anchor, both runtime clients completed the handshake instead of returning `BadCertificate`. The red evidence is `red-runtime-ca-trust.log`.

Correct the runtime assignment to the server trust field. Keep ownership borrowed and keep the existing `insecure_skip_verify` and null-bundle behavior. Do not change TLS verification algorithms, certificate formats, or endpoint APIs. The TLS backend retains its existing mapping from certificate errors to `CryptoError`. An expected cryptographic rejection during a pending handshake is logged as a warning. Other receive errors keep their existing diagnostics. Correct-anchor localhost handshakes and 4 KiB stream echoes must pass for both families. Unrelated anchors must fail with the existing runtime error. Existing TLS endpoint certificate regressions remain required.

## Mons integration boundary

Mons keeps Relay for authenticated control and WSS fallback. Its new encrypted payload types must preserve the old IPv4 wire format. New capability interpretation must occur after Host proof validation. A control direction must not encrypt different plaintexts with the same key and sequence. A retry with reset sequence numbers requires a fresh attempt ID because current key derivation does not include the random handshake nonces.

If both families share one attempt, they also share one authorization owner, deadline, and resource budget. Punch and QUIC readiness must be separate from stream-preface delivery. Only one selected transport may send the preface. Host authorization remains consumed even if the subsequent local SSH bridge fails. Family-specific listeners must not multiply the existing aggregate limits.

The remaining Mons wire layout, listener identity ownership, and race details require their own concrete design before product integration changes. They do not block the independent quicz address and runtime slice.

## Validation and rollback

1. Preserve the existing runtime IPv6 rejection as baseline evidence. Add the same real `::1` socket fixture for the new IPv6 entry point.
2. Check IPv4 source compatibility without changing the old examples. Assert the public field and result types that cross module boundaries.
3. Test IPv6 equality and token binding with changed final octet, port, and scope. Keep the old six-byte token vectors.
4. Run IPv6 routing, zero-CID, token, ECN, and path-validation checks through the new specialization.
5. Complete a real IPv6 loopback TLS handshake and bidirectional stream transfer. Exercise cancellation and socket handoff ownership.
6. Run affected IPv4 regressions, the full test step, formatting checks, and the nearest runtime loopback examples. Report the known baseline failures separately.
7. Before claiming Mons success, verify native cellular QUIC, stream authorization, and five fresh SSH echoes on the physical iPhone.

All changes stay in independent task worktrees. Revert the task commits to roll back. Do not publish, deploy, change either main branch, modify system networking, or patch dependency caches for this phase.

## Local validation result

The native endpoint, TLS, socket ownership, trust, and stream checks passed. The full test step passed 1978 of 1979 tests. Its only failure was the unchanged retransmitted-ACK timeout already reproduced on the baseline. The original peer-learning timing test passed in this run.

The final default build completed all 182 steps with unchanged example, header, and build sources. The mobile static-library step completed all four steps. Both existing native mobile ABI loopbacks passed, including authenticated punch, CA-verified QUIC, stream echo, repeated connect, a silent-peer deadline, and cleanup. Logs are under `/private/tmp/quicz-cellular-ipv6.nIR61g/` with the `compat-build-` prefix.

These results validate the local IPv6 runtime slice and existing IPv4 consumers. They do not validate an IPv6 mobile ABI or a cellular Mons session. Those integration stages remain pending.

## Mobile ABI integration design

Keep ABI version 1, every existing C symbol, result value, IPv4 structure layout, and the 56-byte diagnostics layout. Add capability bit 7 for the complete native IPv6 path. Keep the same opaque client handle for stream operations. Both old constructors and the new constructor allocate one internal tagged owner. Its tag selects a stable heap allocation of the corresponding tuple-specialized mobile state. Never reinterpret an IPv6 state as the old IPv4 state.

Add an IPv6 endpoint containing sixteen address bytes, a `uint16_t` port, a zero `uint16_t` reserved field, and a `uint32_t` scope ID. Add a separate IPv6 config containing explicit local and remote endpoints and the existing server-name, ALPN, and DER pointer/length inputs. Do not add a migration promise to this config. The initial ABI supports scope-zero global unicast and loopback endpoints. Local port zero is allowed, remote port zero is rejected, and unspecified or mapped addresses are rejected. Scoped connectivity remains outside this ABI slice because the existing punch and STUN source comparators do not compare zones.

The new symbols are `quicz_mobile_client_create_ipv6`, `quicz_mobile_client_bound_ipv6`, `quicz_mobile_client_discover_ipv6`, `quicz_mobile_client_punch_ipv6`, and `quicz_mobile_client_punch_ipv6_with_diagnostics`. The IPv6 punch config keeps the original authentication and retry fields with an IPv6 remote endpoint. No unverified IPv6 constructor is added. Old address-specific operations reject an IPv6 owner, and new operations reject an IPv4 owner. Valid cross-family calls return `INVALID_ARGUMENT`. Diagnostics are cleared before validation. STUN returns a scope-zero mapped endpoint and rejects an IPv4 mapping on the IPv6 operation.

Connect, timeout, open, keepalive, send, receive, close, and destroy dispatch through the owner tag. One generic implementation retains input copies, the CA bundle, the I/O runtime, and the bounded creation thread. Caller inputs may be released after create returns. Close does not destroy storage. The caller must wait for every native operation before destroy. Allocation failures unwind only resources already acquired by that state and owner.

Validation must preserve old header layout, symbols, and native ABI loopbacks. Compare new C layouts with Zig `extern struct` through `b.addTranslateC`. Exercise valid wrong-family handles, reserved and scope rejection, output clearing, small-stack creation, and real IPv6 STUN, authenticated punch, verified TLS, stream transfer, deadline, close, and destroy. Correct and unrelated CA cases are required.

## Shared admission and record ownership design

Two family listeners must borrow one connection limit before allocating a new Initial's TLS state. The owner outlives both servers. An optional attachment method preserves the old runtime Config layouts. A reservation stays with the actual server record through pending and active states and is released exactly once when that record is destroyed. Default callers without an attached limit retain their existing behavior and per-server capacity.

The current `acceptInitialRecord` has mixed failure ownership. Before adoption the caller retains the record. After adoption some timer or backend failures retire and destroy it. Existing tests depend on that actual behavior despite an inaccurate general comment. The runtime catch also destroys the record, so a post-adoption failure can cause a second destruction. Do not attach a reservation to that ambiguous catch.

Preserve the old public entry point and its actual behavior. Add an explicitly owned admission entry point that consumes the supplied record on every outcome. Both entry points use one private implementation with an explicit failure-consumption mode. The new owned entry destroys a record rejected before adoption. Post-adoption retirement continues to own destruction. The runtime uses the owned entry and never dereferences or destroys the record after an error return. Check generated Initial and Handshake datagram ownership on every failure as part of the same state model.

The new owned entry requires caller-owned record storage allocated by the registry allocator. It rejects overlapping nonempty Initial and Handshake output slices with `BufferTooSmall` and consumes that record. Empty slices do not overlap. The legacy entry keeps its original slice behavior. On success, the runtime frees all returned output datagrams through one deferred cleanup even if a later runtime allocation fails.

| Admission state | Record owner | Reservation and failure behavior |
| --- | --- | --- |
| Before record allocation | Runtime | Return the reservation if allocation or transport initialization fails. |
| Record initialized, before owned admission | Runtime record | Transfer into the owned call. Its failure consumes the record and reservation. |
| Adopted, pending or active | Endpoint registry | Actual retirement or shutdown destroys the record and releases its reservation. |
| Post-adoption backend or timer failure | Endpoint rollback | The runtime must not inspect the consumed pointer. |
| Legacy caller, pre-adoption error | Legacy caller | Preserve the existing behavior. No new ownership promise is inferred. |
| Legacy caller, post-adoption error | Existing endpoint rollback | Preserve the existing behavior and document the boundary accurately. |

Use the existing rejecting Handshake backend to prove a real post-adoption failure. Observe destruction through an external counter so the red test does not inspect freed memory. Cover pre-adoption rejection, post-adoption rejection, success, expiry, and shutdown. Then use real IPv4 and IPv6 servers borrowing a single limit to prove aggregate pending and active capacity and release. These changes are prerequisites for the Mons dual-listener owner, not permission to copy per-family authorization or connection budgets.
