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
