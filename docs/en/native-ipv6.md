# Native IPv6 APIs

The IPv6 APIs use separate address-family specializations. Existing IPv4 names, configuration fields, and callback types remain available. For example, an existing IPv4 caller can continue to read `.path.remote.octets`.

## Zig endpoints and runtimes

`endpoint.Udp6Address` contains sixteen address bytes, a port, and a local scope identifier. `endpoint.Udp6Tuple` contains the local and remote addresses. Path-aware endpoint, lifecycle, registry, and TLS types provide `ForTuple` factories. Their original public names remain IPv4 specializations.

Use `runtime.client.IPv6Client` and `runtime.server.IPv6Server` for native IPv6 sockets. Bind the client to an explicit source address. The initial IPv6 UDP payload limit is 1200 bytes. These runtimes keep one address family for the connection and disable active migration. Existing IPv4 runtime configuration and migration behavior remain unchanged.

IPv4 address-validation tokens retain their existing six-byte IP and port representation. IPv6 tokens have a separate family tag and include the full IPv6 address, port, and scope. An IPv6 token cannot validate an IPv4 path.

## Mobile C ABI

The ABI version remains 1. Existing structures, result values, symbols, and the 56-byte punch diagnostics layout remain unchanged. Native IPv6 support adds capability bit 7 and separate IPv6 configuration and endpoint structures. It does not extend the closed Zig `Capability` enum.

The added entry points are:

- `quicz_mobile_client_create_ipv6`
- `quicz_mobile_client_bound_ipv6`
- `quicz_mobile_client_discover_ipv6`
- `quicz_mobile_client_punch_ipv6`
- `quicz_mobile_client_punch_ipv6_with_diagnostics`

The IPv6 constructor requires an explicit local address and a CA certificate. It accepts scope-zero global unicast or loopback addresses. It does not provide an unverified constructor. Both constructors return the same opaque owner format. Address-neutral connect, stream, close, and destroy functions accept either owner. Address-specific functions reject an owner from the other family.

Close cancels an active punch without destroying its socket. A caller must wait for active ABI calls to return before it destroys the handle. The close state is sticky. A closed handle cannot start another connection or stream operation.

## Shared admission and ownership

`ConnectionAdmission` limits pending and active QUIC records across several runtime servers. Attach one stable instance before either server starts. Keep that instance alive until every borrowing server finishes `deinit`. Existing runtime `Config` shapes remain unchanged.

An owner that revokes shared punch attempts can attach one mutex with `attachPunchHandoffMutex` before each server starts. The runtime holds it across coordinator handoff and responder registration. The owner must hold the same mutex while it removes coordinator and responder entries. This prevents late handoff from recreating a removed entry.

Release the mutex before joining or destroying a server. Keep it alive until all borrowing servers finish `deinit`. Unattached servers retain their previous behavior.

`acceptOwnedInitialRecord` consumes its input record on success and failure. It also releases generated output bytes on failure. The old `acceptInitialRecord` entry point retains its existing ownership behavior. Runtime server admission uses the owned entry point so a failed TLS admission cannot free a record twice.

## Validation

Real IPv4 and IPv6 loopback tests cover CA rejection, verified TLS, a random 4 KiB stream with FIN, cancellation, socket reuse, and a shared one-record admission limit. The Mobile ABI example also covers input copies, STUN6, authenticated punch, and close from callers that block SIGIO.

Run `zig build run-mobile-ipv6-abi-loopback`, `zig build run-mobile-abi-loopback`, and `zig build run-mobile-deadline-regression` for the ABI paths. The complete unit suite retains one baseline failure in the lost-ACK retry timing test. These loopback results do not establish reachability across a particular external network.
