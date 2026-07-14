# quicz

English | [简体中文](README_zh-CN.md)

`quicz` is an experimental IETF QUIC transport implementation in
[Zig](https://ziglang.org/). It targets a usable QUIC v1 transport rather than
every optional QUIC extension.

## Status and scope

The current core includes pure-Zig TLS 1.3, QUIC packet protection, streams,
flow control, Retry, connection-ID routing, path validation, loss recovery,
and a NewReno baseline. Real UDP loopback, separate-process Zig, and
certificate-verified Go/Rust/quic-go interoperability probes cover the primary
handshake and FIN-terminated stream-echo path.

It is still experimental. Production endpoint capacity policy, broader
interoperability, and several RFC edge cases remain in progress. HTTP/3/QPACK,
QUIC DATAGRAM, full QUIC v2/compatible-version behavior, multipath, qlog,
PMTU, GSO/GRO, and advanced congestion controllers are outside the first
transport milestone.

The authoritative status and evidence are in the
[transport task matrix](docs/en/quic_transport_tasks.md).

## Quick start

Use Zig **0.16.0**.

```sh
zig build
zig build test --summary all
zig build run-tls13-udp-loopback
zig build run-tls13-process-interop
```

`run-tls13-udp-loopback` verifies the pure-Zig TLS-owned UDP handshake and
stream path. `run-tls13-process-interop` runs independently built Zig client
and server processes over loopback UDP.

For all available checks and examples:

```sh
zig build --help
```

## Go and Rust interoperability examples

Build the project, then start the local Zig echo server:

```sh
zig-out/bin/quicz-tls13-process-echo-server 127.0.0.1 4443 2 concurrent-retry
```

Run either independently implemented client with the local test CA:

```sh
(cd examples/interop/go_echo_client && go run . -addr 127.0.0.1:4443 -ca ../testdata/quicz-echo-ca.pem -server-name localhost)
(cd examples/interop/rust_echo_client && cargo run -- 127.0.0.1:4443 ../testdata/quicz-echo-ca.pem localhost)
```

Both clients keep certificate verification enabled and report success only
after the `hq-interop` stream echo and peer FIN. The included PEM is a local
test trust anchor, not a deployment credential.

## Development map

| Need | Start here |
| --- | --- |
| Public connection API | [`src/lib.zig`](src/lib.zig) |
| TLS 1.3 implementation | [`src/quic/tls13.zig`](src/quic/tls13.zig) |
| Endpoint routing and timers | [`src/quic/endpoint_lifecycle.zig`](src/quic/endpoint_lifecycle.zig) |
| Runnable probes | [`examples/`](examples/) |
| Protocol status and acceptance evidence | [`docs/en/quic_transport_tasks.md`](docs/en/quic_transport_tasks.md) |
| Architecture and terminology | [`docs/en/architecture.md`](docs/en/architecture.md) |

The API is evolving. `Connection` is the primary public handle; detailed
lifecycle helpers are intentionally documented in the architecture and task
matrix rather than enumerated here.

## License

MIT. See [LICENSE](LICENSE).
