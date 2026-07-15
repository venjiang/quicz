# Examples

[简体中文](README_zh-CN.md)

Run every command from the repository root. `zig build` is implicit in every
`run-*` step. This is the complete catalogue of executable examples registered
by `build.zig`; `zig build --help` is the authoritative generated index.

## Entry points and interoperability

| Command | Source | What it demonstrates |
| --- | --- | --- |
| `run-server` | `echo_server.zig` | Minimal frame-payload echo server. |
| `run-client` | `echo_client.zig` | Minimal frame-payload echo client. |
| `run-tls13-process-interop` | `tls13_process_echo_{client,server}.zig` | Separate pure-Zig TLS/QUIC processes, two FIN streams, routing and close cleanup. |
| `run-interop-external-client -- <ip> <port> <ca> [name]` | `interop_external_client.zig` | Certificate-verified IPv4 peer probe with FIN `hello`/`world` echoes on streams 0 and 4. |
| `run-interop-client -- <host> <port> [testcase]` | `interop_client.zig` | QUIC-Interop-Runner-style client and local fallback probe. |
| `run-interop-event-loopback -- [handshake|transfer|loss|congestion|persistent|key-update|path|stream-control|stream-limit]` | `interop_event_loopback.zig` | TLS-owned UDP event-loop scenarios, including stream control and credit release. |
| Go client | `interop/go_echo_client/main.go` | quic-go FIN echo client; `-expect-stream-limit`, `-expect-reset`, and `-expect-stop-sending` validate the matching concurrent server modes. |
| Go server | `interop/go_echo_client/echo_server/main.go` | One-connection quic-go peer that generates a local CA PEM and echoes two FIN streams. |
| Rust client | `interop/rust_echo_client/src/main.rs` | quinn/rustls client sending FIN streams 0 and 4 to the Zig server. |

The Go/Rust clients require the local test CA and a running Zig server:

```sh
zig-out/bin/quicz-tls13-process-echo-server 127.0.0.1 4443 2 concurrent-retry
(cd examples/interop/go_echo_client && go run . -addr 127.0.0.1:4443 -ca ../testdata/quicz-echo-ca.pem -server-name localhost)
(cd examples/interop/rust_echo_client && cargo run -- 127.0.0.1:4443 ../testdata/quicz-echo-ca.pem localhost)
```

For the external Zig client, start the independent Go peer in one terminal,
then pass its generated CA PEM to the Zig client in another:

```sh
(cd examples/interop/go_echo_client && go run ./echo_server -addr 127.0.0.1:4433 -ca-out /absolute/path/to/go-echo-ca.pem)
zig build run-interop-external-client -- 127.0.0.1 4433 /absolute/path/to/go-echo-ca.pem localhost
```

## Core transport state

| Command | Source | What it demonstrates |
| --- | --- | --- |
| `run-codec` | `codec_roundtrip.zig` | Packet, frame, and varint codec round trips. |
| `run-transport-parameters` | `transport_parameters.zig` | Transport-parameter encode, parse, and application. |
| `run-flow-control` | `flow_control.zig` | Connection and stream credit, BLOCKED, and MAX_* frames. |
| `run-uni-stream` | `uni_stream.zig` | Unidirectional stream permissions and FIN. |
| `run-stream-reset` | `stream_reset.zig` | RESET_STREAM final-size and receive-state handling. |
| `run-stop-sending` | `stop_sending.zig` | STOP_SENDING and resulting send-side state. |
| `run-crypto-stream` | `crypto_stream.zig` | CRYPTO stream buffering and retransmission. |
| `run-graceful-close` | `graceful_close.zig` | CONNECTION_CLOSE and draining behavior. |
| `run-idle-timeout` | `idle_timeout.zig` | Idle deadlines and timeout close. |
| `run-packet-spaces` | `packet_spaces.zig` | Initial, Handshake, 0-RTT, and Application packet spaces. |
| `run-ecn-validation` | `ecn_validation.zig` | ACK_ECN validation and CE congestion response. |
| `run-loss-recovery` | `loss_recovery.zig` | ACK, loss-time, and retransmission selection. |
| `run-pto-recovery` | `pto_recovery.zig` | PTO probes and recovery backoff. |
| `run-endpoint-recovery-timers` | `endpoint_recovery_timers.zig` | Deadline selection across endpoint connections. |
| `run-path-validation` | `path_validation.zig` | PATH_CHALLENGE/PATH_RESPONSE state. |
| `run-address-validation` | `address_validation.zig` | Address-validation state and anti-amplification. |
| `run-retry-token` | `retry_token.zig` | Retry token issue and validation. |
| `run-connection-ids` | `connection_ids.zig` | CID issuance, retirement, and replacement. |
| `run-stateless-reset` | `stateless_reset.zig` | Stateless-reset token recognition. |
| `run-initial-keys` | `initial_keys.zig` | RFC 9001 Initial secret derivation. |
| `run-endpoint-routing` | `endpoint_routing.zig` | CID/tuple routing decisions. |

## TLS integrations

| Command | Source | What it demonstrates |
| --- | --- | --- |
| `run-tls13-backend-loopback` | `tls13_backend_loopback.zig` | Pure-Zig TLS 1.3 CRYPTO-backend handshake in memory. |
| `run-tls13-udp-loopback` | `tls13_udp_loopback.zig` | Pure-Zig TLS-owned handshake and protected UDP stream path. |
| `run-tls13-lifecycle-loopback` | `tls13_lifecycle_loopback.zig` | TLS backend driving through endpoint lifecycle. |
| `run-tls13-stateless-reset-loopback` | `tls13_stateless_reset_loopback.zig` | TLS-owned stateless-reset receive and cleanup. |
| `run-tls13-path-validation-loopback` | `tls13_path_validation_loopback.zig` | TLS-owned UDP path migration validation. |
| `run-tls13-retry-loopback` | `tls13_retry_loopback.zig` | Retry, ClientHello retransmission, and 1-RTT completion. |
| `run-tls-backend-adapter` | `tls_backend_adapter.zig` | Generic TLS backend adapter contract. |
| `run-tls-c-abi-adapter` | `tls_c_abi_adapter.zig` | C-ABI TLS adapter boundary. |
| `run-tls-openssl-probe` | `tls_openssl_probe.zig` | OpenSSL QUIC TLS API availability probe. |
| `run-tls-openssl-backend-adapter` | `tls_openssl_backend_adapter.zig` | OpenSSL-backed CRYPTO adapter integration. |
| `run-tls-openssl-pair-transcript` | `tls_openssl_pair_transcript.zig` | OpenSSL client/server CRYPTO transcript. |

## UDP lifecycle loopbacks

| Command | Source | What it demonstrates |
| --- | --- | --- |
| `run-udp-address-validation-loopback` | `udp_address_validation_loopback.zig` | Socket-backed address validation. |
| `run-udp-endpoint-loopback` | `udp_endpoint_loopback.zig` | Endpoint routing and Version Negotiation follow-up. |
| `run-udp-zero-cid-loopback` | `udp_zero_cid_loopback.zig` | Zero-length CID tuple routing. |
| `run-udp-preferred-address-loopback` | `udp_preferred_address_loopback.zig` | Preferred-address route migration. |
| `run-udp-replacement-cid-loopback` | `udp_replacement_cid_loopback.zig` | Replacement CID activation and retirement. |
| `run-udp-connection-ids-loopback` | `udp_connection_ids_loopback.zig` | NEW_CONNECTION_ID and RETIRE_CONNECTION_ID. |
| `run-udp-flow-control-loopback` | `udp_flow_control_loopback.zig` | Protected stream flow-control refresh. |
| `run-udp-spin-bit-loopback` | `udp_spin_bit_loopback.zig` | Spin-bit path state. |
| `run-udp-ecn-validation-loopback` | `udp_ecn_validation_loopback.zig` | Lifecycle ACK_ECN validation and CE response. |
| `run-udp-pto-recovery-loopback` | `udp_pto_recovery_loopback.zig` | Protected UDP PTO probes and retransmission. |
| `run-udp-loss-recovery-loopback` | `udp_loss_recovery_loopback.zig` | Protected ACK/loss-time recovery. |
| `run-udp-stream-retransmission-loopback` | `udp_stream_retransmission_loopback.zig` | ACK-driven STREAM retransmission. |
| `run-udp-congestion-recovery-loopback` | `udp_congestion_recovery_loopback.zig` | NewReno loss and persistent congestion. |
| `run-udp-protected-loopback` | `udp_protected_loopback.zig` | Protected-packet receive/send. |
| `run-udp-handshake-keys-loopback` | `udp_handshake_keys_loopback.zig` | Installed Handshake-key datagrams. |
| `run-udp-crypto-stream-loopback` | `udp_crypto_stream_loopback.zig` | CRYPTO backend data over UDP. |
| `run-udp-zero-rtt-loopback` | `udp_zero_rtt_loopback.zig` | Explicit 0-RTT accept/reject path. |
| `run-udp-one-rtt-loopback` | `udp_one_rtt_loopback.zig` | Installed 1-RTT packet path. |
| `run-udp-echo-loopback` | `udp_echo_loopback.zig` | Protected UDP stream echo. |
| `run-udp-crypto-backend-loopback` | `udp_crypto_backend_loopback.zig` | Crypto backend drive and UDP routing. |
| `run-udp-handshake-done-loopback` | `udp_handshake_done_loopback.zig` | HANDSHAKE_DONE transmission and receive. |
| `run-udp-key-update-loopback` | `udp_key_update_loopback.zig` | Key-phase update and ACK gate. |
| `run-udp-path-validation-loopback` | `udp_path_validation_loopback.zig` | Lifecycle route update after path validation. |
| `run-udp-retry-loopback` | `udp_retry_loopback.zig` | Lifecycle Retry route switch. |
| `run-udp-close-lifecycle-loopback` | `udp_close_lifecycle_loopback.zig` | Close-driven route retirement and reset. |
| `run-udp-stateless-reset-loopback` | `udp_stateless_reset_loopback.zig` | Inactive-CID stateless-reset emission. |

## Support files

`tls_c_abi_adapter.zig` uses `tls_backend_c_abi.h`, `tls_c_abi_demo_backend.c`,
and `tls_c_abi_demo_backend.h`. The OpenSSL examples use
`tls_openssl_backend_adapter.{c,h}`, `tls_openssl_pair_transcript.{c,h}`, and
`tls_openssl_probe.{c,h}`. These are compiled through their matching Zig
examples; they are not standalone commands.
