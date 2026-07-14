# 示例

[English](README.md)

所有命令在仓库根目录运行；每个 `run-*` step 会自动构建。本文件完整列出
`build.zig` 注册的可执行示例，`zig build --help` 是自动生成的权威索引。

## 入口与互通

| 命令 | 源码 | 简要说明 |
| --- | --- | --- |
| `run-server` | `echo_server.zig` | 最小 frame-payload echo server。 |
| `run-client` | `echo_client.zig` | 最小 frame-payload echo client。 |
| `run-tls13-process-interop` | `tls13_process_echo_{client,server}.zig` | 独立纯 Zig TLS/QUIC 进程、两条 FIN stream、路由和 close cleanup。 |
| `run-interop-external-client -- <ip> <port> <ca> [name]` | `interop_external_client.zig` | 连接独立 IPv4 QUIC server，校验 stream 0、4 的 FIN `hello`/`world` echo。 |
| `run-interop-client -- <host> <port> [testcase]` | `interop_client.zig` | QUIC-Interop-Runner 风格 client 与本地回退探针。 |
| `run-interop-event-loopback -- [mode]` | `interop_event_loopback.zig` | handshake、transfer、loss、congestion、persistent、key-update、path 事件循环。 |
| Go client | `interop/go_echo_client/main.go` | quic-go client 向 Zig server 发送 stream 0、4 的 FIN 数据。 |
| Rust client | `interop/rust_echo_client/src/main.rs` | quinn/rustls client 向 Zig server 发送 stream 0、4 的 FIN 数据。 |

Go/Rust 使用本地测试 CA，先启动 server，再任选一个 client：

```sh
zig-out/bin/quicz-tls13-process-echo-server 127.0.0.1 4443 2 concurrent-retry
(cd examples/interop/go_echo_client && go run . -addr 127.0.0.1:4443 -ca ../testdata/quicz-echo-ca.pem -server-name localhost)
(cd examples/interop/rust_echo_client && cargo run -- 127.0.0.1:4443 ../testdata/quicz-echo-ca.pem localhost)
```

## 核心 transport 状态

| 命令 | 源码 | 简要说明 |
| --- | --- | --- |
| `run-codec` | `codec_roundtrip.zig` | packet、frame、varint 编解码。 |
| `run-transport-parameters` | `transport_parameters.zig` | transport parameter 编解码与应用。 |
| `run-flow-control` | `flow_control.zig` | connection/stream credit、BLOCKED、MAX_*。 |
| `run-uni-stream` | `uni_stream.zig` | 单向 stream 权限与 FIN。 |
| `run-stream-reset` | `stream_reset.zig` | RESET_STREAM final size 与接收状态。 |
| `run-stop-sending` | `stop_sending.zig` | STOP_SENDING 与发送侧状态。 |
| `run-crypto-stream` | `crypto_stream.zig` | CRYPTO stream 缓冲与重传。 |
| `run-graceful-close` | `graceful_close.zig` | CONNECTION_CLOSE 与 draining。 |
| `run-idle-timeout` | `idle_timeout.zig` | idle deadline 与 timeout close。 |
| `run-packet-spaces` | `packet_spaces.zig` | Initial、Handshake、0-RTT、Application space。 |
| `run-ecn-validation` | `ecn_validation.zig` | ACK_ECN 校验与 CE 拥塞响应。 |
| `run-loss-recovery` | `loss_recovery.zig` | ACK/loss-time 重传选择。 |
| `run-pto-recovery` | `pto_recovery.zig` | PTO probe 与 backoff。 |
| `run-endpoint-recovery-timers` | `endpoint_recovery_timers.zig` | endpoint 多连接 deadline 选择。 |
| `run-path-validation` | `path_validation.zig` | PATH_CHALLENGE/PATH_RESPONSE。 |
| `run-address-validation` | `address_validation.zig` | 地址校验与 anti-amplification。 |
| `run-retry-token` | `retry_token.zig` | Retry token 签发与验证。 |
| `run-connection-ids` | `connection_ids.zig` | CID 生命周期。 |
| `run-stateless-reset` | `stateless_reset.zig` | stateless-reset token。 |
| `run-initial-keys` | `initial_keys.zig` | RFC 9001 Initial secret 派生。 |
| `run-endpoint-routing` | `endpoint_routing.zig` | CID/tuple 路由决策。 |

## TLS 集成

| 命令 | 源码 | 简要说明 |
| --- | --- | --- |
| `run-tls13-backend-loopback` | `tls13_backend_loopback.zig` | 内存内纯 Zig TLS 1.3 CRYPTO backend。 |
| `run-tls13-udp-loopback` | `tls13_udp_loopback.zig` | TLS-owned 握手与受保护 UDP stream。 |
| `run-tls13-lifecycle-loopback` | `tls13_lifecycle_loopback.zig` | TLS backend 经 endpoint lifecycle 驱动。 |
| `run-tls13-stateless-reset-loopback` | `tls13_stateless_reset_loopback.zig` | TLS-owned reset 接收和清理。 |
| `run-tls13-path-validation-loopback` | `tls13_path_validation_loopback.zig` | TLS-owned UDP 路径迁移校验。 |
| `run-tls13-retry-loopback` | `tls13_retry_loopback.zig` | Retry、ClientHello 重传、1-RTT 完成。 |
| `run-tls-backend-adapter` | `tls_backend_adapter.zig` | 通用 TLS backend adapter 契约。 |
| `run-tls-c-abi-adapter` | `tls_c_abi_adapter.zig` | C ABI TLS adapter 边界。 |
| `run-tls-openssl-probe` | `tls_openssl_probe.zig` | OpenSSL QUIC TLS API 可用性。 |
| `run-tls-openssl-backend-adapter` | `tls_openssl_backend_adapter.zig` | OpenSSL CRYPTO adapter 集成。 |
| `run-tls-openssl-pair-transcript` | `tls_openssl_pair_transcript.zig` | OpenSSL client/server CRYPTO transcript。 |

## UDP lifecycle loopback

| 命令 | 源码 | 简要说明 |
| --- | --- | --- |
| `run-udp-address-validation-loopback` | `udp_address_validation_loopback.zig` | 地址校验。 |
| `run-udp-endpoint-loopback` | `udp_endpoint_loopback.zig` | endpoint 路由和 Version Negotiation follow-up。 |
| `run-udp-zero-cid-loopback` | `udp_zero_cid_loopback.zig` | 零长度 CID tuple 路由。 |
| `run-udp-preferred-address-loopback` | `udp_preferred_address_loopback.zig` | preferred-address 路由迁移。 |
| `run-udp-replacement-cid-loopback` | `udp_replacement_cid_loopback.zig` | replacement CID 激活与退役。 |
| `run-udp-connection-ids-loopback` | `udp_connection_ids_loopback.zig` | NEW/RETIRE_CONNECTION_ID。 |
| `run-udp-flow-control-loopback` | `udp_flow_control_loopback.zig` | 受保护 stream flow-control 刷新。 |
| `run-udp-spin-bit-loopback` | `udp_spin_bit_loopback.zig` | spin-bit path 状态。 |
| `run-udp-ecn-validation-loopback` | `udp_ecn_validation_loopback.zig` | ACK_ECN 与 CE 响应。 |
| `run-udp-pto-recovery-loopback` | `udp_pto_recovery_loopback.zig` | PTO probe 和重传。 |
| `run-udp-loss-recovery-loopback` | `udp_loss_recovery_loopback.zig` | ACK/loss-time recovery。 |
| `run-udp-stream-retransmission-loopback` | `udp_stream_retransmission_loopback.zig` | ACK 驱动 STREAM 重传。 |
| `run-udp-congestion-recovery-loopback` | `udp_congestion_recovery_loopback.zig` | NewReno loss/persistent congestion。 |
| `run-udp-protected-loopback` | `udp_protected_loopback.zig` | 受保护 packet 收发。 |
| `run-udp-handshake-keys-loopback` | `udp_handshake_keys_loopback.zig` | Handshake-key datagram。 |
| `run-udp-crypto-stream-loopback` | `udp_crypto_stream_loopback.zig` | CRYPTO backend 数据。 |
| `run-udp-zero-rtt-loopback` | `udp_zero_rtt_loopback.zig` | 0-RTT accept/reject。 |
| `run-udp-one-rtt-loopback` | `udp_one_rtt_loopback.zig` | 1-RTT packet path。 |
| `run-udp-echo-loopback` | `udp_echo_loopback.zig` | 受保护 UDP stream echo。 |
| `run-udp-crypto-backend-loopback` | `udp_crypto_backend_loopback.zig` | Crypto backend drive 与路由。 |
| `run-udp-handshake-done-loopback` | `udp_handshake_done_loopback.zig` | HANDSHAKE_DONE 收发。 |
| `run-udp-key-update-loopback` | `udp_key_update_loopback.zig` | key phase update 与 ACK gate。 |
| `run-udp-path-validation-loopback` | `udp_path_validation_loopback.zig` | path validation 后 route update。 |
| `run-udp-retry-loopback` | `udp_retry_loopback.zig` | lifecycle Retry route switch。 |
| `run-udp-close-lifecycle-loopback` | `udp_close_lifecycle_loopback.zig` | close 驱动 route retirement/reset。 |
| `run-udp-stateless-reset-loopback` | `udp_stateless_reset_loopback.zig` | inactive-CID reset emission。 |

## 支撑文件

`tls_c_abi_adapter.zig` 使用 `tls_backend_c_abi.h`、`tls_c_abi_demo_backend.c/.h`；
OpenSSL 示例使用 `tls_openssl_backend_adapter.c/.h`、`tls_openssl_pair_transcript.c/.h`、
`tls_openssl_probe.c/.h`。它们由对应 Zig 示例编译，不是独立命令。
