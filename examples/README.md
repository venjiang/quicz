# Examples

[English](#english) | [简体中文](#简体中文)

## English

All commands run from the repository root after `zig build`. Examples are
small executable probes, not a stable high-level application API. Start with
the library snippet in the [root README](../README.md), then choose the
closest runnable path below.

### Start here

| Goal | Command | Source |
| --- | --- | --- |
| Encode and decode representative QUIC values | `zig build run-codec` | [`codec_roundtrip.zig`](codec_roundtrip.zig) |
| Queue a stream frame and observe flow control | `zig build run-flow-control` | [`flow_control.zig`](flow_control.zig) |
| Exercise uni-stream, reset, and STOP_SENDING state | `zig build run-uni-stream`, `run-stream-reset`, `run-stop-sending` | [`uni_stream.zig`](uni_stream.zig), [`stream_reset.zig`](stream_reset.zig), [`stop_sending.zig`](stop_sending.zig) |
| Run the pure-Zig TLS 1.3 UDP handshake and echo path | `zig build run-tls13-udp-loopback` | [`tls13_udp_loopback.zig`](tls13_udp_loopback.zig) |
| Run independently built Zig client and server processes | `zig build run-tls13-process-interop` | [`tls13_process_echo_client.zig`](tls13_process_echo_client.zig), [`tls13_process_echo_server.zig`](tls13_process_echo_server.zig) |

### Transport behavior probes

The loopback probes each isolate a transport concern and are suitable for
regression checks after changing that area:

| Concern | Commands |
| --- | --- |
| Loss, PTO, and congestion recovery | `run-udp-loss-recovery-loopback`, `run-udp-pto-recovery-loopback`, `run-udp-congestion-recovery-loopback` |
| Retry, address/path validation, and connection IDs | `run-tls13-retry-loopback`, `run-tls13-path-validation-loopback`, `run-udp-connection-ids-loopback` |
| Stream retransmission, close, and stateless reset | `run-udp-stream-retransmission-loopback`, `run-udp-close-lifecycle-loopback`, `run-tls13-stateless-reset-loopback` |
| TLS in memory and lifecycle driving | `run-tls13-backend-loopback`, `run-tls13-lifecycle-loopback` |

Use `zig build --help` for the complete list. The protocol task matrix records
the expected behavior and acceptance evidence, rather than duplicating every
internal lifecycle entry here.

### Go and Rust clients against the Zig server

Build first, then start the local certificate-backed Zig server:

```sh
zig-out/bin/quicz-tls13-process-echo-server 127.0.0.1 4443 2 concurrent-retry
```

Run either independent client:

```sh
(cd examples/interop/go_echo_client && go run . -addr 127.0.0.1:4443 -ca ../testdata/quicz-echo-ca.pem -server-name localhost)
(cd examples/interop/rust_echo_client && cargo run -- 127.0.0.1:4443 ../testdata/quicz-echo-ca.pem localhost)
```

They require ALPN `hq-interop`, validate the server certificate using the
included local test CA, and independently finish `hello` on stream 0 and
`world` on stream 4 before requiring both echoed FINs. The PEM is only a test
trust anchor.

### Zig client against another QUIC server

`quicz-interop-external-client` is an external-server probe. Its CA file must
be an absolute path and certificate verification remains enabled:

```sh
zig build run-interop-external-client -- 127.0.0.1 4433 /absolute/path/to/ca.pem localhost
```

It currently connects to an IPv4 server, requires `hq-interop`, and verifies a
single FIN-terminated `hello` echo. See
[`interop_external_client.zig`](interop_external_client.zig) for its exact
failure conditions.

## 简体中文

所有命令都在仓库根目录、执行 `zig build` 后运行。这些程序是小型可执行验证探针，
不是稳定的高层应用 API。先阅读根目录 [README](../README_zh-CN.md) 的库接入方式，
再选择下列最接近的运行路径。

### 从这里开始

| 目标 | 命令 | 源码 |
| --- | --- | --- |
| 编解码代表性的 QUIC 值 | `zig build run-codec` | [`codec_roundtrip.zig`](codec_roundtrip.zig) |
| 排队发送 stream frame 并观察 flow control | `zig build run-flow-control` | [`flow_control.zig`](flow_control.zig) |
| 验证 uni-stream、reset、STOP_SENDING 状态 | `zig build run-uni-stream`、`run-stream-reset`、`run-stop-sending` | [`uni_stream.zig`](uni_stream.zig)、[`stream_reset.zig`](stream_reset.zig)、[`stop_sending.zig`](stop_sending.zig) |
| 运行纯 Zig TLS 1.3 UDP 握手与 echo 路径 | `zig build run-tls13-udp-loopback` | [`tls13_udp_loopback.zig`](tls13_udp_loopback.zig) |
| 运行独立构建的 Zig client/server 进程 | `zig build run-tls13-process-interop` | [`tls13_process_echo_client.zig`](tls13_process_echo_client.zig)、[`tls13_process_echo_server.zig`](tls13_process_echo_server.zig) |

### Transport 行为探针

每个 loopback 探针都聚焦一个 transport 关注点，适合改动相邻模块后做回归验证：

| 关注点 | 命令 |
| --- | --- |
| loss、PTO、congestion recovery | `run-udp-loss-recovery-loopback`、`run-udp-pto-recovery-loopback`、`run-udp-congestion-recovery-loopback` |
| Retry、address/path validation、connection ID | `run-tls13-retry-loopback`、`run-tls13-path-validation-loopback`、`run-udp-connection-ids-loopback` |
| stream retransmission、close、stateless reset | `run-udp-stream-retransmission-loopback`、`run-udp-close-lifecycle-loopback`、`run-tls13-stateless-reset-loopback` |
| 内存内 TLS 与 lifecycle driving | `run-tls13-backend-loopback`、`run-tls13-lifecycle-loopback` |

完整列表使用 `zig build --help` 查看。协议任务矩阵记录了预期行为和验收证据，因此这里
不重复罗列内部 lifecycle 入口。

### 用 Go/Rust client 连接 Zig server

先构建，再启动本地、带证书的 Zig server：

```sh
zig-out/bin/quicz-tls13-process-echo-server 127.0.0.1 4443 2 concurrent-retry
```

然后运行任一独立实现的客户端：

```sh
(cd examples/interop/go_echo_client && go run . -addr 127.0.0.1:4443 -ca ../testdata/quicz-echo-ca.pem -server-name localhost)
(cd examples/interop/rust_echo_client && cargo run -- 127.0.0.1:4443 ../testdata/quicz-echo-ca.pem localhost)
```

它们要求协商 `hq-interop` ALPN，用仓库内本地测试 CA 校验证书；stream 0 的 `hello` 和
stream 4 的 `world` 都必须独立完成 echo 与 FIN。PEM 只用于测试信任。

### 用 Zig client 连接其他 QUIC server

`quicz-interop-external-client` 用于探测外部 server。CA 文件必须是绝对路径，且始终
开启证书校验：

```sh
zig build run-interop-external-client -- 127.0.0.1 4433 /absolute/path/to/ca.pem localhost
```

当前它连接 IPv4 server、要求 `hq-interop`，并校验一条带 FIN 的 `hello` echo。精确的
失败条件见 [`interop_external_client.zig`](interop_external_client.zig)。
