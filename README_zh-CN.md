# quicz

[English](README.md) | 简体中文

`quicz` 是一个使用 [Zig](https://ziglang.org/) 实现的实验性 IETF QUIC
transport。目标是先完成可用的 QUIC v1 transport，而不是覆盖所有可选扩展。

## 状态与范围

当前核心包含纯 Zig TLS 1.3、QUIC packet protection、stream、flow control、Retry、
connection ID routing、path validation、loss recovery 和 NewReno 基线。真实 UDP
loopback、独立进程 Zig，以及启用证书校验的 Go/Rust/quic-go 互通探针，覆盖了主要的
握手和带 FIN 的 stream echo 路径。

项目仍处于实验阶段。生产 endpoint 的容量策略、更广的互通和部分 RFC 边界仍在推进。
HTTP/3/QPACK、QUIC DATAGRAM、完整 QUIC v2/compatible-version 行为、multipath、
qlog、PMTU、GSO/GRO 和高级拥塞控制不属于第一轮 transport 里程碑。

权威状态与验证证据见[传输任务矩阵](docs/zh-CN/quic_transport_tasks.md)。

## 快速开始

使用 Zig **0.16.0**。

```sh
zig build
zig build test --summary all
zig build run-tls13-udp-loopback
zig build run-tls13-process-interop
```

`run-tls13-udp-loopback` 验证纯 Zig、TLS-owned 的 UDP 握手和 stream 路径。
`run-tls13-process-interop` 会启动独立构建的 Zig client/server，并通过 loopback UDP
运行互通验证。

查看全部构建步骤和示例：

```sh
zig build --help
```

## Go 与 Rust 互通示例

构建项目后，先启动本地 Zig echo server：

```sh
zig-out/bin/quicz-tls13-process-echo-server 127.0.0.1 4443 2 concurrent-retry
```

再使用本地测试 CA 运行任一独立实现的客户端：

```sh
(cd examples/interop/go_echo_client && go run . -addr 127.0.0.1:4443 -ca ../testdata/quicz-echo-ca.pem -server-name localhost)
(cd examples/interop/rust_echo_client && cargo run -- 127.0.0.1:4443 ../testdata/quicz-echo-ca.pem localhost)
```

两个客户端均保持证书校验开启，只有在 `hq-interop` stream echo 和对端 FIN 完成后才会
报告成功。仓库内 PEM 只是本地测试信任锚，不是部署凭据。

## 开发入口

| 需求 | 入口 |
| --- | --- |
| 公开连接 API | [`src/lib.zig`](src/lib.zig) |
| TLS 1.3 实现 | [`src/quic/tls13.zig`](src/quic/tls13.zig) |
| Endpoint 路由与 timer | [`src/quic/endpoint_lifecycle.zig`](src/quic/endpoint_lifecycle.zig) |
| 可运行探针 | [`examples/`](examples/) |
| 协议状态与验收证据 | [`docs/zh-CN/quic_transport_tasks.md`](docs/zh-CN/quic_transport_tasks.md) |
| 架构与术语 | [`docs/zh-CN/architecture.md`](docs/zh-CN/architecture.md) |

API 仍在演进。`Connection` 是主要公开句柄；详细 lifecycle helper 只在架构文档和
任务矩阵中说明，不在 README 枚举。

## 许可证

MIT，见 [LICENSE](LICENSE)。
