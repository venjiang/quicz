# quicz 架构与术语

本文说明 quicz 的关键名词、模块边界、核心协议流程和开发扩展入口。可验证任务计划见
[`quic_transport_tasks.md`](quic_transport_tasks.md)，逐功能实现细节见
[`spec.md`](spec.md)。

## 当前定位

quicz 目前聚焦 QUIC transport core：连接状态、包保护、CRYPTO/STREAM frame、
transport parameters、ACK/loss/PTO、拥塞控制、连接 ID、path validation、Retry、
stateless reset 和 endpoint lifecycle。TLS 由外部 C TLS 库通过很小的 adapter 接入；
quicz 不在仓库内自研 TLS。

当前文档中的“核心协议流程”指 transport 内部状态流转，不代表某个上层应用业务。
HTTP/3、QPACK、DATAGRAM、完整互通矩阵和生产 socket API 仍按任务计划逐步推进。

## 关键名词

- Endpoint：UDP 端点和连接生命周期拥有者，负责按连接 ID 与路径路由 datagram，并维护
  route cleanup、timer、stateless reset 等 endpoint 级状态。
- Connection：单条 QUIC 连接的 transport 状态机，处理 packet number space、frame、
  stream、transport parameter、close 和 recovery 状态。
- Connection ID：QUIC 用于路由连接的标识。DCID 是包上的 destination connection ID，
  SCID 是 source connection ID。
- Path：本端/对端 UDP 地址组合及其验证状态。path validation、migration、Retry 和
  address validation 都围绕该边界展开。
- Packet number space：Initial、Handshake、Application 三类包号空间。不同空间拥有独立
  ACK、CRYPTO 数据和密钥生命周期。
- CRYPTO stream：TLS handshake bytes 在 QUIC transport 内的承载通道。它不是应用 stream，
  但使用类似流偏移的乱序重组规则。
- Stream：应用数据通道，分为双向和单向 stream，受 flow control、reset、STOP_SENDING
  和 stream state machine 约束。
- Transport parameters：QUIC 握手期间交换的 transport 配置，例如 stream 限额、
  ACK delay、max UDP payload size、preferred_address 和 version information。
- TLS backend：外部 TLS 库的 adapter。TLS backend 负责 TLS transcript、traffic secret
  和 QUIC TLS callback；quicz 负责把 CRYPTO bytes 放进包、安装 packet protection key、
  并驱动 transport 状态。
- Traffic secrets：TLS 产出的 Initial 之后的 Handshake/1-RTT 密钥材料输入。quicz 用它们
  派生 packet protection key，但不打印 key material。
- Packet protection：QUIC AEAD 加密与 header protection。quicz 已有 Initial、Handshake、
  1-RTT 和 key update 相关 helper。
- Recovery：ACK、loss detection、PTO 和拥塞控制。当前实现使用确定性测试覆盖关键分支。
- Stateless reset：当 endpoint 无法找到连接但能识别 reset token 时，用短包形式让对端停止
  连接尝试的机制。
- Handshake recording：示例中的 OpenSSL 双端握手记录，用来验证 TLS callback、transport
  parameter bytes、traffic secret 和 CRYPTO handoff。它是内部验证记录，不是用户日志，也不是
  完整抓包格式。

## 系统架构

### Public library layer

公开 library 层提供 `Connection`、配置、stream API、frame codec、transport parameter codec
和 recovery 状态。这里应保持 transport 语义清晰，避免把具体 TLS 库、socket 调度策略或示例
fixture 泄漏到核心 API。

`src/lib.zig` 是公开 `quicz` module 的 root source file，应主要作为公开导出和兼容别名的
聚合入口。实现代码按职责逐步放到 `src/quic/` 下；例如
`src/quic/transport_types.zig` 负责共享 transport state enum 和 version compatibility helper，
`src/quic/crypto_types.zig` 负责共享 TLS traffic-secret 和 backend-progress 类型，
`src/quic/endpoint_types.zig` 负责 endpoint lifecycle 共享的结果、deadline、drain、feed 和
datagram 选项契约，
`src/quic/connection_config.zig` 负责公开连接配置和不需要访问连接状态机的固定存储
transport-parameter 值，
`src/quic/connection_version.zig` 负责 version-list selection 和本地 RFC 9368
version-information validation policy，
`src/quic/tls_backend.zig` 负责 C-ABI TLS adapter，`lib.zig` 继续 re-export 稳定公共表面。

从 `src/lib.zig` 迁出实现代码时，应保持公开 module root 稳定，并为需要被 `zig build test`
发现测试的文件增加显式 `test` import。这样既保留 `@import("quicz")` 调用方式，又能按
transport 职责扩展内部模块。

### Packet protection layer

包保护层负责 long/short packet 编解码、AEAD、header protection、Retry integrity、
installed-key 包收发和 key phase 状态。它接收已经安装好的密钥，不关心密钥来自 mock backend
还是 C TLS backend。

### TLS integration boundary

TLS 集成边界由 Zig `TlsBackend`/`CryptoBackend` wrapper 与 translate-c 生成的 C 绑定组成。
构建脚本使用 Zig 0.16 推荐的 `addTranslateC` + `@import("c")` 路径，不手写 C ABI 的
`extern fn`/`extern struct`。

TLS backend 的职责：

- 接收 quicz 编码后的本端 transport parameters；
- 从 QUIC CRYPTO frame 消费 TLS handshake bytes；
- 产出下一段 TLS CRYPTO bytes；
- 通过 callback 提供 peer transport parameters 和 traffic secrets；
- 在 TLS 认为握手完成时通知 quicz。

quicz 的职责：

- 把 TLS CRYPTO bytes 组进正确 packet number space；
- 根据 traffic secrets 安装 packet protection key；
- 把 peer transport parameters 应用到连接状态；
- 管理 ACK、loss、PTO、stream、close 和 route cleanup。

### Endpoint lifecycle layer

Endpoint 层拥有 socket-facing lifecycle：按 DCID 和路径查找连接、创建/退休 route、驱动连接
timer、投递 stateless reset、清理关闭连接。生产 socket API 还在推进中，但 loopback 示例已经
覆盖了多条关键路径。

### Examples and verifiers

`examples/` 目录用于验证核心能力是否能独立运行。每个示例都应该打印稳定、可核对的证据行，
并避免泄漏密钥材料。新增功能时先落核心实现和单测，再用 verifier 证明同一行为可运行。

## 核心协议流程

### Datagram receive path

1. Endpoint 收到 UDP datagram。
2. Endpoint 按 DCID/path 找到连接或进入 Retry/stateless-reset/unknown-CID 分支。
3. Connection 解保护包头和 payload，并按 packet number space 分发 frame。
4. CRYPTO frame 进入 TLS backend；STREAM/ACK/RESET/close frame 更新 transport 状态。
5. Recovery 更新 ACK、loss、PTO 和 congestion state。
6. 调用方或 endpoint lifecycle 轮询待发送 datagram。

### TLS handshake path

1. quicz 导出本端 transport parameters 并配置给 TLS backend。
2. TLS backend 产出 Initial CRYPTO bytes。
3. quicz 把 CRYPTO bytes 放入 Initial packet 并发送。
4. 收到对端 CRYPTO 后，quicz 按空间投递给 TLS backend。
5. TLS backend 回调 peer transport parameters、Handshake secret、1-RTT secret 和 handshake
   confirmation。
6. quicz 应用 peer transport parameters、安装 packet protection key，并在边界满足时丢弃旧
   packet number space。

### 1-RTT stream path

1. 应用或示例打开 stream 并写入数据。
2. Connection 按 flow control 和 stream state 生成 STREAM frame。
3. Packet protection layer 生成 short packet。
4. Endpoint 发送 datagram，并让 recovery 跟踪 in-flight bytes。
5. 对端解保护、重组 stream 数据、回 ACK，并按需要生成响应 STREAM frame。

### Close and cleanup path

1. Connection 进入 application close、transport close、idle timeout 或 stateless reset 分支。
2. quicz 生成 CONNECTION_CLOSE 或 reset 相关输出。
3. Endpoint 抑制不应继续发送的 active route，并清理连接路由。
4. Recovery/timer 不再为已清理 route 产生新的发送副作用。

## 开发扩展入口

- 新 transport frame 或参数：先看 `src/frame.zig`、transport parameter codec 和
  `docs/zh-CN/quic_transport_tasks.md` 对应条目。
- 新 endpoint 行为：先看 endpoint lifecycle、route cleanup、stateless reset 和 loopback 示例。
- 新 TLS backend 能力：保持 C TLS 库在 adapter 边界外，优先扩展 `TlsBackend` wrapper 和
  OpenSSL verifier，不把 TLS 细节写进 transport core。
- 新 recovery 行为：先定义 deterministic test，再补示例证据；非幂等发送路径不得无依据重试。
- 新文档：面向使用者的入口放 README；面向开发者的设计、术语、排障和模块边界放 `docs/`。

## 排障入口

- 构建或测试异常：先运行 `zig build test --summary all`，再缩小到对应 `run-*` 示例。
- TLS/OpenSSL 异常：优先运行 `zig build run-tls-openssl-probe`、
  `zig build run-tls-openssl-pair-transcript` 和
  `zig build run-tls-openssl-backend-adapter`。
- 包保护异常：优先检查 Initial/Handshake/1-RTT key 是否安装到正确 packet number space。
- Endpoint 路由异常：优先检查 DCID、route retirement、path identity 和 stateless reset token。
- Recovery 异常：优先检查 ACK 生成、in-flight bytes、PTO timer 和 congestion window。
