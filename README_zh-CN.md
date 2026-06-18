# quicz

[English](README.md) | 简体中文

`quicz` 是一个使用 [Zig](https://ziglang.org/) 实现的 QUIC 协议栈，目标对齐 IETF QUIC 标准，规范文档见 <https://quicwg.org/>。

> 状态：**实验性 / 开发中（WIP）**  
> 目标：实现一个与成熟 QUIC 协议栈共同能力对齐的实用 QUIC transport 子集。可选扩展会明确追踪，不作为第一轮可用 transport 的必需条件。

## 特性与路线图

### 已实现 / 正在进行

- [x] 可构建的 Zig package，包含 `Connection`、frame-payload 示例和可运行 loopback 示例。
- [x] varint、packet header、packet number、frame、transport parameter、transport error（含 RFC 9368 version-negotiation close 分类）、Version Negotiation 和 compatible-version selection helper、Retry、stateless reset、QUIC v2 packet/key/token primitive 的核心 codec 覆盖。
- [x] 面向 stream、CRYPTO byte stream、flow control、connection ID、Retry/token、path validation、close/idle timer、packet number space 和 invalid frame payload rollback 的实验性内存态 transport state。
- [x] QUIC v1/v2 Initial key、Retry integrity、protected long/short packet、配置驱动 v2 protected long-packet/Retry wire version、installed-key mock TLS handoff 和 key update state helper。
- [x] 简化 RFC 9002 风格 ACK、loss、PTO、NewReno congestion、congestion-window 发送预算/满窗口查询、ECN、retransmission 和 endpoint recovery-timer 模型，并有 socket-backed UDP loopback 覆盖。
- [x] 内存态 endpoint routing/lifecycle helper，覆盖 DCID 和 IPv4 UDP tuple routing、Version Negotiation、zero-length CID routing、preferred/replacement CID routing、route retirement、stateless reset emission 和 protected UDP loopback。
- [ ] 完整 connection state machine 与 TLS-owned protected-packet packet number space routing。
- [ ] Endpoint-owned TLS-backed socket client/server echo，由 live TLS handshake 驱动 UDP packet routing、自动 traffic-secret 安装和 1-RTT STREAM delivery。
- [ ] 可嵌入 socket API，让调用方自持 UDP socket、connection map、timer 和 datagram 输出队列。
- [ ] 面向 `handshake` 和 `transfer` 的最小外部互通入口。
- [ ] 完整 RFC 9002 loss detection / congestion control，含 socket-owned protected-packet loss/PTO lifecycle integration 与剩余 NewReno 边界。
- [ ] TLS 1.3 集成（RFC 9001）。
- [ ] QUIC v2（RFC 9369）完整版本行为支持。

### 规划里程碑

1. **最小 QUIC v1 子集**
   - 单路径、仅 IPv4
   - 固定 QUIC v1 版本（0x00000001）
   - 支持 Initial / Handshake / 0-RTT / 1-RTT 包
   - 支持基础 STREAM / ACK / PADDING / CONNECTION_CLOSE 帧
2. **TLS 1.3 + 完整握手**
   - 基于 CRYPTO 帧的 TLS 握手集成
   - 密钥派生与包加密保护
3. **丢包检测与拥塞控制**
   - 基于 RFC 9002 的算法（初期会采用类似 NewReno 的实现）
4. **QUIC v2 与高级特性**
   - QUIC v2 版本（0x6b3343cf），已支持 Initial key 派生、long-header type bits、按配置使用 protected long-packet 与 Retry version、Retry integrity、token version 隔离和 RFC 9368 version information，剩余 v2 行为仍待实现
   - 路径迁移、更完整的路径验证策略、stateless reset

### 实用目标边界

第一轮可用目标不是“实现所有 QUIC 可选项”。目标是一个 TLS-backed QUIC v1
client/server stream transport，具备 UDP endpoint lifecycle ownership、transport
parameter exchange、packet protection、双向和单向 stream、flow control、stream
reset/STOP_SENDING、ACK/loss/PTO recovery、congestion control、close/idle
handling、connection ID、path validation、Retry/address validation、stateless reset
和互通证据。

HTTP/3/QPACK、RFC 9221 DATAGRAM、完整 QUIC v2 / RFC 9368 version negotiation、
multi-path、qlog、GSO/GRO、PMTU discovery 和高级 congestion-controller selection
会在任务计划中追踪，但除非选定互通目标要求，否则不作为第一轮可互通 transport
里程碑的必需条件。

可验证 transport 实现任务计划见 [`docs/zh-CN/quic_transport_tasks.md`](docs/zh-CN/quic_transport_tasks.md)。
关键名词、系统架构、核心协议流程和开发扩展入口见
[`docs/zh-CN/architecture.md`](docs/zh-CN/architecture.md)。
更详细的设计和逐功能说明见 [`docs/zh-CN/`](docs/zh-CN/) 目录。

## 快速开始

需要安装 Zig **0.16.0**。当前构建会强制校验这个精确测试版本，避免 Zig 标准库变化静默改变行为。

### 构建并运行示例

```bash
zig build
zig build test --summary all
zig build run-codec
zig build run-initial-keys
```

`zig build` 会构建 `zig-out/lib/libquicz.a` 静态库，以及 `zig-out/bin/` 下的所有示例二进制。当前示例是确定性的协议行为练习，还不是可互操作的 QUIC-over-UDP 程序。

常用可运行示例：

- `run-tls-openssl-backend-adapter`：OpenSSL-backed C TLS adapter 路径，覆盖本端
  transport parameters、第一段 TLS CRYPTO flight，以及 pair-transcript server
  transport-parameter、Handshake/1-RTT secret 和入站 CRYPTO 经 OpenSSL callback
  边界投递到连接层；现在也会把 adapter 产出的 Initial CRYPTO flight 作为 protected
  Initial datagram 通过 loopback UDP 投递，把真实 OpenSSL pair transcript 的
  Handshake CRYPTO 作为 protected Handshake datagram 通过 loopback UDP 投递，复用匹配 Handshake/1-RTT
  secrets，并用 adapter 安装的 client keys 和匹配 peer transcript secrets 驱动
  loopback UDP 1-RTT STREAM echo，并通过同一个 lifecycle owner 服务 Application
  PTO；OpenSSL recv/release 消费入站 Handshake CRYPTO 后，OpenSSL-backed
  `handshake_confirmed` callback 确认 client，并通过 endpoint lifecycle-owned no-output
  Handshake drive 丢弃 client Handshake packet-number space 和 keys；配对 loopback server 也会通过
  loopback UDP 消费 client Handshake CRYPTO，经 backend 拉取 peer transport
  parameters 和 Handshake/1-RTT secrets，完成确认并清理 Handshake keys；direct
  server probe 也会消费 Handshake CRYPTO 并报告 `server_probe_confirmed=true`，随后通过同一个
  socket/lifecycle loop owner 投递 protected close 并完成 route cleanup。
- `run-tls-openssl-pair-transcript`：OpenSSL client/server callback-mode TLS
  transcript，覆盖按 protection level 分离的 CRYPTO handoff，以及双端 peer
  transport-parameter 和 traffic-secret callback，并把生成的 CRYPTO bytes 映射进
  quicz Initial/Handshake/Application CRYPTO 队列；示例会记录并解析按角色区分的 peer
  transport-parameter bytes，这些 bytes 来自 quicz 本端 transport-parameter export
  后配置给 OpenSSL 的 TLS extension，也会记录 keylog callback 次数和字节数，但不打印 key
  material；client Initial CRYPTO bytes 还会经 quicz protected
  Initial long-packet helper 发送，并由 server connection 读回；
  双向 Initial flight 也会通过 quicz endpoint lifecycle 在 loopback UDP 上投递；
  另有手动 OpenSSL context 检查会把 live Initial/Handshake TLS CRYPTO bytes
  通过同一 socket/lifecycle 边界路由；
  OpenSSL Handshake secrets 也会驱动双向 installed-key protected Handshake CRYPTO
  投递，包括通过同一个 lifecycle 的 loopback UDP 投递；同一个手动 OpenSSL context
  还会安装匹配的 1-RTT secrets，并通过同一 socket/lifecycle 路径驱动一次 quicz
  STREAM request/echo/final-ACK，随后丢弃 Handshake 状态并完成双端 lifecycle route
  close cleanup；完整 OpenSSL pair transcript 也会单独验证 installed-key short-packet
  STREAM request/response 和 socket echo。
- `run-udp-echo-loopback`：socket-backed installed-key STREAM echo，包含
  payload equality、ACK cleanup 和 recovery timer cleanup。
- `run-udp-pto-recovery-loopback`、`run-udp-loss-recovery-loopback` 和
  `run-udp-congestion-recovery-loopback`：loopback UDP 上 lifecycle-routed recovery
  与 congestion 行为。
- `run-udp-close-lifecycle-loopback` 和 `run-udp-stateless-reset-loopback`：通过
  endpoint lifecycle owner 驱动 route cleanup 和 reset 行为。

### 作为库使用

高层 API 形态仍可能演进：

```zig
const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var conn = try quicz.Connection.init(
        gpa,
        .client,
        .{
            .max_datagram_size = 1350,
            .initial_rtt_ms = 333,
            .initial_max_data = 65_536,
            .initial_max_stream_data = 65_536,
            .initial_max_streams_bidi = 64,
            .initial_max_streams_uni = 64,
        },
    );
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendCrypto("client-hello-bytes"[0..]);
    try conn.sendPing();
    try conn.sendOnStream(stream_id, "hello, quicz"[0..], true);

    const tx = try conn.pollTx(0);
    defer if (tx) |bytes| gpa.free(bytes);
}
```

当前 `pollTx()` / `processDatagram()` 路径传输未加密的 frame payload 字节。Protected
packet helper、endpoint routing、recovery timer 和 mock TLS handoff 已可用于确定性协议测试；
完整 TLS-owned UDP packetization 仍待实现。`EndpointConnectionLifecycle` 现在提供核心
socket-loop 和 TLS-backend loop 入口 `feedDatagram`、`feedDatagramWithInstalledKeys`、
`feedDatagramWithInstalledKeysAcrossConnections`、`processPendingWork`、
`processAcceptedProtectedInitialWithCryptoBackendAndPollDatagram`、
`processAcceptedProtectedInitialWithCryptoBackendOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagram`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`processPendingWorkAcrossConnections`、`processPendingWorkAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`processPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagram`、
`processPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagrams`、
`processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`、
`processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`processPendingWorkAndDrainDatagrams`、
`processDueDeadlineAndPollDatagram`、`processDueDeadlineAndDrainDatagrams`、
`processDueDeadlineAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendInSpaceAndPollDatagram`、
`processDueDeadlineAndDriveCryptoBackendInSpaceAndDrainDatagrams`、
`processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`、
`processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAcrossConnectionsAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`pollDatagram`、`drainDatagramsAcrossConnections`、`pollDatagramAcrossConnections`、
`driveCryptoBackendsInSpaceAndArmConnections`、
`driveCryptoBackendsInSpaceAndPollDatagram`、
`driveCryptoBackendInSpaceAndPollDatagram`、
`driveCryptoBackendsInSpaceAndDrainDatagrams`、
`driveCryptoBackendInSpaceAndDrainDatagrams`、
`driveCryptoBackendsInSpaceOrCloseAndArmConnections`、
`driveCryptoBackendsInSpaceOrCloseAndPollDatagram`、
`driveCryptoBackendInSpaceOrCloseAndPollDatagram`、
`driveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`、
`driveCryptoBackendInSpaceOrCloseAndDrainDatagrams`、
`driveCryptoBackendsInSpaceWithCompatibleVersionAndArmConnections`、
`driveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`、
`driveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`、
`driveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`、
`driveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`、
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndArmConnections`、
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`driveCryptoBackendInSpaceAndDrainProtectedLongCryptoDatagrams`、
`driveCryptoBackendInSpaceOrCloseAndDrainProtectedLongCryptoDatagrams`、
`processProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams`、
`processProtectedLongDatagramInSpaceAndDriveCryptoBackendOrCloseAndDrainDatagrams`、
`processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams`、
`processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendOrCloseAndDrainDatagrams`、
`processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams`、
`processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendOrCloseAndDrainDatagrams`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendOrCloseAndDrainDatagrams`、
`drainProtectedLongCryptoDatagramsInSpace`、
`processAcceptedProtectedInitialWithCryptoBackendAndDrainDatagrams`、
`nextDeadline` 和
`nextDeadlineAcrossConnections`，用于 routing、
installed-key packet receive、跨连接 receive dispatch、accepted Initial 到 backend server
response 和 close propagation、timeout/timer work、due-deadline
service、跨连接 pending-work sweep、跨连接 due-deadline dispatch、recovery wakeup packet
output、installed-key packet output、bounded long-header CRYPTO output drain、跨连接 output dispatch、
cross-connection pending-work-to-output loop step、cross-connection pending-work-to-bounded-drain loop step、receive-to-backend-to-output
loop step、receive-to-backend-to-bounded-drain loop step、caller-owned output queue 的 bounded drain、跨连接 TLS backend drive、
backend-drive-to-datagram output step、backend-drive-to-bounded-drain output step、
single-connection backend-drive-to-datagram output step、
single-connection backend-drive-to-bounded-drain output step、
single-connection compatible-version backend-drive-to-datagram output step、
single-connection compatible-version backend-drive-to-bounded-drain output step、
backend-drive-to-caller-keyed long-header drain step、
close-propagating backend-drive-to-caller-keyed long-header drain step、
caller-keyed receive-to-backend-to-bounded-drain loop step、
caller-keyed receive-to-backend-close-to-bounded-drain loop step、
routed caller-keyed receive-to-backend-to-bounded-drain loop step、
routed caller-keyed receive-to-backend-close-to-bounded-drain loop step、
installed-key Handshake receive-to-backend-to-bounded-drain loop step、
close-propagating installed-key Handshake backend-drain loop step、
routed installed-key Handshake receive-to-backend-to-bounded-drain loop step、
routed installed-key Handshake receive-to-backend-close-to-bounded-drain loop step、
single-connection installed-key receive-to-backend-to-output loop step、
single-connection installed-key receive-to-backend-to-bounded-drain loop step、
single-connection installed-key receive-to-backend-close-to-output loop step、
single-connection installed-key receive-to-backend-close-to-bounded-drain loop step、
single-connection compatible-version receive-to-backend-to-output loop step、
single-connection compatible-version receive-to-backend-to-bounded-drain loop step、
single-connection compatible-version receive-to-backend-close-to-output loop step、
single-connection compatible-version receive-to-backend-close-to-bounded-drain loop step、
single-connection pending-work-to-backend-to-output loop step、
single-connection pending-work-to-backend-to-bounded-drain loop step、
single-connection pending-work-to-backend-close-to-output loop step、
single-connection pending-work-to-backend-close-to-bounded-drain loop step、
single-connection compatible-version pending-work-to-backend-to-output loop step、
single-connection compatible-version pending-work-to-backend-to-bounded-drain loop step、
single-connection compatible-version pending-work-to-backend-close-to-output loop step、
single-connection compatible-version pending-work-to-backend-close-to-bounded-drain loop step、
single-connection due-deadline-to-backend-to-output loop step、
single-connection due-deadline-to-backend-to-bounded-drain loop step、
single-connection due-deadline-to-backend-close-to-output loop step、
single-connection due-deadline-to-backend-close-to-bounded-drain loop step、
single-connection compatible-version due-deadline-to-backend-to-output loop step、
single-connection compatible-version due-deadline-to-backend-to-bounded-drain loop step、
single-connection compatible-version due-deadline-to-backend-close-to-output loop step、
single-connection compatible-version due-deadline-to-backend-close-to-bounded-drain loop step、
pending-work-to-bounded-drain loop step、pending-work-to-backend-to-output loop step、pending-work-to-backend-to-bounded-drain
loop step、due-deadline-to-backend-to-output loop
step、due-deadline-to-bounded-drain loop step、due-deadline-to-backend-to-bounded-drain
loop step、cross-connection due-deadline terminal-cleanup backend suppression、
close-propagating TLS backend drive、RFC 9368 compatible-version backend sweep，
以及 caller-owned connection map 上的 event-loop wakeup selection；
`EndpointConnectionDeadline.installedKeyPollOptions()`
会把 `nextDeadline()` 返回的 recovery wakeup 映射为 Handshake 和 1-RTT 路径的
installed-key poll options；`processDueDeadlineAndPollDatagramWithInstalledKeyOptions()` 和
`processDueDeadlineAndDrainDatagramsWithInstalledKeyOptions()` 允许调用方用显式
installed-key 输出选择服务到期 recovery wakeup，例如 accepted 0-RTT；跨连接
`WithInstalledKeyOptions` 变体会在调用方持有的 connection map 中选择最早到期连接，同时保留
相同的显式输出选择；single-connection due-deadline-to-backend poll 和 drain wrapper 也会在
backend drive 前保留显式 0-RTT recovery output；cross-connection due-deadline-to-backend
poll/drain 的 `WithInstalledKeyOptions` 变体会在 backend sweep 前保留同样的显式选择；生产级
TLS-owned socket event loop 仍待实现。

`Connection` 是当前推荐的公开连接句柄；`QuicConnection` 作为兼容别名保留，便于旧调用方在实验性 API 继续演进期间平滑迁移。

## 示例

- [Echo server](examples/echo_server.zig)：最小 frame-payload echo server 骨架。
  运行：`zig build run-server`。
- [Echo client](examples/echo_client.zig)：最小 frame-payload echo client 骨架。
  运行：`zig build run-client`。
- [Codec roundtrip](examples/codec_roundtrip.zig)：varint、packet header、Version Negotiation（含显式 compatible-version selection 和 RFC 9368 downgrade close-code 证据）、frame、transport parameter 和 error codec 往返。
  运行：`zig build run-codec`。
- [Transport parameters](examples/transport_parameters.zig)：transport parameter 导出、解析、应用（含 compatible-version selection）和错误关闭行为。
  运行：`zig build run-transport-parameters`。
- [Flow control](examples/flow_control.zig)：connection、stream、stream-count、MAX_STREAMS overflow 拒绝和 BLOCKED/MAX frame 行为。
  运行：`zig build run-flow-control`。
- [Unidirectional streams](examples/uni_stream.zig)：本端与对端 unidirectional stream 打开和校验。
  运行：`zig build run-uni-stream`。
- [Stream reset](examples/stream_reset.zig)：RESET_STREAM 发送/接收行为、重传边界、带 reset-read/reset-acked 证据的 stream 状态快照，以及 reset 后发送 credit 关闭。
  运行：`zig build run-stream-reset`。
- [STOP_SENDING](examples/stop_sending.zig)：STOP_SENDING 接收处理，以及 RESET_STREAM 响应的 stream 状态快照证据。
  运行：`zig build run-stop-sending`。
- [CRYPTO streams](examples/crypto_stream.zig)：按 packet number space 隔离的 CRYPTO buffering、接收缓冲超限 auto-close、mock backend handoff、protected backend transport-parameter auto-close、compatible backend Version Information handoff progress、backend-confirmed Handshake key discard 和 protected CRYPTO flow。
  运行：`zig build run-crypto-stream`。
- [TLS backend adapter](examples/tls_backend_adapter.zig)：把 C-ABI `TlsBackend`
  callback 适配到现有 `CryptoBackend` drive 路径，并输出本端/对端
  transport-parameter handoff、CRYPTO bytes、Handshake traffic secret 和
  confirmation 证据。运行：`zig build run-tls-backend-adapter`。
- [TLS C ABI adapter](examples/tls_c_abi_adapter.zig)：把 C 编译单元里的 callback
  object 接到 `TlsBackend`，证明绑定具体 TLS 库之前，adapter 能从 C 边界驱动。
  运行：`zig build run-tls-c-abi-adapter`。
- [TLS OpenSSL probe](examples/tls_openssl_probe.zig)：通过 `pkg-config` 链接
  OpenSSL，验证 OpenSSL QUIC method 与 QUIC TLS callback/transport-parameter
  API，并记录 callback mode 不等于 OpenSSL 完整 QUIC connection mode。
  运行：`zig build run-tls-openssl-probe`。
- [TLS OpenSSL pair transcript](examples/tls_openssl_pair_transcript.zig)：使用固定
  PSK 的 OpenSSL client/server callback-mode TLS transcript 示例，覆盖按
  protection level 分离的 CRYPTO handoff、peer transport-parameter callback，以及双端
  Handshake/1-RTT traffic-secret callback，并把生成的 CRYPTO bytes 投递到 quicz
  packet-number-space CRYPTO 队列；示例会把 quicz 编码的本端 transport-parameter bytes
  配置给 OpenSSL，记录并解析 OpenSSL callback 收到的 peer bytes，也会记录 keylog
  callback 次数和字节数，但不打印 key material；同时会把 client Initial CRYPTO bytes 经 quicz protected Initial
  long-packet helper 组包，并通过 quicz endpoint lifecycle 在
  loopback UDP 上投递双向 Initial flight，并验证一段手动 OpenSSL
  Initial/Handshake transcript 也能走同一 socket 路径；安装 OpenSSL 产出的
  Handshake secrets，并验证双向 protected Handshake CRYPTO 投递，包括通过同一个 lifecycle 的 loopback UDP 投递；
  同一个手动 OpenSSL context 还会安装 OpenSSL 产出的 1-RTT secrets，并通过同一
  socket 路径驱动 STREAM request/echo 和 final ACK，随后验证 Handshake key discard
  和 protected close/route cleanup；完整 pair transcript 也会用 OpenSSL 产出的
  1-RTT secrets 验证 installed-key protected STREAM request/response 与 loopback UDP
  STREAM echo。运行：
  `zig build run-tls-openssl-pair-transcript`。
- [TLS OpenSSL backend adapter](examples/tls_openssl_backend_adapter.zig)：把
  OpenSSL-backed `TlsBackend` wrapper 接到 endpoint lifecycle-owned backend drive 路径，通过
  `SSL_set_quic_tls_transport_params()` 接收 quicz 本端 transport parameters，驱动
  `SSL_do_handshake()` 产出第一段 TLS CRYPTO flight，并让 pair-transcript server
  transport parameters（由 quicz 本端 export 编码后配置到 OpenSSL）、真实 pair-transcript Handshake/1-RTT secrets 和入站
  Handshake CRYPTO bytes 经 OpenSSL callback 边界进入连接层；同时把 adapter 产出的
  Initial CRYPTO flight 作为 protected Initial datagram 通过 loopback UDP 投递，把真实
  pair-transcript Handshake CRYPTO 作为 protected Handshake datagram 通过 loopback UDP
  投递，并用 adapter 安装的 client keys 和匹配 peer transcript secrets 驱动 loopback UDP 1-RTT STREAM echo，
  同时通过同一个 lifecycle owner 服务 Application PTO；OpenSSL recv/release 消费入站
  Handshake CRYPTO 后，OpenSSL-backed `handshake_confirmed` callback 确认 client，
  并通过 no-output Handshake drive 丢弃 client Handshake packet-number space 和 keys；
  server connection probe 也会通过 backend 拉取真实 pair-transcript 1-RTT secrets，
  确认 server connection，并记录 OpenSSL secret callbacks 和已应用 transport
  parameters 里的 peer stream-count limit，随后丢弃 server Handshake packet-number
  space 和 keys；再通过同一个
  socket/lifecycle loop owner 投递 protected close 并完成 route cleanup。输出也会证明
  已消费的 transcript transport-parameter bytes 与连接层应用的 peer bytes 一致，同时打印
  transcript keylog 证据和当前 wrapper keylog 边界。
  运行：`zig build run-tls-openssl-backend-adapter`。
- [Graceful close](examples/graceful_close.zig)：本端/对端关闭、protected long/short close、非法 ACK/ACK_ECN range auto-close、包含非法 ACK/ACK_ECN、0-RTT ACK/ACK_ECN packet-type 违规、非法 STREAMS_BLOCKED limit、冲突 STREAM data 和非法 stream control frame 的语义 frame 错误 auto-close、protected receive auto-close、lifecycle-routed protected auto-close、protected long/0-RTT close-state discard、draining 行为和关闭触发校验。
  运行：`zig build run-graceful-close`。
- [Idle timeout](examples/idle_timeout.zig)：建模 idle timeout 导出、刷新、关闭行为和 endpoint route/timer 清理。
  运行：`zig build run-idle-timeout`。
- [Packet spaces](examples/packet_spaces.zig)：Initial、Handshake、0-RTT 和 Application packet-number-space 行为。
  运行：`zig build run-packet-spaces`。
- [ECN validation](examples/ecn_validation.zig)：ACK_ECN 校验和 CE 驱动的 congestion response。
  运行：`zig build run-ecn-validation`。
- [Loss recovery](examples/loss_recovery.zig)：ACK 驱动的 loss、RTT sampling、NewReno recovery-period ACK accounting、loss/CE-driven congestion probe、persistent-congestion min-RTT refresh、recovery-period 清理/重新进入和非连续 persistent-congestion 抑制。
  运行：`zig build run-loss-recovery`。
- [PTO recovery](examples/pto_recovery.zig)：PTO timer、probe selection、backoff、client anti-deadlock PTO、anti-amplification gating/unblock service 和已 ACK 的 RESET_STREAM 重传抑制。
  运行：`zig build run-pto-recovery`。
- [Endpoint recovery timers](examples/endpoint_recovery_timers.zig)：跨 connection handle 的 endpoint-owned recovery timer 调度、caller-keyed/installed-key protected long/short probe polling 和 routed protected receive refresh。
  运行：`zig build run-endpoint-recovery-timers`。
- [Path validation](examples/path_validation.zig)：PATH_CHALLENGE/PATH_RESPONSE 重试、重复 pending response 抑制、1200 字节 protected path-validation datagram 和验证驱动的 lifecycle route update。
  运行：`zig build run-path-validation`。
- [Address validation](examples/address_validation.zig)：HMAC address-validation token、version binding、secret rotation、replay snapshot、lifecycle-owned HANDSHAKE_DONE/NEW_TOKEN emission/delivery timer 证据和 lifecycle-owned token validation unblocking。
  运行：`zig build run-address-validation`。
- [UDP address validation loopback](examples/udp_address_validation_loopback.zig)：socket-backed lifecycle-owned HANDSHAKE_DONE/NEW_TOKEN emission/delivery timer 证据、带 changed-path rejection 证据的 NEW_TOKEN path/version binding、secret rotation、replay snapshot restore rejection 和 lifecycle-owned address-validation block/unblock 证据。
  运行：`zig build run-udp-address-validation-loopback`。
- [Retry token](examples/retry_token.zig)：Retry datagram 处理、lifecycle-owned token validation/consumption、token 复用拒绝和 Retry CID transport-parameter byte 校验。
  运行：`zig build run-retry-token`。
- [Connection IDs](examples/connection_ids.zig)：NEW_CONNECTION_ID、RETIRE_CONNECTION_ID、lifecycle-owned issue/register route bridge 和 replacement state。
  运行：`zig build run-connection-ids`。
- [Stateless reset](examples/stateless_reset.zig)：reset token 匹配和 inactive-CID reset 构造。
  运行：`zig build run-stateless-reset`。
- [Initial keys](examples/initial_keys.zig)：QUIC v1/v2 Initial key 派生和配置驱动 v2 Initial packetization。
  运行：`zig build run-initial-keys`。
- [Endpoint routing](examples/endpoint_routing.zig)：内存态 DCID、tuple、Version Negotiation、Retry 和 reset routing。
  运行：`zig build run-endpoint-routing`。
- [UDP endpoint loopback](examples/udp_endpoint_loopback.zig)：socket-backed endpoint routing，覆盖 Version Negotiation、protected follow-up Initial、follow-up Original DCID 证据、accepted protected Initial processing、protected server Initial response processing、server transport-parameter byte validation 和 Initial/short-header classification。
  运行：`zig build run-udp-endpoint-loopback`。
- [UDP zero-CID loopback](examples/udp_zero_cid_loopback.zig)：基于 loopback UDP 的 zero-length CID tuple routing、unknown tuple 拒绝和 route update。
  运行：`zig build run-udp-zero-cid-loopback`。
- [UDP preferred address loopback](examples/udp_preferred_address_loopback.zig)：preferred-address transport-parameter byte handoff、route migration 和 active-migration-disabled 处理。
  运行：`zig build run-udp-preferred-address-loopback`。
- [UDP replacement CID loopback](examples/udp_replacement_cid_loopback.zig)：replacement CID 注册、retire_prior_to 处理和 reset-token 保留。
  运行：`zig build run-udp-replacement-cid-loopback`。
- [UDP connection IDs loopback](examples/udp_connection_ids_loopback.zig)：lifecycle-routed protected NEW_CONNECTION_ID/RETIRE_CONNECTION_ID、endpoint issue/register route bridge、active replacement routing 与 ACK 交换。
  运行：`zig build run-udp-connection-ids-loopback`。
- [UDP protected loopback](examples/udp_protected_loopback.zig)：lifecycle-owned accepted protected Initial processing、protected server Initial response processing，以及 routed caller-keyed 1-RTT loopback UDP processing。
  运行：`zig build run-udp-protected-loopback`。
- [UDP Handshake keys loopback](examples/udp_handshake_keys_loopback.zig)：socket-backed lifecycle-routed installed-key Handshake CRYPTO delivery、ACK cleanup 和已服务的 installed-key Handshake PTO probe routing。
  运行：`zig build run-udp-handshake-keys-loopback`。
- [UDP Crypto stream loopback](examples/udp_crypto_stream_loopback.zig)：socket-backed mock `CryptoBackend` Handshake CRYPTO byte handoff、transport-parameter exchange 和 routed ACK cleanup。
  运行：`zig build run-udp-crypto-stream-loopback`。
- [UDP 0-RTT loopback](examples/udp_zero_rtt_loopback.zig)：socket-backed lifecycle-routed installed-key 0-RTT STREAM delivery、accept-before-process enforcement、rejection-driven key discard、已服务的 installed-key 0-RTT PTO probe routing 与重复 STREAM discard 证据、accepted early ACK 证据、1-RTT ACK cleanup 和 client/server 0-RTT key discard 证据。
  运行：`zig build run-udp-zero-rtt-loopback`。
- [UDP 1-RTT loopback](examples/udp_one_rtt_loopback.zig)：socket-backed lifecycle-routed installed-key 1-RTT STREAM delivery、已服务的 installed-key 1-RTT PTO probe routing 与重复 STREAM discard 证据，以及 ACK cleanup。
  运行：`zig build run-udp-one-rtt-loopback`。
- [UDP echo loopback](examples/udp_echo_loopback.zig)：socket-backed lifecycle-routed installed-key 1-RTT STREAM echo、request/echo payload equality、已服务的 server-side 1-RTT PTO probe routing 与重复 STREAM discard 证据、final ACK cleanup 和 client/server bytes-in-flight/timer-state 证据。
  运行：`zig build run-udp-echo-loopback`。
- [UDP CryptoBackend loopback](examples/udp_crypto_backend_loopback.zig)：socket-backed mock `CryptoBackend` 1-RTT traffic-secret handoff、lifecycle-routed installed-key STREAM echo、client/server installed-key PTO probe routing 与重复 STREAM discard 证据、final ACK cleanup，以及 client/server bytes-in-flight 和 recovery-timer deadline/cleanup 证据。
  运行：`zig build run-udp-crypto-backend-loopback`。
- [UDP HANDSHAKE_DONE loopback](examples/udp_handshake_done_loopback.zig)：socket-backed lifecycle-routed installed-key HANDSHAKE_DONE confirmation、server/client Handshake key discard 和公开 state 证据，以及 ACK pending/cleanup 输出。
  运行：`zig build run-udp-handshake-done-loopback`。
- [UDP flow control loopback](examples/udp_flow_control_loopback.zig)：lifecycle-routed protected STREAM/BLOCKED/MAX flow-control loopback UDP 交换，并输出恢复发送后的 FIN final-size 证据，以及 caller-keyed resumed STREAM PTO probe routing 与重复 discard 证据。
  运行：`zig build run-udp-flow-control-loopback`。
- [UDP spin bit loopback](examples/udp_spin_bit_loopback.zig)：lifecycle-routed protected short packet 上的可配置单路径 spin-bit signaling 和 route-update spin reset。
  运行：`zig build run-udp-spin-bit-loopback`。
- [UDP ECN validation loopback](examples/udp_ecn_validation_loopback.zig)：loopback UDP 上 lifecycle-routed 建模 ECN state 和 ACK_ECN validation。
  运行：`zig build run-udp-ecn-validation-loopback`。
- [UDP loss recovery loopback](examples/udp_loss_recovery_loopback.zig)：lifecycle-routed protected ACK 驱动 packet loss 和 timer-driven cleanup。
  运行：`zig build run-udp-loss-recovery-loopback`。
- [UDP congestion recovery loopback](examples/udp_congestion_recovery_loopback.zig)：loopback UDP 上 lifecycle-routed NewReno recovery-period、persistent-congestion 和 ACK_ECN CE-driven STREAM probe 行为，并输出 repeated-loss suppression、minimum-window 和 CE probe 证据。
  运行：`zig build run-udp-congestion-recovery-loopback`。
- [UDP PTO recovery loopback](examples/udp_pto_recovery_loopback.zig)：endpoint lifecycle timer service、protected long/short 和 installed-key 0-RTT PTO probe polling、routed receive processing 和 retransmission choice。
  运行：`zig build run-udp-pto-recovery-loopback`。
- [UDP STREAM retransmission loopback](examples/udp_stream_retransmission_loopback.zig)：通过 lifecycle-routed protected receive 执行 ACK-loss-triggered STREAM retransmission。
  运行：`zig build run-udp-stream-retransmission-loopback`。
- [UDP key update loopback](examples/udp_key_update_loopback.zig)：经 lifecycle route 的 installed-key key update、key phase advancement、第二次 update PTO probe routing、stale old-generation packet rejection，以及带可观测 ACK threshold、generation-count 和 retained-generation old-key discard 证据的 ACK gating。
  运行：`zig build run-udp-key-update-loopback`。
- [UDP path validation loopback](examples/udp_path_validation_loopback.zig)：在新 peer port 上执行带 close-propagating receive 的 lifecycle-routed PATH_CHALLENGE/PATH_RESPONSE 验证驱动 route update，并证明验证前 PING 不会提交 route update。
  运行：`zig build run-udp-path-validation-loopback`。
- [UDP Retry loopback](examples/udp_retry_loopback.zig)：lifecycle-owned Retry delivery、token validation/consumption 和 follow-up Initial acceptance/processing。
  运行：`zig build run-udp-retry-loopback`。
- [UDP close lifecycle loopback](examples/udp_close_lifecycle_loopback.zig)：lifecycle-routed protected close delivery、protected receive auto-close、close/drain deadline 证据、timeout-driven route cleanup、route retirement 和 stateless reset follow-up。
  运行：`zig build run-udp-close-lifecycle-loopback`。
- [UDP stateless reset loopback](examples/udp_stateless_reset_loopback.zig)：socket-backed active-route suppression、unknown-CID drop、reset trigger delivery、reset emission 和 client token match。
  运行：`zig build run-udp-stateless-reset-loopback`。

## 高级主题

- [传输任务矩阵](docs/zh-CN/quic_transport_tasks.md)：当前 RFC 覆盖、剩余工作和验证证据。
- [架构与术语](docs/zh-CN/architecture.md)：关键名词、模块边界、核心协议流程、开发扩展和排障入口。
- [设计说明](docs/zh-CN/spec.md)：当前架构、协议范围和未支持区域。
- 包保护：QUIC v1/v2 Initial key、Retry integrity、protected packet helper 和 key-update state。
- 端点生命周期：DCID routing、route retirement、stateless reset lookup/emission 和 endpoint recovery timer。
- 恢复与拥塞：简化 RFC 9002 ACK/loss/PTO/NewReno/ECN 模型，并有确定性测试覆盖。
- TLS 状态：已有 mock `CryptoBackend` handoff 和很小的 C-ABI `TlsBackend` adapter；
  `run-tls-openssl-probe` 已链接 OpenSSL 并验证 QUIC TLS callback API，
  `run-tls-openssl-pair-transcript` 已完成 OpenSSL client/server callback-mode TLS
  transcript，按 protection level 分离 CRYPTO handoff，把生成的 bytes 映射进 quicz
  CRYPTO 队列，并验证 protected Initial long-packet 投递和双向 Initial flight 的
  socket-backed 投递，以及手动 OpenSSL Initial/Handshake transcript 通过同一
  socket/lifecycle 边界路由；还会验证使用 OpenSSL Handshake secrets 的 installed-key protected
  Handshake 投递（含 socket-backed 投递）、同一个手动 context 的 1-RTT STREAM echo
  经同一 socket/lifecycle 路径投递、同一 context 的 Handshake key discard 和
  protected close/route cleanup，以及使用 OpenSSL 1-RTT secrets 的 installed-key protected
  STREAM request/response 与 socket-backed STREAM echo；
  `run-tls-openssl-backend-adapter` 已把 OpenSSL object 接入 adapter 路径并
  产出第一段 TLS CRYPTO flight，也能让 peer transport parameters、真实
  pair-transcript Handshake/1-RTT secrets 和入站 CRYPTO 经 callback 边界进入连接层，
  并把 adapter 产出的 Initial CRYPTO flight 和真实 pair-transcript Handshake CRYPTO
  作为 protected Initial/Handshake datagram 通过 loopback UDP 投递，随后用 adapter
  安装的 client keys 和匹配 peer transcript secrets 驱动 loopback UDP 1-RTT STREAM
  echo，并通过同一个 lifecycle owner 服务 Application PTO；OpenSSL recv/release 消费入站
  Handshake CRYPTO 后，OpenSSL-backed `handshake_confirmed` callback 确认 client，
  并通过 lifecycle-owned no-output Handshake drive 丢弃 client Handshake packet-number space 和 keys；
  server connection probe 也会通过 backend 拉取真实 pair-transcript 1-RTT secrets，
  确认 server connection，并记录 OpenSSL secret callbacks 和已应用 transport
  parameters 里的 peer stream-count limit，随后丢弃 server Handshake packet-number
  space 和 keys；配对
  loopback server 也会通过 loopback UDP 消费 client Handshake CRYPTO，经 backend 拉取
  peer transport parameters 和 Handshake/1-RTT secrets，完成确认并清理 Handshake
  keys；direct server probe 也会消费 Handshake CRYPTO 并报告
  `server_probe_confirmed=true`；随后通过同一个
  socket/lifecycle loop owner 投递 protected close 与清理 route；完整 endpoint-owned live
  TLS handshake/socket loop 仍待实现。

## 许可证

MIT
