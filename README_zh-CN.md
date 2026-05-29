# quicz

[English](README.md) | 简体中文

`quicz` 是一个使用 [Zig](https://ziglang.org/) 实现的 QUIC 协议栈，目标对齐 IETF QUIC 标准，规范文档见 <https://quicwg.org/>。

> 状态：**实验性 / 开发中（WIP）**  
> 目标：从一个最小但语义正确的子集开始，逐步实现一个完整的 QUIC 传输协议（覆盖 RFC 9000 系列以及 QUIC v2 RFC 9369）。

## Features and Roadmap（特性与路线图）

### Implemented / In Progress（已实现 / 正在进行）

- [x] 可构建的 Zig package，包含 `Connection`、frame-payload 示例和可运行 loopback 示例。
- [x] varint、packet header、packet number、frame、transport parameter、transport error、Version Negotiation、Retry、stateless reset、QUIC v2 packet/key/token primitive 的核心 codec 覆盖。
- [x] 面向 stream、CRYPTO byte stream、flow control、connection ID、Retry/token、path validation、close/idle timer、packet number space 和 invalid frame payload rollback 的实验性内存态 transport state。
- [x] QUIC v1/v2 Initial key、Retry integrity、protected long/short packet、配置驱动 v2 protected long-packet/Retry wire version、installed-key mock TLS handoff 和 key update state helper。
- [x] 简化 RFC 9002 风格 ACK、loss、PTO、NewReno congestion、ECN、retransmission 和 endpoint recovery-timer 模型，并有 socket-backed UDP loopback 覆盖。
- [x] 内存态 endpoint routing/lifecycle helper，覆盖 DCID 和 IPv4 UDP tuple routing、Version Negotiation、zero-length CID routing、preferred/replacement CID routing、route retirement、stateless reset emission 和 protected UDP loopback。
- [ ] 完整 connection state machine 与 TLS-owned protected-packet packet number space routing。
- [ ] 完整 RFC 9002 loss detection / congestion control，含 socket-owned protected-packet loss/PTO lifecycle integration 与剩余 NewReno 边界。
- [ ] TLS 1.3 集成（RFC 9001）。
- [ ] QUIC v2（RFC 9369）完整版本行为支持。

### Planned Milestones（规划的里程碑）

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

可验证 transport 实现任务计划见 [`docs/zh-CN/quic_transport_tasks.md`](docs/zh-CN/quic_transport_tasks.md)。
更详细的设计和逐功能说明见 [`docs/zh-CN/`](docs/zh-CN/) 目录。

## Quick Start（快速开始）

需要安装 Zig **0.16.0**。当前构建会强制校验这个精确测试版本，避免 Zig 标准库变化静默改变行为。

### 构建并运行示例

```bash
zig build
zig build test --summary all
zig build run-codec
zig build run-initial-keys
```

`zig build` 会构建 `zig-out/lib/libquicz.a` 静态库，以及 `zig-out/bin/` 下的所有示例二进制。当前示例是确定性的协议行为练习，还不是可互操作的 QUIC-over-UDP 程序。

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

当前 `pollTx()` / `processDatagram()` 路径传输未加密的 frame payload 字节。Protected packet helper、endpoint routing、recovery timer 和 mock TLS handoff 已可用于确定性协议测试；完整 TLS-owned UDP packetization 仍待实现。

`Connection` 是当前推荐的公开连接句柄；`QuicConnection` 作为兼容别名保留，便于旧调用方在实验性 API 继续演进期间平滑迁移。

## Examples（示例）

- [Echo server](examples/echo_server.zig)：最小 frame-payload echo server 骨架。
  运行：`zig build run-server`。
- [Echo client](examples/echo_client.zig)：最小 frame-payload echo client 骨架。
  运行：`zig build run-client`。
- [Codec roundtrip](examples/codec_roundtrip.zig)：varint、packet header、Version Negotiation、frame、transport parameter 和 error codec 往返。
  运行：`zig build run-codec`。
- [Transport parameters](examples/transport_parameters.zig)：transport parameter 导出、解析、应用和错误关闭行为。
  运行：`zig build run-transport-parameters`。
- [Flow control](examples/flow_control.zig)：connection、stream、stream-count 和 BLOCKED/MAX frame 行为。
  运行：`zig build run-flow-control`。
- [Unidirectional streams](examples/uni_stream.zig)：本端与对端 unidirectional stream 打开和校验。
  运行：`zig build run-uni-stream`。
- [Stream reset](examples/stream_reset.zig)：RESET_STREAM 发送/接收行为和重传边界。
  运行：`zig build run-stream-reset`。
- [STOP_SENDING](examples/stop_sending.zig)：STOP_SENDING 接收处理和 RESET_STREAM 响应。
  运行：`zig build run-stop-sending`。
- [CRYPTO streams](examples/crypto_stream.zig)：按 packet number space 隔离的 CRYPTO buffering、mock backend handoff 和 protected CRYPTO flow。
  运行：`zig build run-crypto-stream`。
- [Graceful close](examples/graceful_close.zig)：本端/对端关闭、draining 行为和关闭触发校验。
  运行：`zig build run-graceful-close`。
- [Idle timeout](examples/idle_timeout.zig)：建模 idle timeout 导出、刷新和关闭行为。
  运行：`zig build run-idle-timeout`。
- [Packet spaces](examples/packet_spaces.zig)：Initial、Handshake、0-RTT 和 Application packet-number-space 行为。
  运行：`zig build run-packet-spaces`。
- [ECN validation](examples/ecn_validation.zig)：ACK_ECN 校验和 CE 驱动的 congestion response。
  运行：`zig build run-ecn-validation`。
- [Loss recovery](examples/loss_recovery.zig)：ACK 驱动的 loss、RTT sampling、NewReno 和 persistent congestion。
  运行：`zig build run-loss-recovery`。
- [PTO recovery](examples/pto_recovery.zig)：PTO timer、probe selection、backoff 和 anti-amplification gating。
  运行：`zig build run-pto-recovery`。
- [Endpoint recovery timers](examples/endpoint_recovery_timers.zig)：跨 connection handle 的 endpoint-owned recovery timer 调度。
  运行：`zig build run-endpoint-recovery-timers`。
- [Path validation](examples/path_validation.zig)：PATH_CHALLENGE/PATH_RESPONSE 重试和 route update 建模。
  运行：`zig build run-path-validation`。
- [Address validation](examples/address_validation.zig)：HMAC address-validation token、version binding、secret rotation 和 replay snapshot。
  运行：`zig build run-address-validation`。
- [Retry token](examples/retry_token.zig)：Retry datagram 处理、token 复用和 Retry CID 校验。
  运行：`zig build run-retry-token`。
- [Connection IDs](examples/connection_ids.zig)：NEW_CONNECTION_ID、RETIRE_CONNECTION_ID 和 route replacement state。
  运行：`zig build run-connection-ids`。
- [Stateless reset](examples/stateless_reset.zig)：reset token 匹配和 inactive-CID reset 构造。
  运行：`zig build run-stateless-reset`。
- [Initial keys](examples/initial_keys.zig)：QUIC v1/v2 Initial key 派生和配置驱动 v2 Initial packetization。
  运行：`zig build run-initial-keys`。
- [Endpoint routing](examples/endpoint_routing.zig)：内存态 DCID、tuple、Version Negotiation、Retry 和 reset routing。
  运行：`zig build run-endpoint-routing`。
- [UDP endpoint loopback](examples/udp_endpoint_loopback.zig)：socket-backed endpoint routing，覆盖 Version Negotiation、protected follow-up Initial、accepted protected Initial processing、protected server Initial response 和 Initial/short-header classification。
  运行：`zig build run-udp-endpoint-loopback`。
- [UDP zero-CID loopback](examples/udp_zero_cid_loopback.zig)：基于 loopback UDP 的 zero-length CID tuple routing。
  运行：`zig build run-udp-zero-cid-loopback`。
- [UDP preferred address loopback](examples/udp_preferred_address_loopback.zig)：preferred-address route migration 和 active-migration-disabled 处理。
  运行：`zig build run-udp-preferred-address-loopback`。
- [UDP replacement CID loopback](examples/udp_replacement_cid_loopback.zig)：replacement CID 注册、retire_prior_to 处理和 reset-token 保留。
  运行：`zig build run-udp-replacement-cid-loopback`。
- [UDP connection IDs loopback](examples/udp_connection_ids_loopback.zig)：通过 lifecycle route 交换 protected NEW_CONNECTION_ID/RETIRE_CONNECTION_ID。
  运行：`zig build run-udp-connection-ids-loopback`。
- [UDP protected loopback](examples/udp_protected_loopback.zig)：lifecycle-owned accepted protected Initial processing 和 protected server Initial response，以及 caller-keyed 1-RTT loopback UDP routing。
  运行：`zig build run-udp-protected-loopback`。
- [UDP flow control loopback](examples/udp_flow_control_loopback.zig)：protected STREAM/BLOCKED/MAX flow-control loopback UDP 交换。
  运行：`zig build run-udp-flow-control-loopback`。
- [UDP spin bit loopback](examples/udp_spin_bit_loopback.zig)：protected short packet 上的可配置单路径 spin-bit signaling。
  运行：`zig build run-udp-spin-bit-loopback`。
- [UDP ECN validation loopback](examples/udp_ecn_validation_loopback.zig)：loopback UDP 上的建模 ECN state 和 ACK_ECN validation。
  运行：`zig build run-udp-ecn-validation-loopback`。
- [UDP loss recovery loopback](examples/udp_loss_recovery_loopback.zig)：protected ACK 驱动 packet loss 和 timer-driven cleanup。
  运行：`zig build run-udp-loss-recovery-loopback`。
- [UDP congestion recovery loopback](examples/udp_congestion_recovery_loopback.zig)：loopback UDP 上的 NewReno recovery-period 和 persistent-congestion 行为。
  运行：`zig build run-udp-congestion-recovery-loopback`。
- [UDP PTO recovery loopback](examples/udp_pto_recovery_loopback.zig)：endpoint lifecycle PTO probe 和 retransmission choice。
  运行：`zig build run-udp-pto-recovery-loopback`。
- [UDP STREAM retransmission loopback](examples/udp_stream_retransmission_loopback.zig)：通过 lifecycle route 执行 ACK-loss-triggered STREAM retransmission。
  运行：`zig build run-udp-stream-retransmission-loopback`。
- [UDP key update loopback](examples/udp_key_update_loopback.zig)：installed-key key update、key phase advancement 和 ACK gating。
  运行：`zig build run-udp-key-update-loopback`。
- [UDP path validation loopback](examples/udp_path_validation_loopback.zig)：在新 peer port 上执行 PATH_CHALLENGE/PATH_RESPONSE route validation。
  运行：`zig build run-udp-path-validation-loopback`。
- [UDP Retry loopback](examples/udp_retry_loopback.zig)：lifecycle-owned Retry delivery、token validation 和 follow-up Initial routing。
  运行：`zig build run-udp-retry-loopback`。
- [UDP close lifecycle loopback](examples/udp_close_lifecycle_loopback.zig)：protected close delivery、route retirement 和 stateless reset follow-up。
  运行：`zig build run-udp-close-lifecycle-loopback`。
- [UDP stateless reset loopback](examples/udp_stateless_reset_loopback.zig)：socket-backed reset trigger delivery、reset emission 和 client token match。
  运行：`zig build run-udp-stateless-reset-loopback`。

## Advanced Topics（高级主题）

- [Transport task matrix](docs/zh-CN/quic_transport_tasks.md)：当前 RFC 覆盖、剩余工作和验证证据。
- [Design notes](docs/zh-CN/spec.md)：当前架构、协议范围和未支持区域。
- Packet protection：QUIC v1/v2 Initial key、Retry integrity、protected packet helper 和 key-update state。
- Endpoint lifecycle：DCID routing、route retirement、stateless reset lookup/emission 和 endpoint recovery timer。
- Recovery and congestion：简化 RFC 9002 ACK/loss/PTO/NewReno/ECN 模型，并有确定性测试覆盖。
- TLS status：已有 mock `CryptoBackend` handoff；真实 TLS 1.3 transcript 集成仍待实现。

## License

MIT
