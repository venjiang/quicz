# quicz

[English](README.md) | 简体中文

`quicz` 是一个使用 [Zig](https://ziglang.org/) 实现的 QUIC 协议栈，目标对齐 IETF QUIC 标准，规范文档见 <https://quicwg.org/>。

> 状态：**实验性 / 开发中（WIP）**  
> 目标：从一个最小但语义正确的子集开始，逐步实现一个完整的 QUIC 传输协议（覆盖 RFC 9000 系列以及 QUIC v2 RFC 9369）。

## 特性与路线图（Features and Roadmap）

### 已实现 / 正在进行

- [x] 项目骨架：Zig 构建集成 + 内存态示例 echo client/server
- [x] `QuicConnection` 的基础 API 设计（初版）
- [x] QUIC 变长整数（varint）编解码工具
- [x] 最小 QUIC 包头（long/short，含 short-header spin-bit 保留）、header-level packet number 截断/重建、RFC 9000 long/short packet envelope 解析/序列化、packet number 编码选择/重建、Retry packet codec 与 RFC 8999 Version Negotiation packet 解析/序列化
- [x] RFC 9000 transport parameter 类型化 codec，含默认值、重复参数拒绝、未知参数忽略、preferred_address 支持，以及 `QuicConnection` 导出/应用 helper
- [x] RFC 9000 transport error code helper，含固定错误码与 CRYPTO_ERROR TLS alert 映射
- [x] RFC 9001 QUIC v1 Initial secret/key/IV/header-protection key 派生、AEAD_AES_128_GCM payload protection helper、protected long-packet seal/open、Retry Integrity Tag 校验与 AES header-protection mask 应用，覆盖 Appendix A 向量
- [x] 基础帧模型（STREAM / CRYPTO / PADDING / PING / ACK/ACK_ECN 多区间 / RESET_STREAM / STOP_SENDING / MAX_* / BLOCKED / NEW_TOKEN / NEW_CONNECTION_ID / RETIRE_CONNECTION_ID / PATH_CHALLENGE / PATH_RESPONSE / HANDSHAKE_DONE / CONNECTION_CLOSE 子集）
- [x] 最小内存态连接与 stream 发送队列 / 接收缓存流转，含发送侧 PING 与 STREAM/按 packet number space 隔离的 CRYPTO 分片、入站 CRYPTO 缓冲、乱序 STREAM 接收重组、本端 RESET_STREAM 与 STOP_SENDING 发出、入站 RESET_STREAM 与 STOP_SENDING 处理、PATH_CHALLENGE 响应排队、outbound PATH_CHALLENGE 跟踪、PTO 驱动重试、失败计数与匹配 PATH_RESPONSE 校验、建模的 server anti-amplification 发送限制、显式 peer-address validation 与 Retry token 消费、对端签发 connection ID 跟踪与 RETIRE_CONNECTION_ID 排队、本端 NEW_CONNECTION_ID 签发与对端 RETIRE 处理、客户端侧 NEW_TOKEN 存储、HANDSHAKE_DONE 接收校验与 handshake confirmation、基础 connection/stream/stream-count 流量控制、outbound BLOCKED 上报、接收侧 MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS_BIDI/UNI credit 刷新、对端 BLOCKED 可观测状态与旧 limit MAX 重发、严格 stream 方向校验、max_idle_timeout 处理与关闭状态处理
- [x] 简化丢包恢复与拥塞控制状态，含自动 ACK 生成、ACK range 处理、未发送 packet 的 ACK 拒绝、ACK 驱动的 sent-packet tracking、ACK delay exponent / handshake confirmed 后 max_ack_delay 截断、packet/time-threshold loss detection、确定性的 loss-timeout hook、NewReno-style recovery period、persistent congestion 响应与 packet-number-space PTO PING hook
- [x] 实验性的 Initial/Handshake/Application packet number space 模型，用于 frame-payload ACK/recovery 隔离、RFC 9000 Initial/Handshake/0-RTT frame-type filtering，并包含建模的 Initial/Handshake discard cleanup
- [x] 针对已建模 ECT(0)/ECT(1) 发送 packet 的 frame-payload ACK_ECN counter 校验
- [x] Stateless reset packet helper，以及针对对端签发 CID 的连接层 reset-token 检测
- [ ] 完整连接状态机与 protected-packet packet number space 路由
- [ ] 完整 RFC 9002 丢包检测与拥塞控制（含 protected-packet loss/PTO timer 调度、PTO recovery 行为与剩余 NewReno 细节）
- [ ] TLS 1.3 集成（RFC 9001）
- [ ] QUIC v2（RFC 9369）版本支持

### 规划的里程碑

1. **最小 QUIC v1 子集**
   - 单路径、仅 IPv4
   - 固定 QUIC v1 版本（0x00000001）
   - 支持 Initial / Handshake / 1-RTT 包
   - 支持基础 STREAM / ACK / PADDING / CONNECTION_CLOSE 帧
2. **TLS 1.3 + 完整握手**
   - 基于 CRYPTO 帧的 TLS 握手集成
   - 密钥派生与包加密保护
3. **丢包检测与拥塞控制**
   - 基于 RFC 9002 的算法（初期会采用类似 NewReno 的实现）
4. **QUIC v2 与高级特性**
   - QUIC v2 版本（0x6b3343cf）支持
   - 路径迁移、更完整的路径验证策略、stateless reset 等

更详细的设计与每个功能的业务逻辑说明，请参考：

- 可验证 transport 实现任务计划：[`docs/zh-CN/quic_transport_tasks.md`](docs/zh-CN/quic_transport_tasks.md)
- 英文文档：[`docs/en/`](docs/en/) 目录
- 中文文档：[`docs/zh-CN/`](docs/zh-CN/) 目录

## 构建（Build）

需要安装 Zig **0.16.0**。当前构建会强制校验这个精确测试版本，避免 Zig
标准库变化静默改变行为。

```bash
zig build
```

上述命令会构建：

- 静态库：`libquicz.a`
- 示例程序：
  - `zig-out/bin/quicz-echo-server`
  - `zig-out/bin/quicz-echo-client`
  - `zig-out/bin/quicz-codec-roundtrip`
  - `zig-out/bin/quicz-flow-control`
  - `zig-out/bin/quicz-uni-stream`
  - `zig-out/bin/quicz-stream-reset`
  - `zig-out/bin/quicz-stop-sending`
  - `zig-out/bin/quicz-crypto-stream`
  - `zig-out/bin/quicz-graceful-close`
  - `zig-out/bin/quicz-idle-timeout`
  - `zig-out/bin/quicz-packet-spaces`
  - `zig-out/bin/quicz-ecn-validation`
  - `zig-out/bin/quicz-loss-recovery`
  - `zig-out/bin/quicz-pto-recovery`
  - `zig-out/bin/quicz-path-validation`
  - `zig-out/bin/quicz-address-validation`
  - `zig-out/bin/quicz-retry-token`
  - `zig-out/bin/quicz-connection-ids`
  - `zig-out/bin/quicz-stateless-reset`
  - `zig-out/bin/quicz-initial-keys`

## 作为库使用（Using quicz as a library）

高层 API（仍可能演进）：

```zig
const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var conn = try quicz.QuicConnection.init(
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

    // 当前骨架行为：
    // - 本地发起的 bidirectional / unidirectional stream 需要先调用
    //   conn.openStream() 或 conn.openUniStream()
    // - sendOnStream(...) 可用于回复已观察到的对端 bidirectional stream，
    //   但会拒绝未观察到的对端 stream、未打开的本地 stream 与
    //   对端发起的 unidirectional stream ID
    // - 调用 conn.pollTx(...) 获取未加密的 frame payload 字节；
    //   它可能发送 ACK-only、PING、CRYPTO、PATH_CHALLENGE、PATH_RESPONSE、
    //   MAX_DATA、MAX_STREAM_DATA、DATA_BLOCKED、STREAM_DATA_BLOCKED、
    //   STREAMS_BLOCKED、RESET_STREAM、STOP_SENDING 或 STREAM payload，
    //   并在空间允许时合并待发送 ACK
    // - 将对端 payload 字节喂给 conn.processDatagram(...)，或用
    //   conn.processDatagramInSpace(...) 显式指定 Initial/Handshake/
    //   Application packet number space 的 ACK/recovery 记账；需要在
    //   Application packet space 内区分 0-RTT/1-RTT frame-type 校验时，
    //   使用 conn.processDatagramForPacketType(...)
    // - 外部 TLS bridge 确认握手后调用 conn.confirmHandshake()；
    //   client 侧收到 HANDSHAKE_DONE 也会标记 handshake confirmed
    // - 通过 conn.sendCryptoInSpace(...)、conn.pollTxInSpace(...) 与
    //   conn.recvCryptoInSpace(...) 驱动建模的 Initial/Handshake CRYPTO
    //   byte stream，为后续 TLS bridge 做准备
    // - 通过 conn.recvCrypto(...) 读取默认 Application-space CRYPTO 字节
    // - 通过 conn.recvOnStream(...) 读取应用层数据；通过
    //   recvStreamFinalSize(...) 和 recvStreamFinished(...) 观察 FIN final size
    //   以及数据被消费后的完成状态；stream 读取也会刷新接收侧
    //   MAX_DATA 与 MAX_STREAM_DATA credit，对端发起 stream 的 FIN 完成还会刷新
    //   MAX_STREAMS_BIDI/UNI credit
    // - 调用 conn.resetStream(...) 可中止已打开的本地发送侧，或已观察到的
    //   对端发起 bidirectional stream 的回复发送侧
    // - 调用 conn.stopSending(...) 可要求对端停止发送到已打开的本地
    //   bidirectional stream 或已观察到的对端发起接收 stream
    // sendCrypto(...) 与 sendOnStream(...) 会按 max_datagram_size 分片较大的写入。
    // processDatagram(...) 会校验入站 bidirectional / unidirectional stream
    // count，接收对端发起的 unidirectional stream，拒绝未打开的本地
    // bidirectional ID 与入站本地 unidirectional ID，缓存乱序 STREAM range
    // 直到数据连续，并在 payload 无效时回滚本次部分状态变更。
    // CRYPTO 帧会进入按 packet number space 隔离的连续内存态握手缓冲。
    // sendPing() 会排队一个
    // ack-eliciting PING 帧。ACK、MAX_DATA、MAX_STREAM_DATA 与
    // MAX_STREAMS_BIDI/UNI 帧会更新内存态 recovery 与流控
    // 状态；packet-number-space helper 会在 frame-payload API 内隔离
    // Initial、Handshake 与 Application 的 ACK/recovery 状态，并拒绝 RFC 9000
    // 不允许出现在 Initial、Handshake 与 0-RTT 中的 frame type；discardPacketNumberSpace()
    // 会在 key discard 后清理建模的 Initial/Handshake sent-packet、CRYPTO、ACK、
    // loss 与 PTO 状态；ACK 可通过
    // packet/time-threshold loss detection 将较旧的未确认 packet 标记为 lost；
    // recovery period 会抑制恢复期内重复降窗，也不会让恢复前发送 packet 的
    // ACK 增长 cwnd；persistent congestion 可把 congestion window 降到 RFC 9002 minimum；
    // checkLossDetectionTimeouts() 会处理已经到期的 time-threshold loss deadline；
    // checkPtoTimeouts() 会在可控时钟下排队 packet-number-space PTO PING probe；
    // ACK_ECN 会用 ACK ranges 更新 recovery，并按 packet number space 把已建模的
    // ECT(0)/ECT(1) 发送 packet 与累计 ECN counter 做校验。RTT 更新会应用
    // 对端 ACK delay exponent，并在 handshake confirmed 后把 ACK delay 截到
    // 对端 max_ack_delay。MAX_STREAM_DATA
    // 会先校验 stream 状态再更新发送 credit；
    // 入站 PATH_CHALLENGE 会排队匹配的 PATH_RESPONSE；sendPathChallenge()
    // 会排队 outbound PATH_CHALLENGE，checkPathValidationTimeouts()
    // 会按小重试预算重发超时 challenge，processDatagram() 只接受匹配的
    // PATH_RESPONSE；NEW_CONNECTION_ID 会跟踪对端签发的 connection ID，
    // retire_prior_to 会排队 RETIRE_CONNECTION_ID；issueConnectionId()
    // 会排队本端 NEW_CONNECTION_ID，收到对端 RETIRE_CONNECTION_ID 时标记
    // 本端 CID 已 retired；detectStatelessReset(...) 会把 datagram 尾部与
    // active peer stateless reset token 匹配，供后续 UDP packet 层使用；
    // NEW_TOKEN 只允许 client
    // 连接接收并保存为后续地址验证 token，HANDSHAKE_DONE 也只允许 client
    // 接收；server 连接默认把 peer address 视为未验证；可用
    // recordPeerAddressBytesReceived(...) 显式记录已接收 datagram 字节，
    // 并在外部握手、token 或 path 检查证明地址归属后调用 validatePeerAddress()。
    // pollTx() 与 pollTxInSpace() 会在验证前执行 RFC 9000 3x
    // anti-amplification 发送预算限制。server 也可用 issueRetryToken(...)
    // 与 validateRetryToken(...) 建模一次性 Retry token；匹配 token 会被消费并验证 peer address；
    // stopSending() 会为可接收 stream 排队 STOP_SENDING；resetStream()
    // 和入站 STOP_SENDING 会关闭对应发送侧并排队 RESET_STREAM；RESET_STREAM
    // 会关闭接收侧，除非该 stream 已经以相同 final size 完成。本地发送因对端 credit 阻塞时会排队 DATA_BLOCKED、
    // STREAM_DATA_BLOCKED 与 STREAMS_BLOCKED_*；recvOnStream() 会在应用读取释放
    // receive credit 后排队 MAX_DATA 与 MAX_STREAM_DATA，并在对端发起 FIN stream
    // 完全消费后排队 MAX_STREAMS_BIDI/UNI；localTransportParameters()
    // 会导出本端配置的接收限制、disable_active_migration 和 server stateless_reset_token，
    // applyPeerTransportParameters() 会把对端握手参数应用到发送侧流控、
    // stream-count、ACK delay、outbound datagram 大小和
    // peerActiveMigrationDisabled() / peerStatelessResetToken() 可观测状态。
    // 入站 BLOCKED 帧会更新已观察
    // 到的对端最高 blocked limit；如果对端报告的是旧 receive limit，也会重新排队
    // 当前 MAX_* 帧。closeConnection() 与 closeApplication()
    // 会排队 CONNECTION_CLOSE 变体；pollTx() 会在 closing 期间发出并重发
    // close frame；max_idle_timeout 会通过 transport parameter 导出/应用，成功
    // 收发会刷新 idleTimeoutDeadlineMillis()，checkIdleTimeouts() 会在建模的
    // idle deadline 到期时关闭 active 连接。connectionState() 会暴露 active/closing/draining/closed
    // 生命周期状态。DCID routing 仍不在这个骨架内。
    // 连接层现在可通过 processInitialProtectedDatagram() 接收单个 protected
    // Initial long packet；protected transmit、coalescing、完整 UDP
    // packetization、TLS 和后续 encryption level 仍未实现。
}
```

更多示例用法，请参考：

- [`examples/echo_server.zig`](examples/echo_server.zig)
- [`examples/echo_client.zig`](examples/echo_client.zig)
- [`examples/codec_roundtrip.zig`](examples/codec_roundtrip.zig)
- [`examples/flow_control.zig`](examples/flow_control.zig)
- [`examples/uni_stream.zig`](examples/uni_stream.zig)
- [`examples/stream_reset.zig`](examples/stream_reset.zig)
- [`examples/stop_sending.zig`](examples/stop_sending.zig)
- [`examples/graceful_close.zig`](examples/graceful_close.zig)
- [`examples/idle_timeout.zig`](examples/idle_timeout.zig)
- [`examples/packet_spaces.zig`](examples/packet_spaces.zig)
- [`examples/ecn_validation.zig`](examples/ecn_validation.zig)
- [`examples/loss_recovery.zig`](examples/loss_recovery.zig)
- [`examples/pto_recovery.zig`](examples/pto_recovery.zig)
- [`examples/path_validation.zig`](examples/path_validation.zig)
- [`examples/address_validation.zig`](examples/address_validation.zig)
- [`examples/retry_token.zig`](examples/retry_token.zig)
- [`examples/connection_ids.zig`](examples/connection_ids.zig)
- [`examples/stateless_reset.zig`](examples/stateless_reset.zig)
- [`examples/initial_keys.zig`](examples/initial_keys.zig)

这些示例当前用于演示内存态 frame-payload API、codec API、transport-parameter
API、flow-control API、unidirectional stream API、stream-reset API、STOP_SENDING API、
close-state API、idle-timeout API、packet-number-space discard 与 0-RTT frame filtering API、
ECN-validation API、包含 ACK-delay、recovery-period 与 persistent congestion 处理的
loss-recovery API、PTO-recovery API、
path-validation API、address-validation API、Retry-token 与 integrity-tag API、connection-ID API、stateless-reset API 与 Initial key/protected-packet/header-protection API，并不是
可互通的 QUIC-over-UDP 程序。

## 文档结构（Documentation Layout）

项目文档使用中英文目录区分存放：

- 英文文档：`docs/en/`
  - 作为权威、完整的设计与业务逻辑说明
  - 当前已有：`docs/en/spec.md`
  - 可验证任务计划：`docs/en/quic_transport_tasks.md`
- 中文文档：`docs/zh-CN/`
  - 对应英文文档的等价翻译与本地化说明
  - 当前已有：`docs/zh-CN/spec.md`
  - 可验证任务计划：`docs/zh-CN/quic_transport_tasks.md`

代码中的标识符与注释统一使用英文；中文文档主要用于帮助理解与说明，不会影响 API 设计。

## License

MIT
