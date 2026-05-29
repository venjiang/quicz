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
- [x] 最小 QUIC 包头（long/short，含 RFC 9369 QUIC v2 long-header packet type bits、short-header spin-bit 保留、protected short-packet spin-bit peeking 与 socket-backed UDP spin-bit loopback）、header-level packet number 截断/重建、RFC 9000 long/short packet envelope 解析/序列化、packet number 编码选择/重建、Retry packet codec、RFC 8999 Version Negotiation packet 解析/序列化，以及带 RFC 9368 downgrade-check handoff 的 client-side Version Negotiation validation/selection state
- [x] RFC 9000 transport parameter 类型化 codec，含默认值、重复参数拒绝、未知参数忽略、preferred_address 支持、RFC 9368 `version_information`、包含 VN 后 server Version Information downgrade validation 的 `QuicConnection` 导出/应用 helper，以及 TLS extension byte 编码/应用 helper
- [x] RFC 9000/RFC 9368 transport error code helper，含固定错误码、VERSION_NEGOTIATION_ERROR 与 CRYPTO_ERROR TLS alert 映射
- [x] RFC 9001 QUIC v1 和 RFC 9369 QUIC v2 Initial secret/key/IV/header-protection key 派生、RFC 9001 `quic ku` key-update 派生、调用方持有和连接已安装的 short-packet key-phase 状态与 selection，并带 ACK-gated installed-key update initiation 和 socket-backed UDP installed-key key-update loopback、mock backend Handshake/0-RTT/1-RTT traffic-secret handoff、显式 installed-key 0-RTT accept/reject 与 discard cleanup、建模 1-RTT 边界的 0-RTT key discard、AEAD_AES_128_GCM payload protection helper、protected long/short-packet seal/open、v1/v2 Retry Integrity Tag 校验与 AES header-protection mask 应用，覆盖 Appendix A 向量
- [x] 基础帧模型（STREAM / CRYPTO / PADDING / PING / ACK/ACK_ECN 多区间与 ACK range 校验 / RESET_STREAM / STOP_SENDING / MAX_* / BLOCKED / NEW_TOKEN / NEW_CONNECTION_ID / RETIRE_CONNECTION_ID / PATH_CHALLENGE / PATH_RESPONSE / HANDSHAKE_DONE / CONNECTION_CLOSE 子集），包含 frame type 最短 varint 编码校验与未知 frame type 拒绝
- [x] 最小内存态连接与 stream 发送队列 / 接收缓存流转，含发送侧 PING 与 STREAM/按 packet number space 隔离的 CRYPTO 分片、protected Initial/Handshake CRYPTO/ACK/PING（含首个 client Initial DCID 长度、server Initial token 校验与 RFC 9000 Initial UDP datagram 1200 字节扩展/丢弃检查）、使用调用方 key 或连接已安装 key 的 0-RTT STREAM/RESET_STREAM/STOP_SENDING long-packet bridge、使用连接已安装 key 的 protected Handshake long-packet CRYPTO/ACK/PING bridge、使用调用方 key 和连接已安装 key 的 protected 1-RTT short-packet PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit 和 receive bridge，并带 key-phase 状态 helper 与可配置的单路径 spin-bit signaling、入站乱序 CRYPTO 缓冲与相同重复重传丢弃、可插拔 `CryptoBackend` 驱动的按 space CRYPTO 投递/输出排队、transport-parameter byte handoff、mock Handshake/0-RTT/1-RTT traffic-secret handoff 和建模 handshake confirmation、乱序 STREAM 接收重组与相同重复重传丢弃、本端 RESET_STREAM 与 STOP_SENDING 发出、入站 RESET_STREAM 与 STOP_SENDING 处理、PATH_CHALLENGE 响应排队、outbound PATH_CHALLENGE 跟踪、PTO 驱动重试、失败计数、匹配 PATH_RESPONSE 校验，以及 protected PATH_RESPONSE 验证后的 endpoint route update、建模的 server anti-amplification 发送限制、显式 peer-address validation、HMAC-SHA256 地址绑定、带过期时间并绑定 originating version 的 address-validation token、endpoint peer-address binding 和内存态 `AddressValidationPolicy` secret/replay snapshot 导出恢复与 replay 拒绝、Retry token 消费、server 侧 Retry datagram 签发、客户端侧 Retry datagram 处理与 handshake CID transport-parameter 校验/导出、带 stateless-reset-token uniqueness checks 的对端签发 connection ID 跟踪与 RETIRE_CONNECTION_ID 排队、带 stateless-reset-token uniqueness checks 的本端 NEW_CONNECTION_ID 签发与对端 RETIRE 处理、server 侧 HANDSHAKE_DONE 和 NEW_TOKEN 签发、客户端侧 NEW_TOKEN 存储、HANDSHAKE_DONE 接收校验、显式 handshake progress 可观测状态、handshake confirmation、RFC 9001 client 发送 Handshake / server 接收 Handshake 后的 Initial discard，以及有效客户端侧 HANDSHAKE_DONE、server 侧 sendHandshakeDone 或 backend-confirmed no-output Handshake drive 后的 Handshake-space discard、基础 connection/stream/stream-count 流量控制、outbound BLOCKED 上报、接收侧 MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS_BIDI/UNI credit 刷新与可选目标 receive data 和 stream-count window、对端 BLOCKED 可观测状态、STREAM_DATA_BLOCKED 接收侧状态创建/校验、旧 limit MAX 重发、基于已配置 receive window 的增长和 stream-count-window 增长、严格 stream 方向校验、max_idle_timeout 处理与关闭状态处理
- [x] 简化丢包恢复与拥塞控制状态，含自动 ACK 生成、ACK range 校验/处理、未发送 packet 的 ACK 拒绝、ACK 驱动的 sent-packet tracking、largest-acknowledged RTT sampling、跨 packet number space 的 connection-level RTT 估计共享、Initial/Handshake RTT ACK-delay suppression、Application ACK delay exponent / handshake confirmed 后 max_ack_delay 截断、packet/time-threshold loss detection、确定性的 loss-timeout hook、带 closing/draining disarm 的 aggregate loss-time-before-PTO timer deadline selection 和 service helper、endpoint-owned 多连接 recovery timer scheduling、跨 packet number space bytes-in-flight 拥塞发送准入、带 underutilized-cwnd suppression 的 NewReno slow-start/congestion-avoidance 字节计数与 batched-ACK 增长、recovery period、新拥塞事件后一次性 recovery probe、minimum-window clamp 但不抬高 ssthresh 的边界、不受 PTO backoff 放大的 persistent congestion duration/response、ACK_ECN CE 拥塞响应、使用 connection-level PTO backoff 的 packet-number-space PTO hook、Initial/Handshake space 不计 max_ack_delay，Application PTO 在 handshake confirmation 前 gated，且优先使用已排队 ack-eliciting 数据、in-flight CRYPTO、protected 0-RTT STREAM/control frames 或 in-flight STREAM，最后才 fallback 到 PING，并为其他仍有 in-flight packet 的 packet number space 排 cross-space peer probe，以及 socket-backed UDP endpoint-timer 驱动的 loss/PTO recovery 与 congestion/STREAM-retransmission recovery loopback
- [x] 实验性的 Initial/Handshake/Application packet number space 模型，用于 frame-payload ACK/recovery 隔离、RFC 9000 Initial/Handshake/0-RTT frame-type filtering，并包含建模的 RFC 9001 Initial discard 与会清理 ECN 状态的 Initial/Handshake discard cleanup
- [x] 针对已建模 ECT(0)/ECT(1) 发送 packet 的 frame-payload ACK_ECN counter 校验、ACK_ECN CE 驱动的 NewReno recovery 响应，以及按 UDP path identity 隔离的内存态 endpoint ECN 状态和 socket-backed UDP ECN validation loopback
- [x] 带 constant-time token matching 的 stateless reset packet helper，以及针对对端签发 CID 的连接层 reset-token 检测和唯一性校验
- [x] 内存态 endpoint DCID/IPv4 UDP 四元组 router，覆盖 long-header DCID peeking、unsupported-version RFC 8999 Version Negotiation response generation、client Initial Source CID route registration、supported-version unknown-DCID Initial accept classification、accepted Initial Original DCID/server Initial SCID route registration、short-header registered-CID matching、zero-length CID tuple routing、Retry Source CID route switching、调用方验证后的 preferred-address migration commit、sequence/retire-prior-to 和 connection-handle route retirement、endpoint replacement-CID registration、stateless-reset-token 唯一性校验、调用方验证后的 path update、active-migration-disabled rejection、inactive-CID stateless reset token lookup、reset datagram construction、socket-backed UDP endpoint/zero-CID/preferred-address/replacement-CID/connection-ID/protected packet/flow-control/spin-bit/ECN-validation/loss-recovery/congestion-recovery/PTO-recovery/key-update/path-validation/Retry/close/stateless reset loopback 示例，以及 route/version-negotiation/reset/drop/accept receive classification
- [ ] 完整连接状态机与 protected-packet packet number space 路由
- [ ] 完整 RFC 9002 丢包检测与拥塞控制（含 socket-owned protected-packet loss/PTO timer lifecycle 集成与剩余 NewReno 边界）
- [ ] TLS 1.3 集成（RFC 9001）
- [ ] QUIC v2（RFC 9369）版本支持

### 规划的里程碑

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
   - QUIC v2 版本（0x6b3343cf），已支持 Initial key 派生、long-header type bits、Retry integrity、token version 隔离和 RFC 9368 version information，剩余 v2 行为仍待实现
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
  - `zig-out/bin/quicz-transport-parameters`
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
  - `zig-out/bin/quicz-endpoint-routing`
  - `zig-out/bin/quicz-udp-endpoint-loopback`
  - `zig-out/bin/quicz-udp-zero-cid-loopback`
  - `zig-out/bin/quicz-udp-preferred-address-loopback`
  - `zig-out/bin/quicz-udp-replacement-cid-loopback`
  - `zig-out/bin/quicz-udp-connection-ids-loopback`
  - `zig-out/bin/quicz-udp-protected-loopback`
  - `zig-out/bin/quicz-udp-flow-control-loopback`
  - `zig-out/bin/quicz-udp-spin-bit-loopback`
  - `zig-out/bin/quicz-udp-ecn-validation-loopback`
  - `zig-out/bin/quicz-udp-loss-recovery-loopback`
  - `zig-out/bin/quicz-udp-congestion-recovery-loopback`
  - `zig-out/bin/quicz-udp-pto-recovery-loopback`
  - `zig-out/bin/quicz-udp-key-update-loopback`
  - `zig-out/bin/quicz-udp-path-validation-loopback`
  - `zig-out/bin/quicz-udp-retry-loopback`
  - `zig-out/bin/quicz-udp-close-lifecycle-loopback`
  - `zig-out/bin/quicz-udp-stateless-reset-loopback`

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
    //   STREAMS_BLOCKED、HANDSHAKE_DONE、NEW_TOKEN、RESET_STREAM、
    //   STOP_SENDING 或 STREAM payload，并在空间允许时合并待发送 ACK
    // - 将对端 payload 字节喂给 conn.processDatagram(...)，或用
    //   conn.processDatagramInSpace(...) 显式指定 Initial/Handshake/
    //   Application packet number space 的 ACK/recovery 记账；需要在
    //   Application packet space 内区分 0-RTT/1-RTT frame-type 校验时，
    //   使用 conn.processDatagramForPacketType(...)
    // - 通过 conn.driveCryptoBackendInSpace(...) 驱动可插拔 TLS/crypto
    //   backend；backend 可接收本端 transport-parameter extension bytes，
    //   返回对端 transport-parameter bytes 供校验/应用，收到连续的
    //   per-space CRYPTO 字节，返回 Handshake/0-RTT/1-RTT traffic secrets
    //   供 installed-key packet helper 使用，把产出的 CRYPTO 通过 connection 排队，并可
    //   报告 handshake completion。如果 Handshake-space backend drive 确认
    //   handshake 且没有排队 outbound CRYPTO，会丢弃 Handshake packet-number-space
    //   状态和已安装 Handshake key。显式测试仍可直接调用
    //   conn.confirmHandshake()；server 的 sendHandshakeDone() 会标记
    //   handshake confirmed、丢弃同一 Handshake 状态，并排队 HANDSHAKE_DONE；
    //   client 侧在有效 payload 收到 HANDSHAKE_DONE 后也会标记 confirmed 并丢弃同一 Handshake 状态；
    //   conn.handshakeState() 会暴露 Initial/Handshake/Confirmed 进度
    // - 测试需要更底层 Initial/Handshake CRYPTO byte-stream 控制时，可直接用
    //   conn.sendCryptoInSpace(...)、conn.pollTxInSpace(...) 与
    //   conn.recvCryptoInSpace(...)
    // - 通过 conn.recvCrypto(...) 读取默认 Application-space CRYPTO 字节；
    //   入站 CRYPTO 可以乱序到达，相同重传在字节已缓存后会被忽略
    // - 通过 conn.recvOnStream(...) 读取应用层数据；通过
    //   recvStreamFinalSize(...) 和 recvStreamFinished(...) 观察 FIN final size
    //   以及数据被消费后的完成状态；打开更高编号接收 stream 的入站 frame
    //   也会创建同类型低编号 stream；stream 读取也会刷新接收侧
    //   MAX_DATA 与 MAX_STREAM_DATA credit，对端发起 stream 的 FIN 完成还会刷新
    //   MAX_STREAMS_BIDI/UNI credit；final size 已知后，STREAM_DATA_BLOCKED
    //   不再为该 stream 刷新 MAX_STREAM_DATA
    // - 调用 conn.resetStream(...) 可中止已打开的本地发送侧，或已观察到的
    //   对端发起 bidirectional stream 的回复发送侧；入站 RESET_STREAM 之后，
    //   已知 final size 范围内的后续 STREAM 数据会被忽略
    // - 调用 conn.stopSending(...) 可要求对端停止发送到已打开的本地
    //   bidirectional stream 或已观察到的对端发起接收 stream；final data
    //   已到达后，stopSending(...) 会报告 StreamClosed
    // sendCrypto(...) 与 sendOnStream(...) 会按 max_datagram_size 分片较大的写入。
    // processDatagram(...) 会校验入站 bidirectional / unidirectional stream
    // count，接收对端发起的 unidirectional stream，拒绝未打开的本地
    // bidirectional ID 与入站本地 unidirectional ID，缓存乱序 STREAM range
    // 直到数据连续，相同重复 STREAM 重传不会重复增长流控，并在 payload
    // 无效时回滚本次部分状态变更。
    // CRYPTO 帧会进入按 packet number space 隔离的连续内存态握手缓冲。
    // sendPing() 会排队一个
    // ack-eliciting PING 帧。ACK、MAX_DATA、MAX_STREAM_DATA 与
    // MAX_STREAMS_BIDI/UNI 帧会更新内存态 recovery 与流控
    // 状态；packet-number-space helper 会在 frame-payload API 内隔离
    // Initial、Handshake 与 Application 的 ACK/recovery 状态，并拒绝 RFC 9000
    // 不允许出现在 Initial、Handshake 与 0-RTT 中的 frame type；client 成功发送
    // Handshake packet 和 server 成功接收 Handshake packet 后会丢弃 Initial 状态；
    // discardPacketNumberSpace() 会在 key discard 后清理建模的 Initial/Handshake
    // sent-packet、CRYPTO、ACK、loss、PTO、ECN 状态和已安装 Handshake key；discardZeroRttProtectionKeys()
    // 会清理已安装 early-data key，建模的 1-RTT 边界会在 client 安装 1-RTT key
    // 时清理 client 0-RTT key，并在 server 接受 1-RTT short packet 后清理 server 0-RTT key；ACK 可通过
    // packet/time-threshold loss detection 将较旧的未确认 packet 标记为 lost；
    // recovery period 会抑制恢复期内重复降窗，也不会让恢复前发送 packet 的
    // ACK 增长 cwnd；persistent congestion 会使用不受 PTO backoff 放大的 duration，
    // 并可把 congestion window 降到 RFC 9002 minimum；
    // lossDetectionTimerDeadlineMillis() 会暴露 aggregate loss-time-before-PTO
    // recovery timer；serviceLossDetectionTimer() 会处理一个已到期 aggregate
    // timer，执行到期 loss-time deadline 或 PTO probe；EndpointLossDetectionTimers
    // 会跨 caller-owned connection handle 调度这些 aggregate timer。需要分别测试这两条路径时，
    // 仍可直接使用 checkLossDetectionTimeouts() 和 checkPtoTimeouts()；
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
    // issueNewToken() 会排队 server 签发的 NEW_TOKEN；client
    // 连接接收后会保存为后续地址验证 token；issueAddressValidationToken()
    // 可创建 HMAC-SHA256 地址绑定、originating-version-bound 且带过期时间的
    // Retry 或 NEW_TOKEN 值；
    // endpoint.Udp4Tuple.peerAddressValidationBinding() 可提供稳定的远端
    // IPv4/UDP token peer-address binding；
    // endpoint.AddressValidationPolicy 持有内存态 active/previous token
    // secrets 和 replay filter，用于带版本的签发、校验与 replay 拒绝，并可导出/恢复
    // secret set 与 replay-filter snapshot，供外部持久化或 worker 分发；
    // HANDSHAKE_DONE 也只允许 client
    // 接收；server 连接默认把 peer address 视为未验证；可用
    // recordPeerAddressBytesReceived(...) 显式记录已接收 datagram 字节，
    // 并在外部握手、token 或 path 检查证明地址归属后调用 validatePeerAddress()。
    // pollTx() 与 pollTxInSpace() 会在验证前执行 RFC 9000 3x
    // anti-amplification 发送预算限制。server 也可用 issueRetryDatagram(...)
    // 建模 Retry datagram，用 issueRetryToken(...) 与 validateRetryToken(...)
    // 建模一次性 Retry token，或用 validateAddressValidationToken(...)
    // / validateAddressValidationTokenWithSecrets(...)
    // 校验认证过的地址 token；匹配 Retry token 会被消费一次，并验证 originating
    // version 与 peer address；
    // client 可通过 processRetryDatagram(...) 处理 Retry datagram；accepted
    // latestRetryToken() 会在 protected Initial packetization 没有显式传入
    // Initial token 时自动复用。applyPeerTransportParameters(...) 会用
    // originalDestinationConnectionId() 和 retrySourceConnectionId() 校验 server 的
    // original_destination_connection_id 与 retry_source_connection_id，并用
    // peerInitialSourceConnectionId() 校验 initial_source_connection_id。
    // localTransportParameters() 会在本端发出首个 protected Initial 后导出
    // initial_source_connection_id；server 连接成功打开首个 client Initial 后会导出
    // original_destination_connection_id。
    // stopSending() 会为可接收 stream 排队 STOP_SENDING；resetStream()
    // 和入站 STOP_SENDING 会关闭对应发送侧并排队 RESET_STREAM；对于对端发起的
    // bidirectional stream，入站 STOP_SENDING 可以在任何 STREAM 数据前打开接收状态，
    // 且仅关闭本端发送侧。RESET_STREAM 会关闭接收侧，除非该 stream 已经以相同 final size 完成。本地发送因对端 credit 阻塞时会排队 DATA_BLOCKED、
    // STREAM_DATA_BLOCKED 与 STREAMS_BLOCKED_*；recvOnStream() 会在应用读取释放
    // receive credit 后排队 MAX_DATA 与 MAX_STREAM_DATA，并在对端发起 FIN stream
    // 完全消费后排队 MAX_STREAMS_BIDI/UNI；入站 BLOCKED 会记录对端最高 blocked
    // limit，校验 STREAM_DATA_BLOCKED 的接收侧 stream ID，合法时可在 STREAM
    // 数据前创建接收状态，并按需重发或增长 MAX_*；MAX_STREAM_DATA 也可在任何
    // STREAM 数据前打开对端发起 bidirectional stream 的接收/发送状态，让回复使用
    // 对端通告的 credit；匹配发送侧已经发送 FIN 后会忽略后续 MAX_STREAM_DATA。
    // MAX_DATA/MAX_STREAM_DATA 刷新可使用配置的目标 receive window。localTransportParameters()
    // 会导出本端配置的接收限制、ACK delay exponent/max_ack_delay、
    // disable_active_migration、server stateless_reset_token 和配置的 server preferred_address，
    // applyPeerTransportParameters() 会把对端握手参数应用到发送侧流控、
    // stream-count、ACK delay、outbound datagram 大小和
    // peerActiveMigrationDisabled() / peerStatelessResetToken() /
    // peerPreferredAddress() 可观测状态。encodeLocalTransportParameters()
    // 与 applyPeerTransportParameterBytes() 会把同一组数据暴露为 TLS QUIC
    // extension bytes，供后续 TLS backend 集成。
    // 入站 BLOCKED 帧会更新已观察
    // 到的对端最高 blocked limit；如果对端报告的是旧 receive limit，也会重新排队
    // 当前 MAX_* 帧；如果对端报告当前 receive limit，则可按已配置 receive window
    // 增长 MAX_DATA/MAX_STREAM_DATA，也可通过 receive_stream_count_window 增长
    // MAX_STREAMS_BIDI/UNI。closeConnection() 与 closeApplication()
    // 会排队 CONNECTION_CLOSE 变体；pollTx() 会在 closing 期间发出并重发
    // close frame；peerClose() 会在 draining 期间暴露已接受的对端 close 诊断；
    // closing 或 draining 期间的入站 datagram 会直接丢弃，不再解析；
    // max_idle_timeout 会通过 transport parameter 导出/应用，成功
    // 收发会刷新 idleTimeoutDeadlineMillis()，checkIdleTimeouts() 会在建模的
    // idle deadline 到期时关闭 active 连接。connectionState() 会暴露 active/closing/draining/closed
    // 生命周期状态。DCID routing 仍不在这个骨架内。
    // 连接层现在可通过 pollProtectedLongCryptoDatagramInSpace() 与
    // processProtectedLongDatagramInSpace() 收发 Initial/Handshake CRYPTO 的
    // protected long packet；pollProtectedLongDatagram() 与
    // processProtectedLongDatagram() 可 coalesce 并路由 protected
    // Initial/Handshake CRYPTO、ACK-only、PING packet，以及使用调用方 key 或连接已安装 key 的
    // 0-RTT STREAM/RESET_STREAM/STOP_SENDING packet；独立 0-RTT helper 也有
    // installed-key 变体，pollProtectedHandshakeDatagramWithInstalledKeys()
    // / processProtectedHandshakeDatagramWithInstalledKeys() 可使用 CryptoBackend
    // 安装的 Handshake key 收发 Handshake CRYPTO/ACK/PING；pollProtectedShortDatagram()
    // / processProtectedShortDatagram() 和 pollProtectedShortDatagramWithInstalledKeys()
    // / processProtectedShortDatagramWithInstalledKeys() 可收发调用方提供 key 或连接已安装 key 的
    // protected 1-RTT short PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/
    // RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/
    // CONNECTION_CLOSE packet。Config.enable_spin_bit 可启用当前单路径
    // spin-bit 模型；nextOutgoingSpinBit() 暴露下一次 short-header 值，
    // resetSpinBitForPath() 可在 path 或 CID 切换后重置。完整 UDP packetization、socket-owned endpoint routing、
    // 真实 TLS backend secret production、真实 TLS-backed early-data secret ownership，
    // 以及 TLS 0-RTT acceptance/replay policy 仍未实现。
}
```

更多示例用法，请参考：

- [`examples/echo_server.zig`](examples/echo_server.zig)
- [`examples/echo_client.zig`](examples/echo_client.zig)
- [`examples/codec_roundtrip.zig`](examples/codec_roundtrip.zig)
- [`examples/transport_parameters.zig`](examples/transport_parameters.zig)
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
- [`examples/endpoint_routing.zig`](examples/endpoint_routing.zig)
- [`examples/endpoint_recovery_timers.zig`](examples/endpoint_recovery_timers.zig)
- [`examples/udp_endpoint_loopback.zig`](examples/udp_endpoint_loopback.zig)
- [`examples/udp_zero_cid_loopback.zig`](examples/udp_zero_cid_loopback.zig)
- [`examples/udp_preferred_address_loopback.zig`](examples/udp_preferred_address_loopback.zig)
- [`examples/udp_replacement_cid_loopback.zig`](examples/udp_replacement_cid_loopback.zig)
- [`examples/udp_connection_ids_loopback.zig`](examples/udp_connection_ids_loopback.zig)
- [`examples/udp_protected_loopback.zig`](examples/udp_protected_loopback.zig)
- [`examples/udp_flow_control_loopback.zig`](examples/udp_flow_control_loopback.zig)
- [`examples/udp_spin_bit_loopback.zig`](examples/udp_spin_bit_loopback.zig)
- [`examples/udp_ecn_validation_loopback.zig`](examples/udp_ecn_validation_loopback.zig)
- [`examples/udp_loss_recovery_loopback.zig`](examples/udp_loss_recovery_loopback.zig)
- [`examples/udp_congestion_recovery_loopback.zig`](examples/udp_congestion_recovery_loopback.zig)
- [`examples/udp_pto_recovery_loopback.zig`](examples/udp_pto_recovery_loopback.zig)
- [`examples/udp_key_update_loopback.zig`](examples/udp_key_update_loopback.zig)
- [`examples/udp_path_validation_loopback.zig`](examples/udp_path_validation_loopback.zig)
- [`examples/udp_retry_loopback.zig`](examples/udp_retry_loopback.zig)
- [`examples/udp_close_lifecycle_loopback.zig`](examples/udp_close_lifecycle_loopback.zig)
- [`examples/udp_stateless_reset_loopback.zig`](examples/udp_stateless_reset_loopback.zig)

这些示例当前用于演示内存态 frame-payload API、包含 QUIC v2 long-header
type-bit 映射的 codec API、包含 RFC 9368 version information 的 transport-parameter
API、flow-control API、unidirectional stream API、stream-reset API、STOP_SENDING API、
close-state API、idle-timeout API、handshake-state API、packet-number-space discard 与 0-RTT frame filtering API、
ECN-validation API、包含 invalid ACK range rejection、largest-acknowledged RTT sampling、跨 packet number space 共享 RTT 估计、ACK-delay、跨 packet number space bytes-in-flight 拥塞发送准入、NewReno underutilized-cwnd suppression、slow-start/congestion-avoidance 字节计数与 batched-ACK 增长、带 closing/draining disarm 的 endpoint-timer 驱动 loss/PTO service、recovery-period、minimum-window ssthresh clamp、ACK_ECN CE response 与 persistent congestion 处理的
loss-recovery API、含 handshake-confirmation Application PTO gating、connection-level PTO backoff 与 cross-space peer probe 的 PTO-recovery API、
path-validation API、包含 token version binding 的 address-validation API、Retry-token 处理与 v1/v2 integrity-tag API、connection-ID API、stateless-reset API、v1/v2 Initial key、key-update/protected-packet/header-protection API、endpoint-routing/Retry-DCID/preferred-address/stateless-reset-token lookup API、带 client-side Version Negotiation selection 的真实 loopback UDP endpoint routing、socket-backed UDP zero-length CID tuple routing、socket-backed UDP preferred-address route migration、socket-backed UDP replacement-CID route retirement、socket-backed UDP connection-ID NEW/RETIRE exchange、调用方 key protected UDP packet、socket-backed UDP flow-control credit refresh、socket-backed UDP spin-bit signaling、socket-backed UDP ECN validation、socket-backed UDP loss recovery、socket-backed UDP congestion recovery、socket-backed UDP PTO recovery、socket-backed UDP installed-key key update、socket-backed UDP path-validation route update、socket-backed UDP Retry/address-validation routing、socket-backed close-triggered route retirement 和 socket-backed UDP stateless-reset emission 示例，并不是
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
