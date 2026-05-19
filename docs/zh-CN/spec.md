# quicz 实现范围（Implementation Scope）

`quicz` 的目标是在 Zig 中实现 IETF QUIC 传输协议，标准参考：<https://quicwg.org/>。

初期主要参考文档：

- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control
- RFC 9369: QUIC Version 2

## 第 1 阶段：最小但语义正确的 QUIC v1 子集

- 单路径，IPv4-only
- 固定 QUIC 版本（v1: 0x00000001，内部同时预留 v2 0x6b3343cf）
- 基础包头/包体解析与序列化（Initial / Handshake / 1-RTT）
- 每个 UDP 四元组对应一个连接
- 基础流支持、发送侧 STREAM 分片、入站 RESET_STREAM 与 STOP_SENDING 处理、最小 PATH_CHALLENGE/PATH_RESPONSE 处理、流量控制和 stream-count 限制、严格 stream 方向校验与关闭状态处理
- 针对格式错误的内存态 frame payload 做事务化处理，失败时回滚本次部分 receive、recovery、流控和关闭状态更新
- 简化的丢包检测和拥塞控制，含自动 ACK 生成、ACK range 处理、未发送 packet 的 ACK 拒绝与 sent-packet tracking

## 当前实现状态（Current Implementation Status）

- 已实现：QUIC varint 工具、最小 long/short header codec，以及 STREAM、CRYPTO、PADDING、PING、ACK 多区间、RESET_STREAM、STOP_SENDING、MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS_BIDI/UNI、DATA_BLOCKED、STREAM_DATA_BLOCKED、STREAMS_BLOCKED_BIDI/UNI、NEW_TOKEN、NEW_CONNECTION_ID、RETIRE_CONNECTION_ID、PATH_CHALLENGE/PATH_RESPONSE 与 connection-close 变体的基础 frame codec。
- `QuicConnection` 实现了内存态 stream 发送/接收骨架，包含发送侧 STREAM 分片、连续接收缓存、入站 RESET_STREAM 处理、STOP_SENDING 到 RESET_STREAM 的响应处理、最小 PATH_CHALLENGE 响应排队、基础 connection 和 stream 流量控制、双向与单向 stream-count 限制、CONNECTION_CLOSE/APPLICATION_CLOSE 关闭状态处理、针对 ACK-eliciting payload 的自动 ACK 生成、ACK-only 发送、空间允许时的 ACK 与 STREAM/PATH_RESPONSE/RESET_STREAM 合并、ACK 驱动的 sent-packet tracking，以及简化 recovery / congestion 状态对象。
- 本地发起的 bidirectional stream 必须先通过 `openStream()` 创建，才能调用 `sendOnStream()`；`openStream()` 会遵守对端 bidirectional stream limit，直到收到更大的 MAX_STREAMS_BIDI 帧。
- 本地发起的 unidirectional stream 必须先通过 `openUniStream()` 创建，才能调用 `sendOnStream()`；`openUniStream()` 会遵守对端 unidirectional stream limit，直到收到更大的 MAX_STREAMS_UNI 帧。
- `sendOnStream()` 可用于回复已观察到的对端发起 bidirectional stream，当前内存态 echo 示例依赖这个行为；也可用于已打开的本地 unidirectional stream。它会拒绝未观察到的对端发起 stream、未打开的本地发起 stream、对端发起的 unidirectional stream ID、已经发送 FIN 的 stream，以及被流控阻塞的写入。
- `processDatagram()` 接受已建模的 bidirectional STREAM/RESET_STREAM 接收状态，以及对端发起的 unidirectional STREAM/RESET_STREAM 接收状态。它会拒绝未打开的本地 bidirectional stream ID、入站本地 unidirectional stream ID、超过接收 stream-count limit 的对端发起 stream、乱序新 stream 数据、final size 之后的数据、final size 不一致的 RESET_STREAM、超出大小限制的 frame payload，以及确认从未发送 packet number 的 ACK。
- 入站 `STOP_SENDING` 只接受本端拥有发送侧的 stream。它会关闭该发送侧，使用当前 final size 排队 `RESET_STREAM`，在 reset 发出后丢弃该 stream 未发送的 STREAM 数据，并在 reset 已排队后忽略重复 stop 请求。
- 无效的多帧 payload 会回滚本次 payload 中已经改变的状态，包括接收缓存、RESET_STREAM 状态、已排队 PATH_RESPONSE/RESET_STREAM 值、MAX_DATA/MAX_STREAMS_BIDI/UNI 更新、待发送 ACK 状态、sent-packet recovery 状态与关闭状态。
- 当前 `pollTx` / `processDatagram` 只流转未加密 QUIC frame payload 字节。`pollTx` 可能发送 ACK-only payload、已排队 PATH_RESPONSE 或 RESET_STREAM payload，或把待发送 ACK 与 STREAM/PATH_RESPONSE/RESET_STREAM 数据合并；它还不会生成或消费带 packet protection 的真实 UDP QUIC packet。
- 尚未实现：TLS 1.3 集成、packet protection、独立 packet number spaces、完整 RFC 9002 loss timer 和 packet-threshold loss detection、UDP 四元组连接归属、乱序 stream 重组、QUIC v2 行为、完整路径迁移策略与 stateless reset。

后续阶段会逐步扩展，最终覆盖完整 RFC 范围。
