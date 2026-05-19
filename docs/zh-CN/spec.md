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
- 基础流支持、发送侧 STREAM 分片、流量控制和 stream-count 限制与关闭状态处理
- 简化的丢包检测和拥塞控制，含自动 ACK 生成与 sent-packet tracking

## 当前实现状态（Current Implementation Status）

- 已实现：QUIC varint 工具、最小 long/short header codec、基础 frame codec（STREAM、CRYPTO、PADDING、PING、ACK 多区间、RESET_STREAM、STOP_SENDING、MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS_BIDI/UNI 与 connection-close 变体）、带发送侧 STREAM 分片的内存态 `QuicConnection` stream 发送/接收骨架、基础 connection/stream 流量控制和双向 stream-count 限制、CONNECTION_CLOSE/APPLICATION_CLOSE 关闭状态处理、针对 ACK-eliciting payload 的自动 ACK 生成、ACK 驱动的 sent-packet tracking，以及简化 recovery / congestion 状态对象。
- 当前 `pollTx` / `processDatagram` 只流转未加密 QUIC frame payload 字节。`pollTx` 可能发送 ACK-only payload，或把待发送 ACK 与 STREAM 数据合并；它还不会生成或消费带 packet protection 的真实 UDP QUIC packet。
- 尚未实现：TLS 1.3 集成、packet protection、独立 packet number spaces、完整 RFC 9002 loss timer 和 packet-threshold loss detection、UDP 四元组连接归属、QUIC v2 行为、路径迁移与 stateless reset。

后续阶段会逐步扩展，最终覆盖完整 RFC 范围。
