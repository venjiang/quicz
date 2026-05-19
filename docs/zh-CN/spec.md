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
- 基础流支持，流量控制在后续阶段实现
- 简化的丢包检测和拥塞控制（遵循 RFC 9002 框架，但先实现最小可用版本）

## 当前实现状态（Current Implementation Status）

- 已实现：QUIC varint 工具、最小 long/short header codec、基础 frame codec、内存态 `QuicConnection` stream 发送/接收骨架，以及简化 recovery / congestion 状态对象。
- 当前 `pollTx` / `processDatagram` 只流转未加密 QUIC frame payload 字节，还不会生成或消费带 packet protection 的真实 UDP QUIC packet。
- 尚未实现：TLS 1.3 集成、packet protection、packet number space tracking、基于真实 ACK 的 recovery、stream 流量控制、UDP 四元组连接归属、QUIC v2 行为、路径迁移与 stateless reset。

后续阶段会逐步扩展，最终覆盖完整 RFC 范围。
