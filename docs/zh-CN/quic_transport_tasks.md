# QUIC 传输协议实现任务

`quicz` 的目标是在 Zig 中实现 IETF QUIC 传输协议。本文把该目标拆成
可逐步实现、可验证、可回滚的任务。

## 范围

第一轮实现范围限定为 QUIC 传输核心：

- RFC 8999：QUIC 版本无关属性
- RFC 9000：QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001：Using TLS to Secure QUIC
- RFC 9002：QUIC Loss Detection and Congestion Control

暂缓的标准和扩展（不含已实现的 QUIC v2 packet/key/token 与 RFC 9368
version-information 原语）：

- 完整 QUIC v2 行为，RFC 9369
- 完整 Compatible Version Negotiation，RFC 9368
- QUIC DATAGRAM，RFC 9221
- HTTP/3 和 QPACK
- Multipath 以及其他 QUIC WG 进行中的草案

## RFC 覆盖状态

状态值使用 `Done`、`Partial`、`Missing` 和 `Deferred`。`Partial` 表示仓库
已经有该领域的部分代码和测试，但剩余行为仍保留在下面的任务矩阵中。

| 标准领域 | 状态 | 当前证据 | 剩余证明 |
| --- | --- | --- | --- |
| RFC 8999 版本无关属性 | Partial | Version Negotiation packet codec、endpoint unsupported-version Version Negotiation response helper、client-side Version Negotiation packet validation/selection state、long/short packet envelope、包含首个 client Initial DCID 长度约束的 connection ID 校验、stateless reset helper、packet codec/example 测试，以及带 client-side Version Negotiation selection 的 socket-backed UDP endpoint routing loopback。 | 仍需完整 TLS-owned socket-backed packet routing 和互通验证证明完整版本无关行为。 |
| RFC 9000 传输协议 | Partial | Frame codec、transport parameter、连接状态、stream、flow control、connection ID、Retry/token、path validation、close/reset 行为、endpoint routing helper、lifecycle-owned caller-keyed protected UDP packet loopback、socket-backed UDP path-validation route-update loopback、socket-backed UDP lifecycle Retry/address-validation loopback 和示例。 | 仍需完整 protected/TLS socket-backed client/server loopback、完整 endpoint 生命周期和外部互通。 |
| RFC 9001 TLS 与 packet protection | Partial | QUIC v1 Initial secret 派生、AEAD/header-protection helper、Retry Integrity Tag、protected packet helper、mock CRYPTO backend handoff、installed-key 测试和 ACK-gated installed-key key-update 发起。 | 仍需真实 TLS backend transcript 集成、TLS 持有的 traffic-secret production、剩余自动 key discard 和完整 TLS-owned live key-update 调度/old-key discard。 |
| RFC 9002 loss detection 与 congestion control | Partial | Initial/Handshake RTT ACK-delay suppression 与 Application ACK delay scaling/capping、packet/time-threshold loss、带 closing/draining disarm 的 aggregate loss-time-before-PTO timer deadline selection/service、endpoint-owned 多连接 recovery timer scheduling、把 route retirement 与 timer disarm 绑定到同一 endpoint state owner 的 connection lifecycle helper、caller-keyed protected long/Initial-Handshake CRYPTO-space/0-RTT/short-packet、explicit key-phase/key-update short-packet、caller-owned key-phase short-packet、installed-key Handshake/0-RTT long-packet 和 installed-key protected short-packet timer refresh、已 armed 的单个 PTO probe 可绕过 congestion window、ACK 驱动的 frame-payload STREAM/CRYPTO、protected CRYPTO 和 protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission requeue、带 underutilized-cwnd suppression 的 NewReno slow-start/congestion-avoidance 字节计数与 batched-ACK 增长、recovery-period 行为、新拥塞事件后一次性 recovery probe 和 minimum-window ssthresh clamp、不受 PTO backoff 放大的 persistent congestion duration/response、ACK_ECN CE 驱动的 NewReno recovery 响应、带 Initial/Handshake max_ack_delay suppression 的 packet-space PTO PING/new-data/in-flight-CRYPTO/protected-0-RTT-control/protected-0-RTT-STREAM/in-flight-STREAM/cross-space probe hook、ECN validation 与 lifecycle-owned UDP-path mirroring 测试，以及 socket-backed UDP lifecycle loss/PTO recovery、lifecycle congestion-recovery 与 lifecycle STREAM-retransmission loopback。 | 仍需完整 TLS-owned socket-owned protected-packet loss/PTO timer lifecycle 集成和剩余 NewReno 边界。 |
| RFC 9221 QUIC DATAGRAM | Deferred | 明确不在第一轮 transport-core 范围内。 | 核心 transport loop 可用后单独追踪。 |
| RFC 9368 Compatible Version Negotiation | Partial | 已有 `version_information` transport parameter codec、连接层导出/应用校验（含 VN 后 server Version Information downgrade checks）、`VERSION_NEGOTIATION_ERROR` 错误码，以及 client-side incompatible VN packet validation/selection state。 | 仍需完整 incompatible/compatible negotiation 状态机、endpoint routing 集成和互通证明。 |
| RFC 9369 QUIC v2 | Partial | 已有版本常量、long-header packet type bit 映射、Retry packet codec 映射、v2 Retry Integrity Tag helper、address-validation token originating-version binding、RFC 9368 `version_information` transport-parameter 支持，以及 RFC 9369 Initial salt 和 `quicv2` packet-protection label 派生，测试覆盖 Appendix A.1/A.4 向量。 | 仍需完整 compatible version negotiation 状态、endpoint routing 和互通证明。 |
| HTTP/3 和 QPACK | Deferred | 应用层协议不在本 transport-core 计划内。 | transport interop 完成后另起应用层任务。 |

当前代码仍是实验性的 frame-payload 传输骨架。`pollTx` 和
`processDatagram` 只流转未加密 QUIC frame payload 字节；连接层现在有一个
窄范围的 Initial/Handshake CRYPTO/ACK/PING protected long-packet coalesced
send/receive bridge、installed-key Handshake long-packet helper、首个 client Initial DCID 长度与 server Initial token 校验、使用调用方 key 或连接已安装 key 的 0-RTT
STREAM/RESET_STREAM/STOP_SENDING protected long-packet 路由，以及使用调用方 key 的 1-RTT protected short-packet
PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge，并带调用方持有和连接已安装的 key-phase 状态 helper，以及 socket-backed UDP endpoint routing、lifecycle Retry/address-validation routing、lifecycle caller-keyed protected packet/lifecycle loss-recovery/lifecycle congestion-recovery/lifecycle PTO-recovery/lifecycle STREAM-retransmission loopback 和调用方提交的 UDP path-validation route update，但尚不能完整生成或消费 TLS-owned QUIC-over-UDP packet。

## 任务矩阵

| 领域 | 当前状态 | 目标结果 | 验证方式 |
| --- | --- | --- | --- |
| 标准追踪 | 已有核心/延后 RFC 覆盖状态表 | 随实现推进，持续把每个核心 RFC 领域标记为 done、partial、missing 或 deferred。 | Markdown review 加 `zig build test`。 |
| RFC 8999 / 9000 packet codec | 部分完成，已具备 v2 type-bit 感知、endpoint unsupported-version VN response helper 和 client-side VN selection state | 完成版本无关 packet、version negotiation、Retry、long/short header、packet number 与 transport error 值。 | 现有测试覆盖 v1/v2 long-header packet type bit 映射、Retry codec 映射、Version Negotiation response 的 CID echo、client-side VN CID validation、Original Version ignore、mutual-version selection、首个 client Initial DCID 长度校验、server Initial token 拒绝、Initial UDP datagram 1200 字节扩展/丢弃检查、roundtrip、边界值、截断、非法值和分配失败；`run-udp-endpoint-loopback` 证明 Version Negotiation、client-side VN selection 与 Initial classification 的 socket-backed endpoint routing。 |
| RFC 9000 frame codec | frame 集合已覆盖 + frame type 最短 varint 校验 + 未知类型拒绝 + 部分 packet-type 校验 | 覆盖所有 RFC 9000 transport frame，并统一严格校验和错误映射。 | 每类 frame 的合法、截断、非法、未知输入编解码测试。 |
| Transport parameters | 类型化 codec + 连接层暴露 + preferred_address 导出/应用 + RFC 9368 `version_information` 导出/应用校验（含 VN-triggered server downgrade checks） + TLS extension byte 编码/应用 + CryptoBackend byte handoff + 与 peer recovery policy 分离的本端 ACK delay 导出 | 把已导出的参数完整接入 TLS backend transcript handshake，并补齐完整 version-negotiation 状态 ownership。 | 现有 roundtrip、重复/非法参数、连接层应用/导出、TLS extension byte 编码/应用、mock-backend 本端/对端 byte handoff、server preferred_address、`version_information`、VN-triggered downgrade checks、默认值和本端/对端 ACK delay 分离测试覆盖 codec 与连接层表面；后续真实 TLS backend 和 endpoint 测试证明 transcript 集成与完整版本协商。 |
| 连接状态机 | 部分 close-state + peer close 诊断 + idle timeout + 显式 handshake progress 状态 | 建模 Initial、Handshake、0-RTT、1-RTT、idle timeout、closing、draining、closed 状态。 | 现有测试覆盖 close/drain 迁移、closing/draining 入站 datagram 不解析丢弃、peer close 诊断、close 过期、idle 过期、Initial 到 Handshake 到 Confirmed 的 handshake progress，以及非法 packet 回滚；后续 protected-packet 测试覆盖 key-state 迁移。 |
| Packet number spaces | 部分 frame-payload ACK/recovery + CRYPTO 隔离和接收重组 + 带首个 client Initial DCID 长度、server Initial token 校验和 RFC 9000 Initial UDP datagram size 检查的 Initial/Handshake protected CRYPTO/ACK/PING coalesced send/receive bridge + 使用调用方 key 或连接已安装 key 的 0-RTT protected long STREAM/RESET_STREAM/STOP_SENDING 路由 + 1-RTT protected short PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge + frame-type filtering + RFC 9001 client 发送 Handshake / server 接收 Handshake 后的 Initial discard + 会清理已安装 Handshake key 和 ECN 状态的 discard cleanup + 有效 client 侧 HANDSHAKE_DONE、server 侧 sendHandshakeDone 和 backend-confirmed no-output 触发的 Handshake-space discard | 维护独立 Initial、Handshake、Application packet number space，并在后续把 protected packet 路由到匹配空间且遵守剩余 TLS 触发的 key discard 规则。 | 现有 ACK/recovery、CRYPTO 隔离、乱序 CRYPTO 接收、Initial/Handshake protected send/receive（含首个 client Initial DCID 拒绝、server Initial token 拒绝、Initial UDP datagram 1200 字节扩展/丢弃检查）、coalesced send/receive、使用调用方 key 和连接已安装 key 的 0-RTT protected STREAM/RESET_STREAM/STOP_SENDING、1-RTT protected PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive、forbidden-frame、RFC 9001 Initial discard、显式 discard、installed Handshake key cleanup、ECN state cleanup 与有效 HANDSHAKE_DONE/backend-confirmed cleanup 测试证明空间隔离和清理；后续 protected endpoint 测试证明完整路由正确。 |
| 真实 datagram API | 带首个 client Initial DCID 长度、server Initial token 校验和 RFC 9000 Initial UDP datagram size 检查的 Initial/Handshake protected CRYPTO/ACK/PING coalesced send/receive bridge + lifecycle-owned caller-keyed protected Initial/1-RTT short socket loopback + 使用调用方 key 或连接已安装 key 的 0-RTT protected long STREAM/RESET_STREAM/STOP_SENDING 路由 + protected 1-RTT short PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge + 调用方持有和 ACK-gated installed-key key-phase 状态 1-RTT short-packet bridge + 可配置单路径 spin-bit policy + protected long/short-packet helper + 内存态 endpoint DCID/IPv4 四元组 router + VN/Initial/short-header classification 的 socket-backed endpoint routing loopback + socket-backed zero-length CID tuple-routing loopback + socket-backed preferred-address route-migration loopback + socket-backed replacement-CID route-retirement loopback + socket-backed lifecycle connection-ID NEW/RETIRE loopback + socket-backed lifecycle flow-control credit-refresh loopback + socket-backed ECN ACK_ECN validation/CE response loopback + socket-backed lifecycle loss-recovery loopback + socket-backed lifecycle congestion-recovery loopback + socket-backed lifecycle PTO recovery loopback + socket-backed lifecycle STREAM retransmission loopback + socket-backed lifecycle installed-key key-update loopback + socket-backed path-validation route-update loopback + socket-backed lifecycle Retry/address-validation loopback + socket-backed close-triggered route retirement + zero-length CID tuple routing + sequence/retire-prior-to route retirement + endpoint reset-token uniqueness checks + caller-validated path update + retired-CID stateless reset token lookup/datagram construction + socket-backed retired-CID stateless reset emission loopback + route/reset/drop receive classification | 在当前 frame-payload 骨架之上增加受保护 QUIC datagram 收发 API。 | 现有 helper 测试覆盖受保护 Initial packet、protected short-packet roundtrip、key-phase short-packet selection、protected long-packet boundary peeking、endpoint DCID routing（含 zero-length CID tuple routing、sequence/retire-prior-to route retirement、endpoint reset-token reuse rejection 和 caller-validated path update）、route retirement 后的 stateless reset token lookup/datagram construction，以及 endpoint receive action classification；`examples/udp_endpoint_loopback.zig` 覆盖真实 loopback UDP Version Negotiation response delivery、supported Initial accept、client Initial SCID response routing 和 server Initial SCID short-header routing；`examples/udp_zero_cid_loopback.zig` 覆盖真实 loopback UDP 上 short/long datagram 按 zero-length destination CID 的本地/远端 tuple 路由、按 path 退役，以及 route path update；`examples/udp_preferred_address_loopback.zig` 覆盖真实 loopback UDP preferred-address migration commit、当前 route 退役、preferred CID 在 preferred server address 上路由、active-migration-disabled policy 对 stray path 的拒绝，以及退役后的 reset-token lookup；`examples/udp_replacement_cid_loopback.zig` 覆盖真实 loopback UDP replacement-CID registration with `retire_prior_to`、retired sequence route 的 inactive reset-token lookup、active replacement CID routing、invalid sequence rejection，以及 stray path 上 active-migration-disabled rejection；`examples/udp_connection_ids_loopback.zig` 覆盖真实 loopback UDP protected NEW_CONNECTION_ID delivery、通过 lifecycle owner 更新新签发 CID 的 endpoint replacement route、inactive old-CID reset-token lookup、protected RETIRE_CONNECTION_ID 经 active replacement CID 路由、server-side local CID retirement 和 ACK cleanup；`examples/udp_flow_control_loopback.zig` 覆盖真实 loopback UDP lifecycle-owned protected STREAM delivery 到 receive limit、protected STREAM_DATA_BLOCKED routing、接收侧 MAX_DATA/MAX_STREAM_DATA credit refresh delivery、resumed STREAM data 和 final ACK cleanup；`examples/udp_ecn_validation_loopback.zig` 覆盖真实 loopback UDP 投递建模 ECT(0) protected PING、protected ACK_ECN validation、ACK_ECN CE 驱动的 NewReno recovery 响应、当前 UDP tuple 的 endpoint ECN state update，以及迁移路径 ECN 隔离；该示例不声称真实 IP-header ECN marking；`examples/udp_loss_recovery_loopback.zig` 覆盖真实 loopback UDP protected short PING delivery，随后用 protected ACK 驱动 packet-threshold loss，并用 lifecycle timer 驱动 time-threshold cleanup 和最终 timer disarm；`examples/udp_congestion_recovery_loopback.zig` 覆盖真实 loopback UDP lifecycle-owned protected short PING/ACK routing，随后验证 NewReno recovery-period 对重复 loss reduction 的抑制，以及 persistent congestion 把 congestion window 降到 minimum window；`examples/udp_pto_recovery_loopback.zig` 覆盖真实 loopback UDP lifecycle timer 驱动的 ACK loss 后 PTO、protected PING fallback probe delivery、queued STREAM data 和 in-flight STREAM/CRYPTO data 作为 PTO probe、重复 receive/CRYPTO range 丢弃、ACK cleanup 和最终 timer disarm；`examples/udp_stream_retransmission_loopback.zig` 覆盖 lifecycle-owned route selection 下 ACK 驱动的 1-RTT STREAM retransmission 和 final ACK cleanup；`examples/udp_key_update_loopback.zig` 覆盖真实 loopback UDP lifecycle-owned installed-key key update initiation、next key-phase packet routing、authenticated receive 后 peer key-phase advancement、ACK delivery、key-update ACK gating 和 second-update re-enable；`examples/udp_protected_loopback.zig` 覆盖 lifecycle-owned 真实 loopback UDP protected client Initial route registration、protected server Initial routing、routed client 1-RTT PING 和 routed server 1-RTT ACK；`examples/udp_path_validation_loopback.zig` 覆盖真实 loopback UDP PATH_CHALLENGE 投递到新的对端端口、PATH_RESPONSE 以 `path_changed` 路由、验证后由调用方提交 route path update，以及新路径上的 confirmed routing；`examples/udp_retry_loopback.zig` 覆盖 lifecycle-owned 真实 loopback UDP Retry delivery、Retry Source CID route switching、address-bound Retry token validation、replay rejection、follow-up protected Initial routing 和 Retry transport-parameter checks；`examples/udp_close_lifecycle_loopback.zig` 覆盖 UDP 上的 protected close delivery、connection-handle route retirement、保留的 inactive-CID reset-token lookup、reset emission 和 client token matching；`examples/udp_stateless_reset_loopback.zig` 覆盖真实 loopback UDP reset trigger 接收分类、server reset 发出和 client token 匹配；连接层测试覆盖 protected Initial/Handshake CRYPTO、首个 client Initial DCID 拒绝、server Initial token 拒绝、Initial UDP datagram 1200 字节扩展/丢弃检查、ACK-only、PING、使用调用方 key 和连接已安装 key 的 0-RTT STREAM/RESET_STREAM/STOP_SENDING、coalesced send/receive、protected 1-RTT PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive、installed-key short PING/ACK exchange、installed-key ACK-gated key-update 发起、key-phase 状态版 PING receive 与失败状态保持，以及 enabled/disabled spin-bit 状态更新和 invalid-packet 状态保持；后续 socket-backed client/server loopback 必须使用 TLS-owned keys 和 endpoint lifecycle ownership。 |
| TLS 集成 | 已有带 per-space 乱序接收缓冲的 CRYPTO bridge hook、可插拔 backend drive helper、transport-parameter byte handoff、mock Handshake/0-RTT/1-RTT traffic-secret handoff、backend-confirmed no-output Handshake discard、显式 installed-key 0-RTT accept/reject 和建模 1-RTT 边界的 0-RTT discard，尚无真实 TLS backend | 使用可插拔 TLS 后端接口，由 CRYPTO frame 驱动握手。 | 现有 mock-backend 测试覆盖 CRYPTO 投递、本端/对端 transport-parameter byte handoff、backend 输出排队和保留、Handshake、0-RTT 与 1-RTT traffic-secret 安装、handshake confirmation、backend-confirmed no-output Handshake discard、installed-key 0-RTT accept 前拒绝、accept 后接收 0-RTT、reject 后丢弃 key、client 安装 1-RTT key 后清理 0-RTT、server 接受 1-RTT receive 后清理 0-RTT 和 scratch-buffer 边界；后续真实 TLS transcript 测试与本地 1-RTT 建立测试证明完整集成。 |
| Packet protection | 部分 v1/v2 Initial keys + AES-GCM payload/header protection + protected long/short-packet helper + caller-keyed protected UDP loopback + socket-backed lifecycle installed-key key-update loopback + unprotected spin-bit peek + v1/v2 Retry Integrity Tag helper + `quic ku` key-update 派生 + 连接已安装 Handshake 和 0-RTT long-packet key + 显式 installed-key 0-RTT accept/reject + RFC 9001 Handshake send/receive 边界的 Initial discard + 显式 installed Handshake/0-RTT key discard hook + client 侧 HANDSHAKE_DONE、server 侧 sendHandshakeDone 与 backend-confirmed no-output 触发的 Handshake key discard + 建模 1-RTT 边界触发的 client/server 0-RTT key discard + 调用方持有和连接已安装的 1-RTT key-phase 状态 helper、ACK-gated installed-key update 发起与显式 short-packet key-phase 收发 | 实现真实 TLS-backed early-data secret ownership、真实 TLS Handshake/1-RTT secret production、header protection、AEAD、剩余 TLS 触发的 Handshake key discard、完整 TLS 0-RTT acceptance/replay policy、完整 TLS-owned live key-update 调度/old-key discard，以及 Initial key 和 Retry integrity helper 之外的剩余 RFC 9369 packet protection 行为。 | 现有 RFC 向量和固定向量测试覆盖 v1 与 v2 Initial 派生、header protection、AEAD protection、protected packet、v1 与 v2 Retry Integrity Tag、spin-bit peeking、`quic ku` key-update 派生、调用方持有 key-phase 状态迁移、调用方 key 的 key-phase packet selection、mock Handshake/0-RTT/1-RTT traffic-secret 安装、Handshake send/receive 后 RFC 9001 Initial discard、installed-key Handshake long-packet exchange、installed-key 0-RTT long-packet exchange、installed-key 0-RTT accept 前拒绝、accept 后接收 0-RTT、reject 后丢弃 key、显式 installed-key discard cleanup、有效 HANDSHAKE_DONE 和 backend-confirmed no-output cleanup、client 安装 1-RTT key 后 0-RTT cleanup、server 1-RTT receive 失败保留和成功 cleanup、installed-key short-packet exchange、installed-key key-phase 成功接收后推进、handshake confirmation 前拒绝 installed-key key-update、ACK-gated repeat rejection、ACK 后重新允许、invalid-payload rollback、`run-udp-protected-loopback` socket delivery，以及 `run-udp-key-update-loopback` 通过真实 loopback UDP socket 证明 lifecycle-owned installed-key key update；后续 TLS/endpoint 测试覆盖真实 traffic-secret 使用、剩余自动 Handshake key discard 和完整 TLS-owned live key-update 调度。 |
| Spin bit | 可配置单路径 short-header spin-bit state + protected spin-bit peek + lifecycle-owned route-update spin-bit reset + socket-backed UDP lifecycle spin-bit route-update loopback | 保持默认禁用行为，并在后续把多路径 spin-bit 实例绑定到完整 endpoint path lifecycle。 | 现有测试覆盖 enabled/disabled spin-bit 更新、invalid-packet 状态保持，以及 committed route path update 后由 lifecycle 重置 spin bit；`run-udp-spin-bit-loopback` 证明真实 loopback UDP socket 上第一轮 false spin、迁移端口上的第二轮 true-spin packet 以 `path_changed` 路由、lifecycle route update 后 spin reset、reset ACK spin 和 ACK cleanup。 |
| Streams | 部分接收重组与重复重传丢弃 + FIN completion + 本地 reset/stop 可观测 + 隐式低编号接收 stream 创建 + pre-STREAM peer-bidirectional STOP_SENDING 处理 | 在当前内存态重组骨架之外继续完成 stream 状态机、FIN/reset 规则和读写行为。 | 双向、单向、FIN、reset、STOP_SENDING、乱序、重复重传、冲突重叠、回滚、final-size 测试。 |
| Flow control | 部分 receive MAX 与 stream-count 刷新 + 可配置 receive data/stream-count window + BLOCKED 可观测/重发/增长 + 隐式低编号接收 stream 创建 + STREAM_DATA_BLOCKED 接收状态校验 + pre-STREAM peer-bidirectional MAX_STREAM_DATA 处理 + protected short-packet 与 socket-backed UDP credit-refresh exchange | 完成剩余自适应 MAX/BLOCKED 策略响应。 | connection、stream 与 stream-count 级 blocked/unblocked 测试，包含目标 receive-window 刷新、peer-BLOCKED 增长、stream-count-window 增长、接收侧 stream-state 校验、调用方 key protected short-packet flow-control exchange，以及 `run-udp-flow-control-loopback` 对 STREAM_DATA_BLOCKED/MAX_DATA/MAX_STREAM_DATA/resumed STREAM 的 lifecycle-owned socket delivery。 |
| Connection IDs | 部分本端/对端生命周期 + stateless-reset-token uniqueness checks + endpoint sequence/retire-prior-to DCID route table + lifecycle-owned endpoint replacement-CID registration helper + connection-handle route retirement + socket-backed replacement-CID route-retirement loopback + socket-backed lifecycle connection-ID NEW/RETIRE loopback | 增加围绕 DCID routing 和 replacement policy 的完整 socket-owned connection lifecycle 集成。 | 现有测试覆盖本端 NEW_CONNECTION_ID 签发、对端 RETIRE 处理、对端签发 NEW_CONNECTION_ID 生命周期、duplicate CID/token 拒绝、limit、回滚、endpoint route 注册、endpoint reset-token reuse rejection、带 retire_prior_to 应用的 endpoint 与 lifecycle-owned replacement-CID registration、按 CID、sequence number、retire_prior_to threshold 或 connection handle 的 route retirement，以及 unknown/ambiguous CID 拒绝；`run-udp-replacement-cid-loopback` 证明真实 loopback UDP socket 上的 replacement route registration、retire_prior_to retirement、inactive reset-token lookup、active replacement routing、invalid sequence rejection 和 active-migration-disabled rejection；`run-udp-connection-ids-loopback` 证明真实 loopback UDP socket 上的 protected NEW_CONNECTION_ID delivery、lifecycle replacement route installation、protected RETIRE_CONNECTION_ID 经 active replacement CID 路由、server local-CID retirement、inactive reset-token lookup 和 ACK cleanup；后续 endpoint 测试覆盖完整 socket-owned connection lifecycle 集成。 |
| Tokens and Retry | 部分 codec + v1/v2 Retry Integrity Tag helper + server 侧 NEW_TOKEN 签发 + client 侧 NEW_TOKEN 存储 + 建模的 server anti-amplification 发送限制 + HMAC-SHA256 地址绑定、带过期时间并绑定 originating version 的 token 生成/校验 + endpoint IPv4 peer-address token binding + 带轮换 secret、secret-set 导出/恢复、replay-filter snapshot 导出/恢复和 replay 拒绝的内存态 endpoint 地址验证策略 + 显式一次性 Retry token 校验 + server 侧 Retry datagram 签发 + 客户端侧 Retry datagram 处理与 handshake CID transport-parameter 校验/导出 + socket-backed UDP lifecycle Retry/address-validation loopback | 围绕已导出的 secret/replay snapshot 增加生产级 endpoint token secret 存储/分发，并接入 socket-owned endpoint lifecycle。 | 现有测试覆盖 Retry packet codec、RFC 9001 与 RFC 9369 Retry Integrity Tag 向量、protected NEW_TOKEN 签发/存储、建模的 3x anti-amplification 限制、HMAC 地址 token 的类型/地址/篡改/过期/version mismatch 检查、endpoint remote IPv4/port token binding、内存态 endpoint secret 轮换、secret-set 导出/恢复及保留数裁剪、replay-filter snapshot 导出/恢复及保留数裁剪、有界 replay-filter 的重复和容量行为、验证后记录 replay 指纹、一次性 Retry token 消费、server 侧 Retry datagram 签发、客户端侧 Retry datagram 处理、`initial_source_connection_id`、`original_destination_connection_id` 与 `retry_source_connection_id` 校验/导出；`run-udp-retry-loopback` 证明 lifecycle-owned 真实 UDP Retry delivery、地址绑定 token 校验、replay rejection、token 消费和 Retry CID transport-parameter validation；后续 endpoint 测试覆盖生产级 secret/replay 存储集成。 |
| Path validation | 部分 timeout/retry + protected exchange + PATH_RESPONSE 验证后由调用方提交 `EndpointConnectionLifecycle` route update + socket-backed UDP lifecycle path-validation route-update loopback | 在真实 UDP routing 拥有连接路径后自动绑定 endpoint path 身份。 | 现有测试覆盖匹配、重复、不匹配、回滚、超时重试、重试耗尽、protected PATH_CHALLENGE/PATH_RESPONSE exchange、protected PATH_RESPONSE 验证后的 endpoint route path update，以及 lifecycle-owned caller-validated route path update；`run-udp-path-validation-loopback` 证明同一 lifecycle route-update 流程可在 loopback UDP socket 和新对端端口上运行；后续 endpoint 测试覆盖自动 path identity ownership。 |
| Stateless reset | 部分 helper + constant-time token match + 连接层检测 + NEW_CONNECTION_ID token uniqueness checks + endpoint inactive-CID reset datagram construction + 通过 `EndpointConnectionLifecycle` 暴露的 route/reset/drop receive classification + socket-backed UDP reset emission loopback + socket-backed close-triggered lifecycle route retirement/reset loopback | 把 reset emission 接入 socket 拥有的 endpoint lifecycle 和 connection close/drop policy。 | 现有测试覆盖 reset token 命中、误判拒绝、短 datagram 拒绝、跨 CID duplicate-token 拒绝、retired token 忽略、active route token 抑制、retired route token lookup、inactive-route reset datagram construction、smaller-than-trigger sizing、route/reset/drop receive action classification、lifecycle-owned route/reset/drop after timer-disarming retirement 和 ambiguous reset-token CID 拒绝；`run-stateless-reset` 演示 endpoint inactive-CID reset action；`run-udp-stateless-reset-loopback` 演示真实 UDP trigger 投递、reset 发出和客户端 token 匹配；`run-udp-close-lifecycle-loopback` 演示 protected close delivery、`EndpointConnectionLifecycle` connection-handle route retirement、保留 reset token lookup、reset emission 和 client token matching；后续 endpoint 测试覆盖完整 TLS-owned lifecycle 集成。 |
| ECN validation | 部分 frame-payload ACK_ECN 校验 + ACK_ECN CE 驱动的 NewReno recovery 响应 + lifecycle-owned endpoint UDP-path ECN state policy + socket-backed UDP lifecycle ACK_ECN validation/CE response loopback | 等 socket packetization 暴露 packet ECN mark 后，把 ECN validation 绑定到真实 IP ECN 标记。 | 现有测试覆盖 ECT(0) 成功、CE counter 拥塞响应、NewReno recovery period 内重复 CE 抑制、缺少 ACK_ECN 失败、counter 不足、counter 总量超过已发送 ECT packet、reordered ACK 处理、回滚、endpoint path-identity state isolation，以及 connection ECN validation state 到 UDP path identity 的 lifecycle-owned mirroring；`run-udp-ecn-validation-loopback` 覆盖 modeled ECT(0) protected PING delivery、protected ACK_ECN 成功、ECN-CE ACK_ECN 拥塞响应、当前 UDP tuple 的 `EndpointConnectionLifecycle` ECN state update，以及不声称真实 IP-header ECN marking 的迁移路径隔离。 |
| RFC 9002 recovery | 部分 Initial/Handshake RTT ACK-delay suppression + Application ACK delay scaling/capping + packet/time-threshold loss + 带 closing/draining disarm 的 aggregate loss-time-before-PTO timer deadline selection/service + endpoint-owned 多连接 recovery timer scheduling + 已 armed 的单个 PTO probe 绕过 congestion window + ACK 驱动的 frame-payload STREAM/CRYPTO、protected CRYPTO 和 protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission requeue + NewReno underutilized-cwnd suppression、slow-start/congestion-avoidance 字节计数与 batched-ACK 增长、recovery period、新拥塞事件后一次性 recovery probe 和 minimum-window ssthresh clamp + 不受 PTO backoff 放大的 persistent congestion duration/response + ACK_ECN CE 驱动的 NewReno recovery 响应 + 带 Initial/Handshake max_ack_delay suppression 的 packet-space PTO PING/new-data/in-flight-CRYPTO/protected-0-RTT-control/protected-0-RTT-STREAM/in-flight-STREAM/cross-space probe hook + socket-backed UDP lifecycle loss/PTO recovery、lifecycle congestion-recovery 与 lifecycle STREAM-retransmission loopback | 实现 socket-owned protected-packet loss/PTO timer lifecycle 集成和剩余 NewReno 边界。 | 现有测试覆盖 ACK、Initial/Handshake RTT ACK-delay suppression、ACK delay exponent scaling、handshake confirmed 后 max_ack_delay 截断、packet-threshold loss、ACK 驱动和 timeout 驱动的 time-threshold loss、aggregate timer deadline/service 的 loss-time 优先于 PTO、deadline 前无副作用、due loss-time service 不额外排 PTO probe、最早 PTO space service、closing/draining recovery-timer disarm，以及 endpoint-owned 多连接 timer scheduling/re-arm/disarm、protected short PTO service/disarm、protected short loss-time retransmission、protected short CRYPTO loss-time 到期/retransmission、ACK 驱动 lost STREAM、frame-payload/protected CRYPTO requeue、protected 0-RTT STREAM requeue 和 protected 0-RTT RESET_STREAM/STOP_SENDING requeue、retransmission requeue 后 invalid-payload rollback、NewReno underutilized-cwnd suppression 与 slow-start/congestion-avoidance 字节计数/batched-ACK 增长、NewReno recovery-period 抑制 loss 和 ECN-CE、新拥塞事件后一次性 recovery probe、minimum-window ssthresh clamp、不受 PTO backoff 放大的 persistent congestion duration/response、packet-number-space PTO PING 排队/backoff、一次性 PTO probe congestion-window bypass、cross-space PTO peer probes、Initial/Handshake PTO deadline 不计 max_ack_delay、queued STREAM data probe selection、PTO 驱动 in-flight CRYPTO/STREAM/protected-0-RTT-STREAM/protected-0-RTT-control retransmission 和拥塞窗口算术；`run-loss-recovery` 覆盖 aggregate loss-time timer service、NewReno underutilized-cwnd suppression 与字节计数/batched-ACK congestion-window 增长、新拥塞事件 STREAM recovery probe、minimum-window ssthresh clamp，以及不会被 PTO backoff 放宽的 persistent congestion duration；`run-endpoint-recovery-timers` 覆盖多个 caller-owned connection handle 之间的 endpoint-owned selection/servicing 与 closing-state recovery timer disarm；`run-crypto-stream` 覆盖 frame-payload Handshake CRYPTO loss requeue/retransmission 和 protected 1-RTT CRYPTO ACK-loss requeue/retransmission；`run-pto-recovery` 覆盖 aggregate PTO timer service、Initial/Handshake RTT ACK-delay suppression、已 armed 的单个 PTO probe 绕过 congestion window、protected 1-RTT CRYPTO PTO probe selection 和 cross-space PTO peer probes；`run-udp-loss-recovery-loopback` 覆盖 UDP 上的 protected short PING delivery、protected ACK 驱动的 packet-threshold loss removal、lifecycle timer 驱动的 time-threshold cleanup 和最终 timer disarm；`run-udp-congestion-recovery-loopback` 覆盖 UDP 上 lifecycle-owned protected short PING/ACK routing、NewReno recovery-period 内重复 loss reduction 抑制，以及 persistent congestion 降到 minimum window；`run-udp-ecn-validation-loopback` 覆盖 protected ACK_ECN CE response 在 UDP 上降低 congestion window；`run-udp-pto-recovery-loopback` 覆盖 lifecycle timer 驱动的 protected UDP packet ACK-loss PTO、PING fallback probe delivery、queued STREAM data 作为 PTO probe、in-flight STREAM 和 CRYPTO data 作为 PTO probe、重复 receive range/CRYPTO range 丢弃、ACK cleanup 和最终 timer disarm；`run-udp-stream-retransmission-loopback` 覆盖 protected UDP packet 上 lifecycle-owned route selection 下 ACK 驱动的 1-RTT STREAM retransmission 和 final ACK cleanup；`packet_spaces` 覆盖 protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING 的 ACK-loss requeue 和新 packet number 重传。剩余可控时钟测试覆盖完整 socket-owned protected-packet loss/PTO timer lifecycle 集成。 |
| UDP endpoint routing | 部分内存态 DCID/IPv4 四元组 router + 带 client-side VN selection 的 socket-backed UDP endpoint routing loopback + socket-backed zero-length CID tuple-routing loopback + socket-backed preferred-address route-migration loopback + socket-backed replacement-CID route-retirement loopback + socket-backed lifecycle connection-ID NEW/RETIRE loopback + socket-backed lifecycle flow-control credit-refresh loopback + socket-backed ECN ACK_ECN validation/CE response loopback + socket-backed lifecycle loss-recovery loopback + socket-backed lifecycle congestion-recovery loopback + socket-backed lifecycle PTO recovery loopback + socket-backed lifecycle STREAM retransmission loopback + socket-backed lifecycle installed-key key-update loopback + socket-backed path-validation route-update loopback + socket-backed lifecycle Retry route-switch/address-validation loopback + socket-backed close-triggered route retirement/reset loopback + socket-backed stateless reset emission loopback + unsupported-version VN response helper + client-side VN selection state + client Initial Source CID route registration + supported-version unknown-DCID Initial accept classification + accepted Initial Original DCID/server Initial SCID route registration + zero-length CID tuple routing + Retry DCID switch helper + caller-validated preferred-address migration commit + sequence/retire-prior-to/connection-handle route retirement + endpoint reset-token uniqueness checks + caller-validated path update + retired-CID stateless reset token lookup/datagram construction + route/version-negotiation/reset/drop/accept receive classification | 按 DCID、本地/远端地址四元组、版本支持和连接状态路由 UDP datagram。 | 现有确定性 endpoint 测试覆盖 long-header DCID routing、unsupported-version Version Negotiation response generation 和 CID echo、client Initial Source CID route 注册以接收 server Initial/VN response、supported-version unknown-DCID Initial accept metadata、accepted Initial route 注册与回滚、client-side VN selection/ignore/reject state、short-header registered-CID matching、zero-length CID tuple routing、duplicate route 拒绝、duplicate sequence 拒绝、stateless reset token reuse rejection、Retry Source CID route switching、调用方验证后的 preferred-address route migration、unknown CID 拒绝、ambiguous short-header CID 拒绝、path-specific zero-CID retirement、面向 RETIRE_CONNECTION_ID wiring 的 sequence-number route retirement、retire_prior_to threshold retirement、connection-handle route retirement、caller-validated route path update、stale path-update rejection、route retirement、active-migration-disabled path 拒绝、inactive route 的 stateless reset token lookup、inactive route 的 reset datagram construction，以及 route/version-negotiation/reset/drop/accept receive action classification；`run-udp-endpoint-loopback` 覆盖真实 loopback UDP socket 上的路由决策和 client-side VN selection；`run-udp-zero-cid-loopback` 覆盖真实 loopback UDP socket 上的 zero-length CID tuple routing、long-header zero-DCID routing、path-specific retirement 和 route path update；`run-udp-preferred-address-loopback` 覆盖真实 loopback UDP socket 上调用方提交的 preferred-address route migration、preferred CID 路由、当前 route 退役、active-migration-disabled stray-path 拒绝，以及 retained reset-token lookup；`run-udp-replacement-cid-loopback` 覆盖真实 loopback UDP socket 上的 replacement-CID route registration、retire_prior_to sequence retirement、inactive reset-token lookup、active replacement routing、invalid replacement sequence rejection 和 active-migration-disabled stray-path rejection；`run-udp-connection-ids-loopback` 覆盖真实 loopback UDP socket 上 protected NEW_CONNECTION_ID 和 RETIRE_CONNECTION_ID 经 lifecycle-owned endpoint route 的交换、replacement CID routing、inactive reset-token lookup 与 active replacement token suppression；`run-udp-flow-control-loopback` 覆盖真实 loopback UDP socket 上 protected STREAM_DATA_BLOCKED、MAX_DATA/MAX_STREAM_DATA、resumed STREAM data 和 final ACK cleanup 经 lifecycle-owned endpoint route 传递；`run-udp-ecn-validation-loopback` 覆盖 loopback UDP socket 上 modeled ECT(0) protected PING routing、protected ACK_ECN validation、ACK_ECN CE response、endpoint ECN state update 和迁移路径 ECN isolation；`run-udp-loss-recovery-loopback` 覆盖 loopback UDP socket 上 protected short PING routing，以及 ACK 驱动 packet-threshold 和 lifecycle timer 驱动 time-threshold loss 和最终 timer disarm；`run-udp-congestion-recovery-loopback` 覆盖 loopback UDP socket 上 lifecycle-owned protected short PING/ACK routing、NewReno recovery-period 抑制和 persistent congestion 窗口降低；`run-udp-pto-recovery-loopback` 覆盖 loopback UDP socket 上 lifecycle timer 驱动的 ACK-loss PTO timing、protected PING fallback probe delivery、queued STREAM 与 in-flight STREAM/CRYPTO PTO probe delivery、重复 receive/CRYPTO range 丢弃、ACK cleanup 和最终 timer disarm；`run-udp-stream-retransmission-loopback` 覆盖 loopback UDP socket 上 lifecycle-owned route selection 下 sparse ACK 驱动的 1-RTT STREAM retransmission 和 final ACK cleanup；`run-udp-key-update-loopback` 覆盖真实 loopback UDP socket 上 lifecycle-owned installed-key key phase routing、peer key-phase advancement 和 ACK-gated second-update re-enable；`run-udp-path-validation-loopback` 覆盖新对端端口上的 path_changed routing，随后由调用方提交 path update，并在新路径上确认 route；`run-udp-retry-loopback` 覆盖 loopback UDP socket 上 lifecycle-owned Retry response routing、Retry Source CID route switching、follow-up Initial routing 和 accepted server Initial response routing；`run-udp-close-lifecycle-loopback` 覆盖 loopback UDP socket 上 close-triggered connection-handle route retirement 和后续 inactive-CID reset emission；`run-udp-stateless-reset-loopback` 覆盖 inactive CID 的 socket-backed stateless reset 发出；后续测试覆盖 protected client/server 集成。 |
| 互通 | 未实现 | 至少与一个外部 QUIC 实现验证最小 echo flow。 | 手动或可选 CI 脚本记录对端实现和版本。 |

## 进展记录

- 2026-05-29：扩展 RFC 9002/RFC 3465 NewReno congestion-avoidance
  credit 的 batched ACK 处理。`growCongestionAvoidance()` 现在会消耗累计
  ACK credit 中每一个完整 congestion-window 单位，因此单个 ACK frame
  若新确认多个窗口的数据，可以增长多个 max datagram，同时按更新后的窗口保留
  剩余 credit。测试覆盖直接 recovery state 和 connection ACK 聚合路径；
  `loss_recovery` 现在打印 `batched_avoidance_cwnd=14400`。
- 2026-05-29：新增 closing/draining 后 aggregate RFC 9002 recovery timer
  disarm。`lossDetectionTimerDeadlineMillis()` 在 close state 阻止继续
  loss/PTO recovery work 后返回 null，因此 `EndpointConnectionLifecycle`
  刷新 timer 时会移除 stale endpoint timer，同时 close/drain deadline 仍由
  connection 单独持有。测试覆盖直接 closing/draining 查询与 endpoint timer
  disarm；`endpoint_recovery_timers` 现在打印 `close_disarmed=true`。
- 2026-05-28：新增 RFC 9002/RFC 3465 NewReno congestion-avoidance
  字节计数 credit。`Recovery` 现在会在 congestion avoidance 阶段累计已
  ACK 字节，并在达到完整 congestion-window credit 后按 max-datagram
  增量增长 `congestion_window`，避免 tiny ACK 因整数取整被逐 ACK 放大。
  测试覆盖直接 recovery state 和 connection ACK 路径；`loss_recovery`
  现在会先打印只累计 credit 但未增长的 cwnd，再打印完整字节计数后的
  cwnd 增长。
- 2026-05-28：新增 RFC 9002 NewReno underutilized-cwnd 增长抑制。
  连接 ACK 处理现在会在应用 ACK 前检查 bytes in flight 是否已经达到
  congestion window；未充分利用窗口的 ACK 仍会更新 RTT、PTO count 和
  bytes-in-flight accounting，但不会增长 `congestion_window`。测试覆盖直接
  recovery helper 与 connection ACK 路径；`loss_recovery` 现在会先打印未增长的
  underutilized cwnd，再展示满窗口 slow-start 与字节计数 congestion-avoidance 增长。
- 2026-05-28：新增 RFC 9002 NewReno 新拥塞事件后一次性 recovery probe
  额度。当 ACK 驱动 loss 或 ACK_ECN CE 启动新的 recovery period，且受影响的
  packet number space 已有 ack-eliciting 数据待发时，下一次发送可以绕过降窗后的
  congestion window 一次，同时仍受 anti-amplification 和输出 buffer 大小检查约束。
  测试覆盖 full-cwnd STREAM 在 packet-threshold loss 后仍能重传；
  `loss_recovery` 现在打印 probe 重传字节数、cwnd 和 inflight 证据。
- 2026-05-28：把 Initial/Handshake packet-number-space discard cleanup 扩展到
  ECN 状态。`discardPacketNumberSpace()` 现在会清理被丢弃空间中已建模的 ECT
  sent counters、累计 ACK_ECN counters、ECN largest-acknowledged 和 validation
  state。测试覆盖 capable Handshake ECN state 在 discard 后回到 `unknown`；
  `packet_spaces` 会打印已丢弃 Handshake ECN state 证据。
- 2026-05-28：对 Handshake RTT 样本抑制 ACK delay。RTT 更新现在把
  Initial 与 Handshake packet number space 都作为立即确认空间处理；Application
  packet 仍保留对端 ACK delay exponent scaling 和 handshake confirmed 后的
  `max_ack_delay` 截断。测试覆盖第二个 RTT 样本，避免 Handshake ACK delay 被错误
  扣入 RTT；`pto_recovery` 现在打印 Handshake smoothed RTT 证据。
- 2026-05-27：新增一次性 PTO probe congestion-window bypass。PTO service 现在会
  为已有 pending data、retransmission data 或 fallback PING 在对应 packet number
  space 上 armed 一个 probe marker；该 space 的下一次 ack-eliciting 发送可以绕过
  congestion-window 准入，但仍受 endpoint send-budget 检查约束。发送 commit 路径会
  消耗该 marker。测试覆盖 frame-payload 与 protected short-packet PTO probe 在
  bytes in flight 已等于 `congestion_window` 时仍可发送；`pto_recovery` 现在为该
  probe 打印 `cwnd=100 inflight=101`。
- 2026-05-27：新增 `EndpointConnectionLifecycle`，把 endpoint routing 和
  recovery-timer scheduling 交给同一个 endpoint state owner。它仍保持现有
  caller-owned `QuicConnection` 模型，但 socket event loop 现在可以通过同一状态
  owner 对 connection handle 执行 arm、service、route 和 retire；retire 会同时
  移除该 handle 的 route 和任何已 armed 的 loss/PTO timer。测试覆盖 route lookup、
  active timer arming、route/timer retirement 和第二次 retire 的幂等行为；
  `endpoint_recovery_timers` 现在同时打印 `timers_remaining=0` 与
  `routes_remaining=0`。剩余工作是完整 TLS-owned socket-backed protected-packet
  lifecycle 集成和剩余 NewReno 边界。
- 2026-05-28：新增 endpoint lifecycle 的 installed-key protected 1-RTT
  short-packet send/receive timer refresh helper。Socket loop 现在可以通过
  `EndpointConnectionLifecycle` poll 或 process 连接自持 key 的 short packet，
  并在同一次调用中刷新 endpoint-owned recovery timer 表。测试覆盖 route-selected
  protected PING delivery、ACK generation、ACK cleanup 和最终 timer disarm；
  `endpoint_recovery_timers` 现在会打印 `protected_timers=0`。
- 2026-05-28：新增 endpoint lifecycle 的 protected long-header datagram
  send/receive timer refresh helper。Socket loop 现在可以通过
  `EndpointConnectionLifecycle` poll 或 process Initial、Handshake、0-RTT
  long packet，并同步 endpoint-owned recovery timer 表。测试覆盖
  route-selected protected Initial CRYPTO delivery、Initial ACK cleanup 和最终
  timer disarm；`endpoint_recovery_timers` 的 `protected_bytes` 现在包含
  protected long Initial/ACK exchange。
- 2026-05-28：新增 endpoint lifecycle 的 connection-installed Handshake
  long-packet send/receive timer refresh helper。TLS/`CryptoBackend` 安装
  Handshake traffic secrets 后，socket loop 可通过 `EndpointConnectionLifecycle`
  发送或处理 Handshake long packet，不再在 endpoint loop 中传 packet-protection
  key。测试覆盖 route-selected installed-key Handshake CRYPTO delivery、
  Handshake ACK cleanup 和最终 timer disarm；`endpoint_recovery_timers` 的
  `protected_bytes` 现在包含 installed Handshake exchange。
- 2026-05-28：新增 endpoint lifecycle 的 connection-installed 0-RTT
  long-packet send/receive timer refresh helper。TLS/`CryptoBackend` 安装本端
  或已接受的 peer early-data secret 后，socket loop 可通过
  `EndpointConnectionLifecycle` 发送或处理 0-RTT long packet，不再在 endpoint
  loop 中传 0-RTT packet-protection key。测试覆盖 route-selected installed-key
  0-RTT STREAM delivery、由 1-RTT ACK 延迟清理 Application ACK、以及最终
  timer disarm；`endpoint_recovery_timers` 的 `protected_bytes` 现在包含
  installed 0-RTT exchange。
- 2026-05-28：新增 endpoint lifecycle 的 caller-keyed protected 1-RTT
  short-packet send/receive timer refresh helper。仍由 socket loop 外部持有
  packet-protection key 的路径，现在也可复用 `EndpointConnectionLifecycle`
  这个 route/timer owner。测试覆盖 route-selected caller-keyed PING delivery、
  ACK cleanup 和最终 timer disarm；`endpoint_recovery_timers` 的
  `protected_bytes` 现在包含 caller-keyed short exchange。
- 2026-05-28：新增 endpoint lifecycle 的 caller-owned key-phase-state 1-RTT
  short-packet send/receive timer refresh helper。外部持有的 key-update 状态
  现在也可穿过 endpoint route/timer owner，同时 `QuicConnection` 继续持有
  packet-number、ACK 与 recovery 状态。测试覆盖 route-selected next key-phase
  PING delivery、认证成功后的 peer key-phase advancement、ACK cleanup 和最终
  timer disarm；`endpoint_recovery_timers` 的 `protected_bytes` 现在包含
  caller-owned key-phase exchange。
- 2026-05-28：新增 endpoint lifecycle 的 explicit key-phase 与 key-update
  protected 1-RTT short-packet timer refresh helper。确定性 key-update 测试现在
  可以把 wire key-phase bit 与 current/next receive key 穿过 endpoint
  route/timer owner。测试覆盖 route-selected next-key PING delivery、显式
  current/next-key receive、ACK cleanup 和最终 timer disarm；
  `endpoint_recovery_timers` 的 `protected_bytes` 现在包含 explicit key-phase
  exchange。
- 2026-05-28：新增 endpoint lifecycle 的 direct caller-keyed 0-RTT
  long-packet send/receive timer refresh helper。已经持有 early-data
  packet-protection key 的 endpoint loop，现在可以绕过 long-packet coalescing，
  但仍复用同一个 route/timer owner。测试覆盖 route-selected 0-RTT STREAM
  delivery、caller-keyed 1-RTT ACK cleanup 和最终 timer disarm；
  `endpoint_recovery_timers` 的 `protected_bytes` 现在包含 direct caller-keyed
  0-RTT exchange。
- 2026-05-28：新增 endpoint lifecycle 的 caller-keyed single-space
  Initial/Handshake protected long CRYPTO datagram timer refresh helper。
  Endpoint loop 现在可以针对单个 CRYPTO packet-number-space poll datagram，
  或处理一个匹配的 protected long packet，同时仍由
  `EndpointConnectionLifecycle` 持有 route 和 recovery timer。测试覆盖
  route-selected caller-keyed Handshake CRYPTO delivery、通过 single-space
  process helper 完成 ACK cleanup，以及最终 timer disarm；
  `endpoint_recovery_timers` 的 `protected_bytes` 现在包含 caller-keyed
  Handshake CRYPTO exchange。
- 2026-05-28：通过 `EndpointConnectionLifecycle` 暴露 endpoint receive
  classification。Socket loop 现在可以用同一个 lifecycle owner 处理 active
  route delivery、connection-handle route retirement、recovery timer disarm
  和保留 inactive-CID stateless reset emission。测试覆盖 active route
  classification、会 disarm timer 的 retirement、保留 reset-token lookup 和
  reset datagram generation；`udp_close_lifecycle_loopback` 现在用
  `EndpointConnectionLifecycle` 完成 close-triggered route retirement 和
  stateless reset emission。
- 2026-05-28：新增 lifecycle-owned caller-validated route path update。
  `EndpointConnectionLifecycle.updateRoutePath()` 现在会在同一个 state owner
  上提交已验证 UDP tuple 迁移；该 owner 同时负责 route lookup、receive
  classification、protected datagram helper 和 route/timer retirement。测试覆盖
  update 前的 `path_changed` routing、新路径上已提交后的 no-change routing，
  以及 stale current-path rejection；`udp_path_validation_loopback` 现在通过
  lifecycle owner 提交 protected PATH_RESPONSE 验证后的 route update。
- 2026-05-28：新增 lifecycle-owned ECN path-state mirroring。
  `EndpointConnectionLifecycle` 现在持有 `endpoint.EcnPathPolicy`，并可在
  ACK_ECN 校验后把 connection packet-number space 的 ECN state 刷新到一个
  UDP tuple。测试覆盖 capable 与 failed ECN 结果仍隔离在不同 UDP path；
  `udp_ecn_validation_loopback` 现在通过 lifecycle owner 路由，并经该 owner
  写入 active path 的 ECN state。
- 2026-05-28：新增 route path update 后的 lifecycle-owned spin-bit reset。
  `EndpointConnectionLifecycle.updateRoutePathAndResetSpinBit()` 现在会提交
  caller-validated UDP tuple 迁移，并且只有 route update 成功后才重置
  connection 的下一次 outgoing spin bit。测试覆盖 update 前 true spin 状态、
  migrated tuple 上的 `path_changed` routing、update 后 no-change routing 和
  reset next-spin state；`udp_spin_bit_loopback` 现在从迁移后的 client 端口发送
  第二个 PING，并证明 lifecycle route update 会清除 server ACK spin bit。
- 2026-05-28：新增 lifecycle-owned replacement-CID route registration。
  `EndpointConnectionLifecycle.registerReplacementConnectionId()` 现在会提交
  NEW_CONNECTION_ID-style replacement route，应用 `retire_prior_to`，并通过
  `statelessResetTokenForDatagram()` 暴露保留的 inactive-CID reset-token
  lookup。测试覆盖旧 CID 退役后的 routing 拒绝、保留 reset-token lookup、
  active replacement routing，以及 active route 的 reset-token suppression；
  `udp_connection_ids_loopback` 现在通过 lifecycle owner 完成 protected
  NEW_CONNECTION_ID/RETIRE_CONNECTION_ID 的 route update。
- 2026-05-28：把 flow-control UDP loopback 路由到 endpoint lifecycle
  owner。`udp_flow_control_loopback` 现在通过 `EndpointConnectionLifecycle`
  注册 client/server DCID，并通过同一 owner 完成 STREAM、
  STREAM_DATA_BLOCKED、MAX_DATA/MAX_STREAM_DATA 和 final ACK 的 route
  selection，让 socket-backed credit-refresh 示例与其它 lifecycle-routed UDP
  示例保持同一个状态所有者。
- 2026-05-28：把 installed-key key-update UDP loopback 路由到 endpoint
  lifecycle owner。`udp_key_update_loopback` 现在通过
  `EndpointConnectionLifecycle` 注册 client/server DCID，并通过同一 owner
  选择 next key-phase PING 和 ACK route，让认证后的 peer key-phase
  advancement 与 ACK-gated second-update re-enable 走 lifecycle-owned
  endpoint route。
- 2026-05-28：把 loss-recovery UDP loopback 路由到 endpoint lifecycle
  owner。`udp_loss_recovery_loopback` 现在通过
  `EndpointConnectionLifecycle` 注册 client/server DCID，使用同一 owner
  完成 packet-threshold ACK delivery 的 route selection，并通过该 lifecycle
  owner service time-threshold loss timer，让 route selection 与 recovery
  timer cleanup 归属同一个 socket-backed endpoint state owner。
- 2026-05-28：把 PTO recovery UDP loopback 路由到 endpoint lifecycle
  owner。`udp_pto_recovery_loopback` 现在通过
  `EndpointConnectionLifecycle` 注册 client/server DCID，通过同一 owner 路由
  fallback PING、queued STREAM、in-flight STREAM、in-flight CRYPTO 和 final ACK
  delivery，并通过该 lifecycle owner service PTO timer，直到
  `timers_remaining=0`。
- 2026-05-28：把 STREAM retransmission UDP loopback 路由到 endpoint
  lifecycle owner。`udp_stream_retransmission_loopback` 现在通过
  `EndpointConnectionLifecycle` 注册 client/server DCID，并通过同一 owner
  路由 sparse ACK、retransmitted STREAM、重复 receive 和 final ACK cleanup，
  让 ACK 驱动的 STREAM retransmission 与 loss/PTO recovery 保持同一个
  lifecycle route owner。
- 2026-05-28：把 congestion-recovery UDP loopback 路由到 endpoint lifecycle
  owner。`udp_congestion_recovery_loopback` 现在通过
  `EndpointConnectionLifecycle` 注册 client/server DCID，并在 recovery-period
  和 persistent congestion 两个阶段通过同一 owner 路由 protected PING 与 ACK
  delivery，让 NewReno congestion 证据与 loss/PTO/STREAM recovery 保持同一个
  lifecycle route owner。
- 2026-05-28：把 caller-keyed protected UDP loopback 路由到 endpoint
  lifecycle owner。`udp_protected_loopback` 现在通过
  `EndpointConnectionLifecycle` 注册 client Initial SCID route、分类 server
  side accepted Initial、注册 accepted Original DCID/server Initial SCID route，
  并通过同一 owner 路由 protected server Initial、1-RTT PING 和 1-RTT ACK
  delivery。
- 2026-05-28：把 Retry/address-validation UDP loopback 路由到 endpoint
  lifecycle owner。`udp_retry_loopback` 现在通过
  `EndpointConnectionLifecycle` 完成 client Initial SCID route registration、
  server Initial accept classification、Retry Source CID route switching、Retry
  delivery、follow-up Initial routing 和 accepted server Initial response
  routing，同时保留地址绑定 token 校验和 replay rejection。
- 2026-05-27：修正 NewReno minimum-window clamp 边界。Congestion event
  现在会把 `ssthresh` 保持为减半后的 congestion window，只把
  `congestion_window` clamp 到 `kMinimumWindow`。测试覆盖直接 recovery state
  和 ACK 驱动的 connection loss；`loss_recovery` 现在打印
  `cwnd=2400 ssthresh=1500` 证据。
- 2026-05-27：新增 cross-space PTO probe 排队。任一 packet-number
  space 的 PTO 到期时，可控时钟 PTO hook 现在会为其他仍有 in-flight packet
  的 packet number space 排 probe，但这些 space 不会提前推进自己的 PTO
  backoff，直到自身 deadline 到期才 backoff。测试覆盖 Initial 触发的
  Handshake peer-space probe、重复排队抑制和 Handshake 延迟 backoff；
  `pto_recovery` 现在会打印 peer-space probe 证据。
- 2026-05-27：修正 RFC 9002 persistent congestion duration，避免 PTO
  exponential backoff 放大 persistent congestion 判定阈值。`Recovery` 现在把
  persistent congestion 使用的 base PTO 计算，与 probe timer 使用的 backed-off
  PTO 计算分开。测试覆盖 recovery state 的 PTO backoff、PTO backoff 后 ACK
  驱动的 persistent congestion；`loss_recovery` 现在会打印
  `persistent congestion duration=975`。
- 2026-05-27：对齐 closing 和 draining 状态的入站 datagram 处理语义。
  frame-payload 与 protected receive 入口现在会在 close timer 仍有效时直接丢弃
  入站 datagram，不解析非法字节、不生成 ACK，也不推进 peer packet-number 状态；
  close deadline 到期后的 `.closed` 仍返回 `ConnectionClosed`。测试覆盖本端
  queued close、对端 draining close、invalid-payload discard、close 后的 protected
  short-packet receive；`graceful_close` 示例现在会打印丢弃包时保留的 packet-number
  证据。
- 2026-05-27：新增 ACK_ECN ECN-CE 拥塞响应。合法的 ACK_ECN CE
  counter 增量现在会进入与 loss 共用的 NewReno recovery period，但不会把已
  ACK 的 packet 当作 lost；recovery start 之前发送 packet 的重复 CE 增量不会
  再次降低 congestion window。测试覆盖 recovery state bytes-in-flight 保持、
  连接层 CE 降窗/recovery-period 抑制、CE 降窗后的 invalid-payload rollback，
  `udp_ecn_validation_loopback` 现在会打印 `ce_count=1` 和 `ce_cwnd=6762`。
  剩余工作是完整 socket-owned protected-packet loss/PTO timer lifecycle 集成和
  剩余 NewReno 边界。
- 2026-05-27：把 socket-backed UDP loss/PTO recovery 示例接入
  endpoint-owned recovery timer。Protected-packet PTO 和 loss-time 测试现在会
  验证 protected short packet 周围的 endpoint arm/service/disarm；UDP loss 示例
  现在通过 `EndpointConnectionLifecycle` 处理 time-threshold cleanup，并打印
  `time_timers=0`；UDP PTO 示例现在通过 `EndpointConnectionLifecycle` 驱动
  PING、queued STREAM、in-flight STREAM 和 CRYPTO probe，并打印
  `timers_remaining=0`。剩余工作是完整
  socket-owned connection ownership 与 TLS-owned protected-packet timer 集成。
- 2026-05-27：新增显式 NewReno congestion-window 增长覆盖。
  Recovery 测试现在断言 slow start 会按 newly acknowledged bytes 增长
  congestion window，congestion avoidance 会使用
  `max_datagram_size * bytes_acked / congestion_window` 且至少增长 1 字节。
  连接层 ACK 测试证明 `receiveAckInSpace()` 会驱动同一路径，`loss_recovery`
  示例会打印 slow-start 和 congestion-avoidance cwnd 值。剩余工作是完整
  socket-owned protected-packet loss/PTO timer lifecycle 集成和剩余 NewReno
  边界。
- 2026-05-27：新增 endpoint-owned 多连接 recovery timer scheduling。
  `EndpointLossDetectionTimers` 会镜像每个连接的 aggregate
  `lossDetectionTimerDeadlineMillis()` 结果，选择 endpoint 中最早的 deadline，
  对选中的连接调用 `serviceLossDetectionTimer()`，再根据连接当前状态重新 arm
  或 disarm 该 handle。测试覆盖 endpoint selection、deadline 前 no-op、
  PTO-driven re-arm、ACK-driven disarm 和 loss-time service disarm。
  `endpoint_recovery_timers` 示例演示两个 caller-owned connection 之间的同一
  event-loop handoff。剩余工作是完整 socket-owned protected-packet loss/PTO
  timer lifecycle 集成和剩余 NewReno 边界。
- 2026-05-27：新增 RFC 9002 aggregate loss detection timer service。
  `lossDetectionTimerDeadlineMillis()` 现在会跨 packet number space 返回最早
  timer cause，按 RFC 9002 口径让待处理 loss-time deadline 优先于 PTO；
  若没有 loss-time，则选择最早 PTO deadline。`serviceLossDetectionTimer()`
  现在可让 endpoint/event loop 直接处理到期 aggregate timer，执行到期
  loss-time 处理或 PTO probe。测试覆盖 loss-time 优先于 PTO、deadline 前无副作用、
  due loss-time service 不额外排 PTO probe、earliest-space PTO service，以及
  selected loss-time 到期后 protected short CRYPTO retransmission。`loss_recovery`
  示例演示 aggregate loss-time service，`pto_recovery` 示例演示 aggregate
  PTO service。socket-backed `udp_loss_recovery_loopback` 和
  `udp_pto_recovery_loopback` 示例现在也通过 aggregate helper 处理到期
  loss/PTO deadline。剩余工作是 socket-owned protected-packet loss/PTO
  timer lifecycle 集成和剩余 NewReno 边界。
- 2026-05-27：新增 protected 0-RTT RESET_STREAM/STOP_SENDING retransmission 覆盖。
  protected 0-RTT 控制帧发送成功后会在 Application packet number space 的
  sent-packet 记录中保留无分配 sidecar；ACK 驱动的 packet-threshold loss 会把
  RESET_STREAM 或 STOP_SENDING 插回 pending 队列，PTO 到期时也会优先复用
  in-flight 0-RTT 控制帧，而不是直接排 PING。测试覆盖 ACK-loss requeue、新
  0-RTT packet number 的解密验证、PTO-driven 控制帧 probe、STOP_SENDING
  requeue 的 invalid-payload rollback，以及 `packet_spaces` 示例中的
  RESET_STREAM/STOP_SENDING 重传演示。剩余工作是 socket-owned
  protected-packet loss/PTO timer lifecycle 集成和剩余 NewReno 边界。
- 2026-05-27：新增 protected 0-RTT STREAM retransmission 覆盖。
  protected 0-RTT STREAM 发送成功后会在 Application packet number space 的
  sent-packet 记录中保留拥有的 STREAM sidecar；ACK 驱动的 packet-threshold loss
  会把 early data 插回 send queue，PTO 到期时也会优先克隆 in-flight 0-RTT
  STREAM data，而不是直接排 PING。测试覆盖 ACK-loss requeue、新 0-RTT packet
  number 的解密验证、PTO-driven 0-RTT STREAM probe 和 sidecar 释放边界；
  `packet_spaces` 示例现在演示 protected 0-RTT STREAM 投递和 sparse ACK 触发的
  protected 0-RTT STREAM retransmission。后续更新已覆盖 protected 0-RTT
  RESET_STREAM/STOP_SENDING retransmission；剩余工作是 socket-owned
  protected-packet loss/PTO timer lifecycle 集成和剩余 NewReno 边界。
- 2026-05-27：新增 PTO 驱动的 protected CRYPTO retransmission probe。
  `checkPtoTimeouts()` 在没有已排队 ack-eliciting 数据时，会先从到期 packet
  number space 的 sent-packet sidecar 克隆 in-flight CRYPTO，再尝试 Application
  STREAM，最后才排 PING。测试覆盖 protected Initial CRYPTO 和 protected short
  CRYPTO 的 PTO requeue、无额外 PING、PTO backoff，以及新 protected packet 中的
  CRYPTO payload；`run-pto-recovery` 现在打印 protected 1-RTT CRYPTO PTO probe，
  `run-udp-pto-recovery-loopback` 也会通过 loopback UDP 投递 CRYPTO PTO probe 并
  验证接收侧重复 CRYPTO range 幂等丢弃。
  后续更新已覆盖 protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission；
  剩余工作是 socket-owned protected-packet loss/PTO timer lifecycle 集成和剩余 NewReno 边界。
- 2026-05-26：新增 ACK 驱动的 protected CRYPTO retransmission requeue。
  protected Initial/Handshake long-packet 与 protected 1-RTT short-packet
  CRYPTO 成功 commit 后会把原 CRYPTO send-queue 项转移到 sent-packet sidecar，
  ACK 驱动 loss 会把该 CRYPTO data 插回对应 packet number space 的队列前端。
  测试覆盖 protected Initial CRYPTO 和 protected short CRYPTO 的 loss requeue、
  新 packet number retransmission 和 protected packet 解密验证；`run-crypto-stream`
  现在打印 protected 1-RTT CRYPTO loss recovery。后续更新已覆盖 protected CRYPTO
  PTO probe 和 protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission；
  剩余工作是 socket-owned protected-packet loss/PTO timer lifecycle 集成和剩余 NewReno 边界。
- 2026-05-26：新增 ACK 驱动的 frame-payload CRYPTO retransmission requeue。
  已发送的 CRYPTO packet 现在会保留拥有的 CRYPTO frame 副本；ACK 驱动的
  packet-threshold 或 time-threshold loss 会把该副本插回同一 packet number
  space 的 CRYPTO send queue 前端，并在 invalid multi-frame payload 上保留
  queue rollback。测试覆盖 Handshake-space CRYPTO loss requeue、新 packet
  number 上的 retransmission，以及 invalid-payload rollback；`run-crypto-stream`
  现在打印建模的 lost Handshake CRYPTO retransmission。后续更新已覆盖 protected
  CRYPTO PTO probe、protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING
  retransmission 和 aggregate loss/PTO timer deadline selection；剩余工作是
  socket-owned protected-packet loss/PTO timer lifecycle 集成。
- 2026-05-26：扩展 PTO probe hook，让 Application space 在没有更新的
  ack-eliciting 数据排队时复用 in-flight STREAM data。该 hook 仍优先使用
  queued data，仅在没有 STREAM retransmission 可用时 fallback 到 PING，并保持
  PTO backoff/accounting 不变。测试覆盖 frame-payload PTO STREAM retransmission；
  `run-udp-pto-recovery-loopback` 现在证明 protected UDP PTO fallback PING、
  queued STREAM probe、in-flight STREAM/CRYPTO retransmission probe、重复 receive/CRYPTO range
  丢弃和 final ACK cleanup。后续更新已覆盖 protected CRYPTO PTO probe 和
  protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission；完整
  protected-packet timer scheduling 仍待实现。
- 2026-05-26：新增 ACK 驱动的 STREAM retransmission requeue。已发送的
  STREAM packet 现在会保留已发送 frame data 的副本；ACK 驱动的
  packet-threshold 或 time-threshold loss 会把该数据重新排队到新的 packet
  number；ACK 和 invalid-payload rollback 路径会释放或恢复这些已拥有的 frame
  副本；`examples/udp_stream_retransmission_loopback.zig` 与
  `run-udp-stream-retransmission-loopback` 现在证明 lifecycle-owned protected
  UDP delivery、sparse ACK loss classification、protected STREAM
  retransmission、重复 receive range 幂等丢弃和 final ACK cleanup。后续更新已覆盖
  protected CRYPTO PTO probe 和 protected 0-RTT
  STREAM/RESET_STREAM/STOP_SENDING retransmission；完整
  protected-packet timer scheduling 仍待实现。
- 2026-05-26：新增 `examples/udp_congestion_recovery_loopback.zig` 和
  `run-udp-congestion-recovery-loopback` build step。该示例通过 loopback UDP
  经 lifecycle route owner 发送 protected short PING packet，返回触发 NewReno
  recovery-period 行为的 protected ACK frame，证明 recovery 内重复 loss 不会再次降低
  congestion window，并证明 persistent congestion 会把 congestion window 降到
  minimum window。ACK 驱动和 PTO 驱动的 1-RTT STREAM retransmission 加上 ACK
  驱动的 frame-payload/protected CRYPTO retransmission 与 protected CRYPTO PTO
  probe 和 protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission 已单独覆盖。
- 2026-05-26：新增 `examples/udp_loss_recovery_loopback.zig` 和
  `run-udp-loss-recovery-loopback` build step。该示例通过 loopback UDP 发送
  protected short PING packet，返回只确认最大 packet 的 protected ACK frame，
  现在证明 packet-threshold loss removal 与 lifecycle timer 驱动的
  time-threshold loss cleanup 都能走真实 UDP route owner。ACK 驱动和 PTO 驱动的 1-RTT STREAM
  retransmission 加上 ACK 驱动的 frame-payload/protected CRYPTO retransmission
  与 protected CRYPTO PTO probe、protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING
  retransmission 已单独覆盖。
- 2026-05-26：新增 `examples/udp_pto_recovery_loopback.zig` 和
  `run-udp-pto-recovery-loopback` build step。该示例先通过 loopback UDP 投递
  initial protected PING，但不发送 ACK，再推进 lifecycle PTO service，发送并投递
  protected PING fallback probe，随后 ACK 两个 packet。它还会在一个未 ACK 的
  STREAM packet 后排队新的 STREAM data，并证明 lifecycle service 会先把该 queued
  data 作为 protected probe 发送，最后完成 ACK cleanup。它还证明没有更新 queued
  data 时 PTO 会复用 in-flight STREAM 副本，并通过同一个 lifecycle owner 路由
  in-flight CRYPTO PTO probe。后续更新已覆盖 protected 0-RTT
  STREAM/RESET_STREAM/STOP_SENDING retransmission。
- 2026-05-26：新增 `examples/udp_ecn_validation_loopback.zig` 和
  `run-udp-ecn-validation-loopback` build step。该示例通过 loopback UDP
  发送一个建模 ECT(0) 的 protected short PING，返回 protected ACK_ECN，
  验证 client ECN state 变为 `capable`，通过 `EndpointConnectionLifecycle`
  把该状态写入当前 UDP tuple，并证明迁移后的 tuple 仍从 `unknown` 开始。该示例
  不声称真实 IP-header ECN marking。
- 2026-05-26：新增 `examples/udp_spin_bit_loopback.zig` 和
  `run-udp-spin-bit-loopback` build step。该示例在两端启用建模的单路径
  spin-bit policy，通过 loopback UDP 发送 protected short PING/ACK，验证第一轮
  保持 `spin=false`，再从迁移后的 client 端口发送第二个 true-spin PING，并证明
  lifecycle-owned route update/reset 会清除下一次 server ACK spin bit。
- 2026-05-26：新增 `examples/udp_flow_control_loopback.zig` 和
  `run-udp-flow-control-loopback` build step。该示例通过 loopback UDP 发送
  protected STREAM data 直到 receive limit，经过 endpoint lifecycle owner 上报
  STREAM_DATA_BLOCKED，把接收侧 MAX_DATA 和 MAX_STREAM_DATA credit refresh
  投递回发送端，随后恢复 STREAM 并携带 FIN，最后证明 ACK cleanup。
- 2026-05-26：新增 `examples/udp_key_update_loopback.zig` 和
  `run-udp-key-update-loopback` build step。该示例把建模的 1-RTT traffic secret
  安装进 client/server 连接，发起 installed-key update，通过 lifecycle-owned
  loopback UDP routing 发送 next key-phase PING，验证 server 在认证成功后推进
  peer key phase，再通过同一个 lifecycle owner 回 ACK，并证明 ACK gate 会重新允许
  下一次本端 key update。
- 2026-05-26：新增 `examples/udp_connection_ids_loopback.zig` 和
  `run-udp-connection-ids-loopback` build step。该示例通过 loopback UDP 投递
  protected NEW_CONNECTION_ID，更新 replacement CID 的 endpoint route，证明旧 CID
  只暴露 inactive reset token，经 active replacement CID 路由 protected
  RETIRE_CONNECTION_ID，并验证 server-side local CID retirement 与 ACK cleanup。
- 2026-05-26：新增 `examples/udp_replacement_cid_loopback.zig` 和
  `run-udp-replacement-cid-loopback` build step。该示例通过
  `EndpointConnectionLifecycle` 注册初始 route，再通过同一个 lifecycle owner 在
  loopback UDP 上安装带 `retire_prior_to` 的 replacement CID，证明 retired
  sequence route 会暴露 inactive reset token，而 active replacement CID 会抑制
  reset token；同时拒绝非法 replacement sequence metadata，并在
  active-migration-disabled policy 下拒绝 stray path。
- 2026-05-26：新增 `examples/udp_preferred_address_loopback.zig` 和
  `run-udp-preferred-address-loopback` build step。该示例通过
  `EndpointConnectionLifecycle` 在一个 loopback UDP 地址上注册当前 server
  route，并通过同一个 lifecycle owner 在第二个 server 地址上提交调用方已验证的
  preferred-address CID，证明旧 route 已退役、preferred path 可路由、同一 CID
  在 stray path 下因 active-migration-disabled 被拒绝，并验证
  preferred-address reset token 在退役后仍可查找。
- 2026-05-25：新增 `examples/udp_zero_cid_loopback.zig` 和
  `run-udp-zero-cid-loopback` build step。该示例通过
  `EndpointConnectionLifecycle` 在不同 UDP 四元组上注册两个 zero-length
  destination CID route，证明 short/long datagram 都能通过 loopback socket 按
  tuple identity 路由，随后通过 lifecycle owner 按 path 退役其中一个
  zero-CID route，并把剩余 route 更新到新的对端端口后再次验证路由。
- 2026-05-25：新增 `examples/udp_path_validation_loopback.zig` 和
  `run-udp-path-validation-loopback` build step。该示例通过 loopback UDP 把
  protected PATH_CHALLENGE 发送到新的 client 端口，server endpoint 收到
  protected PATH_RESPONSE 时先报告 `path_changed = true`，连接层验证响应后由
  调用方提交 endpoint route update，并证明后续同一路径路由不再报告 path change。
- 2026-05-25：新增 `examples/udp_retry_loopback.zig` 和
  `run-udp-retry-loopback` build step。该示例通过 loopback UDP 发送一个
  Initial-like datagram，server 签发带地址绑定 endpoint token 的 Retry，把
  Retry 经 lifecycle owner 路由回 client，将 server pending route 切换到
  Retry Source CID，校验后续 Initial 中的 token 并拒绝 replay，消费一次性
  Retry token，基于 Retry 派生的 Initial key 交换 protected Initial CRYPTO，
  并校验 Retry 相关 transport parameter。
- 2026-05-25：扩展 `examples/udp_endpoint_loopback.zig`，把真实 loopback
  UDP Version Negotiation response 交给
  `QuicConnection.processVersionNegotiationDatagram()` 处理。示例现在能在同一个
  socket-backed flow 中证明 lifecycle-owned endpoint VN response delivery 与
  client-side mutual-version selection。
- 2026-05-25：新增 `examples/udp_close_lifecycle_loopback.zig` 和
  `run-udp-close-lifecycle-loopback` build step。该示例通过 loopback UDP 投递
  protected CONNECTION_CLOSE，client/server route state 均由
  `EndpointConnectionLifecycle` 持有，并经 active endpoint CID 路由到连接；
  server 进入 draining 后按 connection handle 退役 routes，然后对同一 inactive
  CID 的后续 packet 使用保留的 token 发出 stateless reset。
- 2026-05-23：为当前 transport-core 计划新增明确的 RFC 覆盖状态表。该表把
  RFC 8999、RFC 9000、RFC 9001 和 RFC 9002 标记为 `Partial`，并列出仓库内
  的具体证据和剩余证明；RFC 9221、RFC 9368、HTTP/3、QPACK 与 multipath
  工作继续标记为第一轮核心范围外的 `Deferred`。
- 2026-05-23：新增 RFC 9369 QUIC v2 Initial secret/key/IV/header-protection
  key 派生，使用 v2 Initial salt 和 `quicv2` packet-protection label。测试覆盖
  Appendix A.1 向量，`examples/initial_keys.zig` 会基于同一个 client Initial
  DCID 输出 v1 与 v2 Initial key material。
- 2026-05-23：新增 RFC 9369 QUIC v2 long-header packet type bit 映射，覆盖
  Initial、0-RTT、Handshake 和 Retry。packet codec 现在能序列化和解析 v2
  Initial/Handshake 与 Retry wire type bits，protected long-prefix peeking 复用
  同一套版本感知映射，`examples/codec_roundtrip.zig` 会输出 v2 type bytes。
- 2026-05-23：新增 RFC 9369 QUIC v2 Retry Integrity Tag 支持。现有 Retry
  integrity helper 现在会从 transmitted Retry bytes 推断版本，并选择 RFC 9001
  或 RFC 9369 固定 key/nonce。测试覆盖两个版本的 Appendix A.4 向量，
  `examples/retry_token.zig` 会在 protection 层验证 v2 Retry packet；连接层
  Retry 流程仍保持 QUIC v1。
- 2026-05-23：为 address-validation token 增加 originating-version binding，
  覆盖 RFC 9369 的 token 隔离要求。token 现在会序列化并认证触发签发的 QUIC
  version；`validateForVersion()` 以及 endpoint/connection 的 `*ForVersion()`
  wrapper 会在 replay 状态变化前拒绝跨版本复用。测试覆盖 v1 默认行为、v2 成功、
  v1/v2 mismatch 拒绝、轮换 secret 校验、endpoint replay 边界和连接层
  NEW_TOKEN 地址验证。`examples/address_validation.zig` 现在演示一个 v2-bound
  NEW_TOKEN 会被 v1 校验拒绝，并被 v2 校验接受。
- 2026-05-23：新增 RFC 9368 `version_information` transport parameter 支持。
  类型化 transport-parameter codec 现在会序列化/解析 chosen 和 available QUIC
  versions，拒绝格式错误长度和 zero version；连接层会导出本端 version
  information，并按 endpoint role 校验 client/server 发送的对端 version
  information。`transport_error.zig` 现在暴露 RFC 9368
  `VERSION_NEGOTIATION_ERROR`。`examples/codec_roundtrip.zig` 会输出
  version-information 数量。完整 incompatible/compatible negotiation 状态和
  endpoint ownership 仍待实现。
- 2026-05-23：新增 endpoint 层 RFC 8999 Version Negotiation response
  generation，用于 unsupported long-header version。helper 会 peek
  version-independent long-header connection ID，忽略 short header、已支持版本
  和 Version Negotiation packet，并按 RFC 8999 把收到的 Source CID 回显为
  response 的 Destination CID、收到的 Destination CID 回显为 response 的 Source
  CID。`EndpointRouter.handleDatagramWithVersionNegotiation()` 现在可把单个
  datagram 分类为 route、version negotiation、stateless reset 或 drop。完整
  socket-owned accept loop 和 incompatible VN retry state 仍待实现。
- 2026-05-23：新增 client-side Version Negotiation packet handling state。
  `QuicConnection.processVersionNegotiationDatagram()` 会校验 RFC 8999
  connection-ID echo，忽略包含 client Original Version 或 CID 不匹配的 packet，
  从本地 `available_versions` 中选择 mutual version，记录本次 connection attempt
  已经响应过 VN，并通过 `versionNegotiationSelectedVersion()` 暴露结果。启动后续
  incompatible-version connection，以及校验后续 authenticated RFC 9368 server
  Version Information 仍待实现。
- 2026-05-23：新增 client 响应 Version Negotiation 后的 RFC 9368 server Version
  Information downgrade checks。后续 client connection 可携带
  `Config.version_negotiation_selected_version`；对端 transport-parameter 校验会要求
  server Chosen Version 匹配该选择，拒绝空的 server Available Versions，校验
  client 基于 server Available Versions 加 negotiated version 仍会选择同一版本，并保留
  QUIC v1 缺失 `version_information` 的例外。完整 follow-up connection 编排仍由调用方负责。
- 2026-05-22：新增 RFC 8999 Version Negotiation packet codec。它支持
  0..255 字节 connection ID，解析时忽略首字节低 7 个 unused bits，拒绝空的
  或截断的 supported-version 列表，并在测试中覆盖分配失败传播。
- 2026-05-22：新增 RFC 9000 packet number 重建，覆盖 Appendix A.3 示例向量、
  最接近窗口选择行为、QUIC 的 2^62-1 packet-number 上限，以及非法长度/值测试。
- 2026-05-22：新增 RFC 9000 packet number 编码选择 helper
  `packet.encodePacketNumberForHeader()`。它会根据待发送 packet number 与
  largest acknowledged packet 选择 1..4 字节截断 wire 长度，覆盖 Appendix A.2
  示例、尚未收到 ACK 时的边界、非法范围，并由 `examples/codec_roundtrip.zig`
  演示输出。
- 2026-05-22：新增 header-level packet number 截断/重建 API：
  `encodeLongHeaderWithPacketNumberEncoding()`、
  `encodeShortHeaderWithPacketNumberEncoding()`、
  `parseLongHeaderWithExpectedPacketNumber()`、
  `parseShortHeaderWithExpectedPacketNumber()` 与
  `parseLongPacketWithExpectedPacketNumber()`。测试覆盖 long/short header、
  long-packet envelope 解析、非法 encoding，以及 RFC 9000 Appendix A 风格的
  重建向量。
- 2026-05-23：收紧 RFC 9000 frame type 解码。`decodeFrame()` 现在按 QUIC
  varint 读取 Frame Type 字段，拒绝非最短 frame type 编码，并对未知的一字节和
  多字节 frame type 值返回 `UnsupportedFrameType`。测试覆盖非最短 PING 与未知
  类型输入。
- 2026-05-22：新增 RFC 9000 long-packet envelope codec。`LongPacket`、
  `encodeLongPacket()` 与 `parseLongPacket()` 会用 opaque payload 字节序列化
  Initial/Handshake/0-RTT 这类 long packet，派生并校验 QUIC Length 字段，
  返回已消费的 datagram 长度以支持 coalesced packet，并覆盖截断与分配失败测试。
  packet protection 仍待实现。
- 2026-05-22：新增 RFC 9000 short-packet envelope codec。`ShortPacket`、
  `encodeShortPacket()` 与 `parseShortPacket()` 会用 opaque payload 字节序列化
  1-RTT 风格 short packet。由于 short header 不携带 payload length，解析器会把
  DCID 和 packet number 之后的 datagram 剩余字节全部作为 payload。测试覆盖
  roundtrip、显式 packet-number 重建，以及 payload 分配失败传播；packet
  protection 仍待实现。
- 2026-05-22：新增 RFC 9000 short-header spin-bit 保留。`ShortHeader`
  现在携带 byte 0 的 spin bit，short-header 与 short-packet 测试覆盖
  spin bit 置位时的编码、解析和显式 packet-number 重建。
- 2026-05-23：新增 protected 1-RTT short packet 的可配置单路径运行时
  spin-bit policy。`Config.enable_spin_bit` 默认保持此前确定性的 false
  wire 行为；启用后，server 反射最新成功接收的 peer spin bit，client 对最新
  server spin bit 取反，`nextOutgoingSpinBit()` 暴露下一次 short-header
  值，`resetSpinBitForPath()` 可在后续 path 或 CID 切换后重置状态。
  `protection.peekShortPacketSpinBit()` 可在不认证 payload 的前提下读取未受
  header protection 影响的 spin bit。测试覆盖启用/禁用行为和非法 packet
  状态保持，`examples/crypto_stream.zig` 会打印建模的 spin-bit turn。
- 2026-05-22：新增类型化 RFC 9000 transport parameter codec，并通过
  `quicz.transport_parameters` 暴露。它覆盖默认值、重复参数检测、未知参数忽略、
  值校验、`preferred_address` 和分配失败测试；TLS handshake wiring 仍待完成。
- 2026-05-22：新增 RFC 9000 Retry packet codec。它按完整 datagram
  解析和序列化 Retry packet，解析时忽略 unused bits，拒绝 zero-length token
  和畸形 header，并携带 16 字节 integrity tag 供 packet-protection 层验证。
- 2026-05-22：新增类型化 RFC 9000 transport error code helper，并通过
  `quicz.transport_error` 暴露。它覆盖固定 transport error 值、
  CRYPTO_ERROR 范围检测与 TLS alert 映射；connection-close 策略和错误传播
  仍属于后续状态机工作。
- 2026-05-22：新增 `examples/codec_roundtrip.zig` 和 `zig build run-codec`。
  该示例演示 varint、short-packet envelope、coalesced long-packet envelope、
  short-header spin-bit 保留、header packet number 截断/重建、packet number
  编码、Version Negotiation、STREAM frame、transport parameter、连接层
  transport-parameter 暴露（含 TLS extension bytes、本端 ACK delay policy 和 server preferred_address）与
  transport error helper 的 roundtrip。
- 2026-05-22：新增 `QuicConnection.localTransportParameters()` 和
  `applyPeerTransportParameters()`。本端参数会暴露配置的接收限制、
  本端 `ack_delay_exponent`/`max_ack_delay`、`disable_active_migration`、配置的
  server-only `stateless_reset_token` 和配置的 server-only `preferred_address`，
  对端参数会更新发送侧 connection/stream credit、
  stream-count limit、ACK delay 策略、outbound datagram 大小，以及可观测的
  对端 active-migration policy，并保存对端 `stateless_reset_token` 与
  `preferred_address` 固定存储观测值，以供后续 endpoint reset/migration policy
  使用。测试覆盖本端导出、对端应用、非法 server-only 对端参数、preferred-address
  CID 校验、active connection ID limit 校验，以及对端参数更新 recovery 后仍保持
  本端导出的 ACK delay policy 不变。`encodeLocalTransportParameters()` 会把同一组本端
  参数序列化为 TLS QUIC extension bytes，`applyPeerTransportParameterBytes()` 会先解析
  对端 extension bytes，再复用既有语义校验后应用。测试覆盖 byte roundtrip、
  buffer 空间不足、畸形 extension 拒绝、非法 server-only extension 拒绝和失败时保持
  连接状态；实现也避免 server `preferred_address` CID 导出时借用 optional 临时副本。
  完整 TLS backend transcript 集成、read-only token exposure 之外的 stateless reset
  endpoint handling、自动 preferred-address socket migration 和 UDP migration enforcement
  仍待完成；后续 endpoint 条目覆盖调用方验证后的 preferred-address route commit。
- 2026-05-28：新增 `examples/transport_parameters.zig` 和
  `zig build run-transport-parameters`。该示例覆盖本端 TLS extension byte
  导出、对端 extension bytes 解析/应用、client 省略 server-only
  `stateless_reset_token` 与 `preferred_address`、client 存储 server
  preferred-address/reset-token policy、有效 idle-timeout 选择、对端 stream-data
  limit enforcement，以及 server 拒绝 client 发送 server-only 参数。
- 2026-05-22：新增 `QuicConnection.sendPathChallenge()`，支持 outbound
  PATH_CHALLENGE 排队、匹配 PATH_RESPONSE 校验、重复或不匹配 response 拒绝，
  并补充无效多帧 payload 的回滚测试；timeout/retry 策略仍待实现。
- 2026-05-22：在 `QuicConnection` 增加对端签发 connection ID 生命周期跟踪。
  NEW_CONNECTION_ID 现在会保存 active peer CID、拒绝 sequence number 相同但
  内容不一致的重复帧、拒绝跨 CID stateless reset token 复用、遵守配置的
  active CID limit，并通过 retire_prior_to 排队 RETIRE_CONNECTION_ID；无效多帧
  payload 会回滚部分 CID 状态。本端 CID 签发与完整 endpoint DCID routing 生命周期仍待实现。
- 2026-05-22：在 `QuicConnection` 增加本端 connection ID 签发。
  `issueConnectionId()` 会复制本端 CID 字节、分配 NEW_CONNECTION_ID sequence
  number、遵守对端 active CID limit、拒绝重复本端 CID 和 stateless reset token
  复用，并把未发送 CID 排队给
  `pollTx()`。入站 RETIRE_CONNECTION_ID 现在会把已发送本端 CID 标记为 retired，
  并在无效多帧 payload 中回滚 retirement。endpoint route-table skeleton 现在可保存
  可选 NEW_CONNECTION_ID sequence number，并可按 sequence 或 retire_prior_to
  threshold retire route，供后续 RETIRE_CONNECTION_ID wiring 使用；
  socket-backed replacement-CID route-retirement 和 caller-owned NEW/RETIRE
  证明现在位于 `examples/udp_replacement_cid_loopback.zig` 与
  `examples/udp_connection_ids_loopback.zig`，完整 connection lifecycle wiring 和
  socket 拥有的替换策略仍待实现。
- 2026-05-22：新增 `examples/flow_control.zig` 和
  `zig build run-flow-control`。该示例使用 MAX_DATA、MAX_STREAM_DATA 与
  MAX_STREAMS_BIDI 演示 connection data credit、stream data credit 与
  bidirectional stream-count 的阻塞/解锁。
- 2026-05-22：新增本端 credit 耗尽时的 outbound BLOCKED 上报。
  `sendOnStream()` 现在会在返回 `FlowControlBlocked` 前排队 DATA_BLOCKED
  或 STREAM_DATA_BLOCKED；stream-count 耗尽会排队 STREAMS_BLOCKED_BIDI/UNI。
  `pollTx()` 会在 MAX 更新后跳过过期 BLOCKED 帧。测试和
  `examples/flow_control.zig` 覆盖这些输出帧。
- 2026-05-22：新增对端 BLOCKED 可观测状态。入站 DATA_BLOCKED、
  STREAM_DATA_BLOCKED 与 STREAMS_BLOCKED_* 会更新已观察到的最高 blocked
  limit，并通过公开 getter 暴露；无效多帧 payload 会回滚这些报告。
- 2026-05-22：新增对端 BLOCKED 触发的旧 receive limit MAX 重发。
  如果入站 DATA_BLOCKED、STREAM_DATA_BLOCKED 或 STREAMS_BLOCKED_* 报告的
  limit 低于当前接收侧 credit，连接会重新排队对应的 MAX_DATA、
  MAX_STREAM_DATA 或 MAX_STREAMS_* frame。测试和 `examples/flow_control.zig`
  覆盖 connection data、per-stream data、stream-count 以及无效 payload 回滚。
- 2026-05-22：新增 `recvOnStream()` 消费字节后的接收侧 MAX_DATA 与
  MAX_STREAM_DATA 刷新。连接现在会按已消费字节数增加已通告的 connection
  与 per-stream receive credit，丢弃已排队但更小的过期 MAX limit，
  `examples/flow_control.zig` 会演示发送端因刷新后的 receive credit 解锁。
- 2026-05-23：新增通过 `Config.receive_connection_window` 和
  `Config.receive_stream_window` 配置的目标 receive-window 刷新。配置后，
  `recvOnStream()` 会把 MAX_DATA/MAX_STREAM_DATA 至少通告到已收到最高字节之后的
  目标窗口；默认行为仍保持“消费多少补多少”。测试覆盖目标 limit，且
  `examples/flow_control.zig` 现在演示从 5 字节 initial window 刷新到
  MAX_DATA=15、MAX_STREAM_DATA=17。
- 2026-05-23：复用已配置的 receive-window target 处理 peer BLOCKED
  增长。当 DATA_BLOCKED 或 STREAM_DATA_BLOCKED 报告当前或更新的 receive
  limit 时，连接会把对应 MAX_DATA 或 MAX_STREAM_DATA 增长到 `reported +
  window` 并排队重发；旧报告仍只重发当前 limit，receive-window 配置为空时
  保持原来的不增长行为。测试和 `examples/flow_control.zig` 覆盖 connection
  data、stream data、重复旧报告和无效 payload 回滚。
- 2026-05-23：新增通过 `Config.receive_stream_count_window` 配置的 peer
  STREAMS_BLOCKED stream-count 增长。当 STREAMS_BLOCKED_BIDI/UNI 报告当前或更新的
  receive stream-count limit 时，连接会按该 count window 增长对应 MAX_STREAMS
  并排队重发。配置为空时保持原来的不增长行为，旧报告仍只重发当前 limit，过大的
  count window 会在 init 阶段被拒绝。测试和 `examples/flow_control.zig`
  覆盖 BIDI/UNI 增长、重复旧报告和无效 payload 回滚。
- 2026-05-23：收紧 STREAM_DATA_BLOCKED 接收侧 stream-state 处理。该 frame
  现在会校验 stream 方向和接收 stream-count limit，拒绝 send-only 以及未打开的
  本地 bidirectional stream ID；对合法的 blocked stream，会在任何 STREAM 数据前创建
  接收状态。测试覆盖 STREAM 前接收状态创建、旧 MAX_STREAM_DATA 重发、非法方向/数量
  拒绝和回滚；`examples/flow_control.zig` 不再先造空 STREAM，而是直接演示 peer-BLOCKED
  路径。
- 2026-05-23：抑制 final size 已知后的 per-stream MAX 刷新。处于 Size Known
  或 Data Recvd 的 stream 收到 STREAM_DATA_BLOCKED 时会直接丢弃，因此连接不会在接收侧
  已知终点 offset 后继续重排或增长 MAX_STREAM_DATA。测试覆盖带 receive window 配置时的
  抑制行为，`examples/flow_control.zig` 演示不会再产生 MAX 的路径。
- 2026-05-23：当 stream 在 queued MAX_STREAM_DATA 发出前离开 Recv 时丢弃该
  per-stream MAX。STREAM FIN 或 RESET_STREAM 建立 final size 后，packetization
  会过滤该 stream 的 MAX_STREAM_DATA，同时保留 connection-level MAX_DATA。
  测试覆盖 final-size 与 reset 竞态，`examples/flow_control.zig` 演示
  final-size 抑制路径。
- 2026-05-23：当匹配的发送侧在 queued STREAM_DATA_BLOCKED 发出前 FIN 或 reset
  时丢弃该 per-stream BLOCKED。packetization 现在会在 FIN 或 `RESET_STREAM`
  后过滤该 stream 的 `STREAM_DATA_BLOCKED`，同时保留 connection-level 与
  stream-count 的 BLOCKED 行为。测试覆盖 FIN 与 reset 竞态，
  `examples/flow_control.zig` 演示 reset 抑制路径。
- 2026-05-23：允许入站 `MAX_STREAM_DATA` 与 `STOP_SENDING` 在任何 STREAM 数据前
  打开对端发起的 bidirectional stream。`MAX_STREAM_DATA` 会创建接收/发送状态，让
  回复使用对端通告的 credit；`STOP_SENDING` 会创建接收状态，只 reset 本端发送侧，
  并继续接受后续对端 STREAM 数据。测试覆盖 pre-STREAM 创建与无效 payload 回滚，
  `examples/flow_control.zig` 和 `examples/stop_sending.zig` 演示该边界。
- 2026-05-23：新增隐式低编号接收 stream 创建。入站 STREAM、RESET_STREAM、
  STREAM_DATA_BLOCKED、MAX_STREAM_DATA 或 STOP_SENDING 打开更高编号 stream 时，
  现在会创建同类型缺失的低编号 stream。测试覆盖双向/单向 STREAM 数据、
  pre-STREAM MAX_STREAM_DATA、pre-STREAM STOP_SENDING、低编号 stream idle
  读取和无效 payload 回滚；`examples/flow_control.zig` 与
  `examples/stop_sending.zig` 会打印该隐式打开边界。
- 2026-05-23：发送侧发送 FIN 后忽略入站 MAX_STREAM_DATA。Data Sent/已关闭发送
  状态不再更新发送 credit，未完成发送侧仍会应用更大的 limit。测试覆盖 FIN
  边界和 FIN 后继续发送返回 `StreamClosed` 的行为。
- 2026-05-22：新增对端发起 FIN stream 完全消费后的接收侧
  MAX_STREAMS_BIDI/UNI 刷新，包括通过 `recvOnStream()` 观察到的零长度
  FIN stream。连接会对每个完成 stream 只释放一次 receive stream-count
  credit，排队对应 MAX_STREAMS frame，并由 `examples/flow_control.zig`
  演示被 stream-count 阻塞的发送端在刷新后打开下一个 bidirectional stream。
- 2026-05-23：为对端发起的 reset stream 释放 receive stream-count credit。
  应用通过 `recvOnStream()` 观察到 reset 后，连接会排队对应 MAX_STREAMS frame。
  测试覆盖 bidirectional 与 unidirectional RESET_STREAM completion 路径，
  `examples/stream_reset.zig` 演示 reset 解锁下一个 stream。
- 2026-05-22：新增 `examples/uni_stream.zig` 和
  `zig build run-uni-stream`。该示例在当前 frame-payload 骨架中演示
  client 与 server 发起的 unidirectional stream 传递，并验证 receive-only
  的对端单向 stream 会拒绝反向发送。
- 2026-05-22：在 `QuicConnection` 增加入站乱序 STREAM range 缓存。
  非重叠 range 会在接收时计入流控，只在缺口补齐后暴露给
  `recvOnStream()`。测试覆盖缺失前缀之前先收到 FIN、重叠拒绝、
  无效 payload 回滚，以及带 pending range 时的 RESET_STREAM final-size
  记账。
- 2026-05-23：新增重复 STREAM 重传的幂等接收处理。已经存在于连续接收
  buffer 的相同字节会被忽略，连续前缀相同的数据会先裁剪再追加新的后缀
  字节，完全相同的 pending range 会被忽略且不会重复增长接收侧流控记账。
  冲突或当前无法判定的重叠仍按无效 payload 失败。测试覆盖连续重复、
  后缀裁剪、pending range 重复、冲突重叠拒绝和回滚；
  `examples/uni_stream.zig` 演示 client 发起单向 stream 的重复重传丢弃。
- 2026-05-23：新增 Data Recvd 后 late STREAM 丢弃。所有 final size 之前的
  字节都已经进入连续 buffer 后，后续仍落在该 final size 内的 STREAM frame 会被忽略，
  不再重新校验已缓存字节或增加流控记账。测试覆盖 FIN 后冲突 late data 被丢弃，同时保留
  final-size 违规错误。
- 2026-05-22：新增 `recvStreamFinalSize()` 与 `recvStreamFinished()`，
  调用方现在可以观察 STREAM FIN final size，以及所有字节被消费后的接收侧
  成功完成状态。RESET_STREAM final size 仍会暴露，但不算 FIN completion。
  测试覆盖乱序 FIN completion、reset 行为和无效 receive-only stream 方向。
- 2026-05-22：新增 `QuicConnection.resetStream()` 与
  `examples/stream_reset.zig`，并增加 `zig build run-stream-reset`。该 API
  可中止已打开的本地发送侧和已观察到的对端 bidirectional stream 回复发送侧，
  使用当前发送 offset 作为 final size 排队单个 RESET_STREAM，拒绝 receive-only
  方向和未打开 stream，并在 reset 发出后丢弃未发送的 STREAM 数据。
- 2026-05-23：让接收侧 RESET_STREAM cancellation 忽略后续仍落在已知 final
  size 内的 STREAM 数据，同时继续拒绝超出 final size 的 STREAM 数据或会改变
  final size 的 FIN。测试覆盖 reset 后 late STREAM 忽略、final-size 违规回滚，
  `examples/stream_reset.zig` 演示 reset 后忽略路径。
- 2026-05-23：让相同 final size 的 RESET_STREAM 作用于仍有缺口的 Size
  Known 接收 stream。后续 reset 会把缺失的 final size 计入 connection
  flow control 并关闭接收侧；Data Recvd stream 仍保留已完整接收的 FIN 数据可读。
  测试覆盖 FIN 缺口后的 abort 路径，`examples/stream_reset.zig` 演示该边界。
- 2026-05-22：新增 `QuicConnection.stopSending()` 与
  `examples/stop_sending.zig`，并增加 `zig build run-stop-sending`。该 API
  会为已打开的本地 bidirectional 接收侧和已观察到的对端发起接收 stream
  排队 STOP_SENDING，拒绝 send-only 和未观察到的 stream，去重本地 stop
  请求，并演示对端 RESET_STREAM 响应。
- 2026-05-28：在匹配发送侧已 reset 后抑制 ACK-loss STREAM 重传。
  `removeAckDrivenLosses()` 现在会在 `STOP_SENDING` 或本地 reset 已把发送
  stream 标记为 `reset_sent` 后跳过 lost STREAM 数据重排队，同时保留
  RESET_STREAM 发出和普通 lost STREAM 重传。测试覆盖 reset 边界，
  `examples/stop_sending.zig` 演示 reset 响应后不会留下 stray STREAM 重传。
- 2026-05-23：把本地 STOP_SENDING 发出限制到 Recv 与 Size Known 接收状态。
  final data 已经到达后，`stopSending()` 会返回 `StreamClosed`；final size 已知但仍有缺口的
  stream 仍可请求 STOP_SENDING。测试覆盖 Data Recvd 拒绝和 Size Known 成功，
  `examples/stop_sending.zig` 演示 final data 后跳过 STOP_SENDING。
- 2026-05-23：丢弃发送前已经过期的 queued STOP_SENDING。未加密、
  protected 0-RTT 与 protected 1-RTT packetization 现在会在接收侧进入
  Data Recvd 或 Reset Recvd 后过滤 STOP_SENDING。测试覆盖 final-data 与
  RESET_STREAM 竞态，`examples/stop_sending.zig` 演示 reset 竞态。
- 2026-05-22：在 `QuicConnection` 增加客户端侧 NEW_TOKEN 存储。
  client 连接会按 `Config.max_stored_new_tokens` 上限保存 opaque token
  字节，并通过 `latestNewToken()` 暴露最新 token。测试覆盖存储、容量、
  server 侧拒绝和无效 payload 回滚；认证 token 生成、过期和 endpoint
  peer-address binding 由后续 address-validation token 与 endpoint helper 覆盖。
- 2026-05-22：在 `QuicConnection` 增加本端 close 发出能力，包含
  `closeConnection()` 与 `closeApplication()`。它们会排队 CONNECTION_CLOSE
  变体，`pollTx()` 会在进入本端 closing 状态时发出 close frame；测试覆盖
  payload 编码、closing 状态 API 拒绝、非法值拒绝，以及超尺寸 close 不改变状态。
- 2026-05-22：增加显式 `ConnectionState` 模型，并通过
  `connectionState()` 与 `closeDeadlineMillis()` 暴露。本端 close 进入
  `closing`，对端 close 进入 `draining`，两者都会在当前简化的 3x PTO
  超时后进入 `closed`。测试覆盖本端 close 过期、对端 close 过期，以及无效
  payload 回滚到 `active`。后续条目覆盖地址验证发送限制与内存态 endpoint
  地址验证策略。
- 2026-05-23：新增通过 `peerClose()` 暴露的对端 close 诊断。入站
  transport 和 application CONNECTION_CLOSE frame 现在会在进入 draining 前复制
  peer error code、存在时的 transport frame type 与 reason phrase。无效多帧
  payload 会回滚该诊断状态，已记录的 peer close 在 drain timer 过期后仍可观测。
  `examples/graceful_close.zig` 会打印内存态和 protected short-packet 的
  peer close 诊断。
- 2026-05-23：新增通过 `handshakeState()` 暴露的显式 `HandshakeState`
  进度。连接从 `initial` 开始，发送或处理 Handshake-space traffic 后进入
  `handshake`，并通过 `confirmHandshake()`、server `sendHandshakeDone()` 或
  client 侧收到 HANDSHAKE_DONE 进入 `confirmed`。无效 payload 会回滚状态转换。
  测试覆盖发送侧、接收侧转换和回滚；`examples/crypto_stream.zig` 会打印建模的
  handshake state。
- 2026-05-22：新增本端 `closing` 状态下的 close frame 重发。连接会保留
  已排队的 CONNECTION_CLOSE/APPLICATION_CLOSE 到 3x PTO close deadline，
  `pollTx()` 可在其它公开 API 继续关闭的同时重发该 close frame，过期后释放保留帧。
- 2026-05-22：新增建模的 `max_idle_timeout` 处理。`Config.max_idle_timeout_ms`
  会通过本端 transport parameter 导出，对端 `max_idle_timeout` 会在参数解析后应用，
  `effectiveIdleTimeoutMillis()` 使用两端非零值中更短的一个。成功发送/接收会刷新
  `idleTimeoutDeadlineMillis()`，无效 frame payload 不会刷新，`checkIdleTimeouts()`
  会在受控 deadline 到期时关闭 active 连接。
- 2026-05-22：新增 `examples/idle_timeout.zig` 和
  `zig build run-idle-timeout`。该示例演示本端/对端 timeout 协商、活动刷新
  deadline，以及 active 到 closed 的过期转换。
- 2026-05-22：新增建模的 RFC 9000 server anti-amplification 发送限制。
  server 连接默认把 peer address 视为未验证，并暴露
  `recordPeerAddressBytesReceived()`、`antiAmplificationLimitRemaining()` 与
  `validatePeerAddress()`；`pollTx()` 与 `pollTxInSpace()` 会在验证前共享并执行
  3x 发送预算，验证后解除限制。测试覆盖未记录接收字节时阻塞发送、跨
  packet number space 消耗预算、验证后放行，以及无效 payload 回滚时保留显式预算。
- 2026-05-22：新增显式一次性 Retry token 校验 hook。
  `issueRetryToken()` 会注册 server 拥有的 opaque token，`validateRetryToken()`
  会消费一个匹配 token 并把 peer address 标记为已验证。测试覆盖空/重复 token
  拒绝、server-only、无效 token 不改状态、成功消费、解除 anti-amplification
  限制以及 token 不可复用。认证 token 生成、过期和 endpoint peer-address
  binding 由后续 address-validation token 与 endpoint helper 覆盖。
- 2026-05-22：增加显式 `PacketNumberSpace` 模型，覆盖 Initial、Handshake
  与 Application 的 frame-payload 处理。`recordPacketSentInSpace()`、
  `receiveAckInSpace()`、`queueAckForReceivedPacketInSpace()` 与
  `processDatagramInSpace()` 会按空间隔离 ACK 生成、sent-packet tracking
  和简化 recovery 状态。`FramePacketType` 与
  `processDatagramForPacketType()` 会在共享 Application packet number space
  记账的同时区分 0-RTT 与 1-RTT 的 frame-type 校验。测试覆盖 ACK/recovery
  隔离、接收侧 ACK 生成隔离，以及 0-RTT forbidden-frame 回滚。
  protected endpoint 路由、TLS 触发的自动 key discard，以及完整 endpoint-owned
  key-state 集成仍待实现。
- 2026-05-22：新增 `examples/packet_spaces.zig` 和
  `zig build run-packet-spaces`。该示例演示 Initial packet number space
  内的 ACK 不会确认 Application packet，并演示 Handshake 与 Application
  frame-payload 处理的待发送 ACK 会分开记录。
- 2026-05-22：增加 PTO 驱动的 PATH_CHALLENGE 重试与失败可观测性。
  `checkPathValidationTimeouts()` 会把超时的 outstanding challenge 放回发送队列，
  `pollTx()` 在发新 payload 前会自动执行该检查，`failedPathValidationCount()`
  暴露当前三次发送预算耗尽的 challenge 数。测试覆盖超时前无动作、重试排队、
  自动重发、重试耗尽，以及无效 payload 回滚时保留 outstanding challenge 元数据。
  endpoint path identity 绑定仍需等待 UDP routing 层。
- 2026-05-22：新增 `examples/path_validation.zig` 和
  `zig build run-path-validation`。该示例演示超时触发重试、重试后匹配
  PATH_RESPONSE 验证成功、重试预算耗尽、protected short-header
  PATH_CHALLENGE/PATH_RESPONSE，以及 protected PATH_RESPONSE 验证后的 endpoint
  lifecycle route path update。
- 2026-05-22：新增 `examples/connection_ids.zig` 和
  `zig build run-connection-ids`。该示例演示本端 NEW_CONNECTION_ID 签发、
  对端 RETIRE_CONNECTION_ID 处理，以及 lifecycle-owned endpoint replacement-CID
  route registration 和 retire_prior_to。
- 2026-05-22：在 `quicz.packet` 增加 stateless reset helper，并在连接层增加
  只读 reset 检测。`encodeStatelessReset()` 使用调用方提供的不可预测字节和
  16 字节 token 序列化 reset datagram，`matchesStatelessReset()` 以 constant-time 方式比较尾部
  token，`QuicConnection.detectStatelessReset()` 匹配 active peer-issued CID
  的 reset token 并忽略 retired CID。
- 2026-05-22：新增 `examples/stateless_reset.zig` 和
  `zig build run-stateless-reset`。该示例演示匹配对端 stateless reset token
  、拒绝错误 token，并构造 lifecycle-owned endpoint inactive-CID reset action。
- 2026-05-22：新增 `quicz.protection.deriveInitialSecrets()`，用于 RFC 9001
  QUIC v1 Initial secret 派生。它会基于第一个 client Initial DCID，通过 TLS
  HKDF-Expand-Label 派生 Initial PRK、client/server Initial secret、
  AEAD_AES_128_GCM key、IV 和 AES header-protection key。
  `aes128HeaderProtectionMask()` 与 `applyHeaderProtectionMask()` 现在覆盖
  RFC 9001 AES header-protection mask，以及可逆的 first-byte / packet-number
  mask 应用。测试覆盖 RFC 9001 Appendix A.1 与 A.2 向量、未知版本拒绝、
  非法 CID 长度拒绝、packet-number 长度校验和 short-header first-byte masking。
- 2026-05-22：新增 `packetProtectionNonce()`、`protectAes128Payload()` 与
  `unprotectAes128Payload()`，覆盖 RFC 9001 AEAD_AES_128_GCM payload
  protection，包括 packet number XOR nonce 构造和 associated-data 认证。
  测试覆盖 RFC 9001 Appendix A.3 Server Initial protected payload、解密往返、
  认证失败错误映射、非法 packet number 拒绝与 buffer 长度校验。完整
  protected-packet 组包、protected-packet 路由、真实 TLS traffic-secret
  production、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `protectLongPacketAes128()` 与
  `unprotectLongPacketAes128()`，把 long-header 序列化、AEAD_AES_128_GCM
  payload protection、认证 tag、header protection 采样、packet number
  解除 mask、packet number 重建和认证解密组合成一个 protected long-header
  packet helper。新增 `peekProtectedLongPacketInfo()`，暴露 coalesced protected
  long-packet 接收路由所需的 version、packet type 和 consumed length。测试覆盖
  RFC 9001 Appendix A.3 Server Initial final protected packet、open 往返、认证
  失败、header-protection sample 过短拒绝，以及 protected long-packet boundary
  peeking。Endpoint routing、真实 TLS traffic-secret production、key discard 和 key
  update 仍待实现。
- 2026-05-22：新增 `QuicConnection.processInitialProtectedDatagram()`。
  该连接层 bridge 会用调用方提供的 RFC 9001 Initial keys 解开一个 QUIC v1
  protected Initial long packet，校验 packet type、packet number 和单 packet
  datagram 边界，再把 plaintext frame payload 投递到 Initial packet number
  space。测试覆盖受保护 Initial CRYPTO 投递、ACK 生成、next peer packet
  number 前进，以及篡改 packet 的状态回滚。CRYPTO-only long packet 之外的
  protected transmit、TLS traffic secret production、key discard 和 key update
  仍待实现。
- 2026-05-22：新增 `QuicConnection.pollInitialProtectedDatagram()`，覆盖
  Initial CRYPTO bridge 的发送侧。它会从 Initial CRYPTO send queue 发出一个
  protected QUIC v1 Initial long packet，使用选定的 packet-number encoding，
  只在 header-protection sample 需要时补 PADDING，并把 protected datagram
  字节数计入 sent-packet、recovery、anti-amplification 和 idle-timeout 记账。
  测试覆盖 protected send 到 `processInitialProtectedDatagram()`、packet number
  前进、bytes-in-flight 记账，以及没有 Initial CRYPTO 排队时保持 idle。
  ACK-only、PING-only、coalesced protected packet、TLS traffic secret
  production、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `QuicConnection.processProtectedLongDatagramInSpace()` 与
  `pollProtectedLongCryptoDatagramInSpace()`，把 protected long-packet bridge
  从 Initial 泛化到 Initial 和 Handshake 两个 packet number space。原有
  Initial-specific wrapper 继续保留以兼容现有调用。测试覆盖 protected
  Handshake CRYPTO 发出/解密/投递、packet-number 记账、long-packet packet
  type 不匹配时的回滚，以及 Handshake token 在修改发送状态前被拒绝。
  `examples/crypto_stream.zig` 现在会用调用方提供的 keys 让 Initial 与
  Handshake CRYPTO flight 都经过 protected long packet。Endpoint Retry policy、
  1-RTT protected transmit、TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `QuicConnection.processProtectedLongDatagram()` 与
  `ProtectedLongDatagramKeys`，用于 coalesced protected long datagram 接收路由。
  该方法会先 peek 每个 long-header packet 的边界，确认所有 packet type 均可
  支持且调用方已提供对应 keys，再开始修改连接状态；随后逐个打开 Initial 或
  Handshake packet 并路由到对应 packet number space。测试覆盖一个 coalesced
  datagram 中同时包含 Initial+Handshake CRYPTO，以及缺少 Handshake key 时不会
  提前修改 Initial 状态。`examples/crypto_stream.zig` 现在演示 coalesced server
  Initial + Handshake flight。Endpoint Retry policy、1-RTT protected transmit、
  TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `QuicConnection.pollProtectedLongDatagram()`，用于
  coalesced protected long datagram transmit。该方法会从 queued CRYPTO、
  PING 加可选 ACK、或 ACK-only 状态中预构造下一个 Initial 与 Handshake
  protected packet，验证聚合后的 datagram 大小、congestion 状态与
  anti-amplification 预算，然后一起提交 packet number、sent-packet 记录、
  recovery bytes、ACK/PING 状态和 CRYPTO queue 移除。测试覆盖
  Initial+Handshake coalesced transmit 到 `processProtectedLongDatagram()`、
  缺少 Handshake key 时不修改发送状态、ACK-only packet 前进 packet number
  但不进入 bytes-in-flight，以及 PING+ACK packet 保持 ack-eliciting。
  `examples/crypto_stream.zig` 现在用 `pollProtectedLongDatagram()` 发出
  coalesced server flight 和 coalesced client Initial ACK-only + Handshake
  PING/ACK probe。Endpoint Retry policy、1-RTT protected
  transmit、TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `protectShortPacketAes128()`、
  `unprotectShortPacketAes128()`、`deinitProtectedShortPacket()` 与
  `QuicConnection.processProtectedShortDatagram()`，用于调用方提供 key 的
  1-RTT short-header packet 接收。连接层 API 要求调用方提供 destination-CID
  长度上下文，打开单个 protected short datagram，要求 packet number 匹配
  Application packet number space 的下一个期望值，然后按 1-RTT frame 规则投递
  plaintext。测试覆盖 protected short-packet roundtrip、header-protection
  sample 长度边界、PING 投递到 Application ACK 状态、packet-number 不匹配回滚，
  以及 authentication failure 不修改状态。`examples/crypto_stream.zig` 现在会在
  建模 handshake confirmation 后演示 protected 1-RTT PING receive。Retry
  routing、TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `QuicConnection.pollProtectedShortDatagram()`，用于调用方
  提供 key 的 1-RTT short-header PING/ACK transmit。该方法会保护
  Application-space PING 加可选 ACK，或 ACK-only 状态，检查 congestion 和
  anti-amplification 预算，推进 packet number，只为 ack-eliciting packet 记录
  bytes-in-flight，并清理已提交的 ACK/PING 状态。测试覆盖 protected 1-RTT
  PING 后接 ACK-only protected response，并确认 sender bytes-in-flight 被清空。
  `examples/crypto_stream.zig` 现在会在建模 handshake confirmation 后演示
  protected 1-RTT PING/ACK exchange。Endpoint Retry policy、TLS secret production、
  key discard 和 key update 仍待实现。
- 2026-05-22：扩展 `QuicConnection.pollProtectedShortDatagram()`，支持把一个
  queued Application-space STREAM frame 和可选 ACK 保护为 1-RTT short packet。
  commit path 只会在 packet-number、congestion 和 anti-amplification 检查通过后
  消费已发送的 stream frame，并在这些检查阻塞发送时释放预构造的 datagram。测试覆盖
  protected STREAM 投递、随后 protected ACK 清空 sender bytes-in-flight，以及
  anti-amplification block 不消费 queued STREAM、后续仍可发送。`examples/crypto_stream.zig` 现在会在建模
  handshake confirmation 后演示调用方 key 的 protected 1-RTT PING/ACK 与
  STREAM/ACK exchange。Endpoint Retry policy、TLS secret production、key discard 和
  key update 仍待实现。
- 2026-05-22：扩展 `QuicConnection.pollProtectedShortDatagram()`，支持把 queued
  Application-space `RESET_STREAM` 与 `STOP_SENDING` frame 加可选 ACK 保护为
  1-RTT short packet。protected path 现在沿用 `pollTx()` 的 stream-control
  优先级，只在 send commit 后消费 RESET/STOP 队列，并在 RESET_STREAM 发出后继续
  丢弃 stale STREAM data。测试覆盖 protected RESET_STREAM 投递、stale STREAM
  移除、protected ACK 清理，以及 protected STOP_SENDING 后接 protected
  RESET_STREAM response。`examples/crypto_stream.zig` 现在演示调用方 key 的
  protected 1-RTT PING/ACK、STREAM/ACK、RESET_STREAM/ACK 和
  STOP_SENDING/RESET_STREAM exchange。Endpoint Retry policy、TLS secret production、
  key discard 和 key update 仍待实现。
- 2026-05-22：扩展 `QuicConnection.pollProtectedShortDatagram()`，支持把 queued
  Application-space CRYPTO frame 和可选 ACK 保护为 1-RTT short packet。
  protected path 只会在 packet-number、congestion 和 anti-amplification
  检查通过后消费 CRYPTO 队列，沿用 STREAM transmit 的回滚边界。测试覆盖
  protected CRYPTO 投递、随后 protected ACK 清空 sender bytes-in-flight，以及
  anti-amplification block 不消费 queued CRYPTO、后续仍可发送。
  `examples/crypto_stream.zig` 现在演示调用方 key 的 protected 1-RTT
  PING/ACK、CRYPTO/ACK、STREAM/ACK、RESET_STREAM/ACK 和
  STOP_SENDING/RESET_STREAM exchange。Endpoint Retry policy、TLS secret production、
  key discard 和 key update 仍待实现。
- 2026-05-22：扩展 `QuicConnection.pollProtectedShortDatagram()`，支持把 queued
  Application-space `PATH_RESPONSE` 与 outbound `PATH_CHALLENGE` frame 和可选
  ACK 保护为 1-RTT short packet。PATH_RESPONSE 队列只在 send commit 后消费；
  PATH_CHALLENGE 也只会在 packet-number、congestion 和 anti-amplification
  检查通过后移动到 outstanding validation 状态。测试覆盖 protected
  PATH_CHALLENGE/PATH_RESPONSE/ACK 往返，以及 anti-amplification block 不消费
  pending PATH_CHALLENGE、后续仍可发送。`examples/path_validation.zig` 现在会在
  frame-payload 重试示例之外演示 protected short-header path-validation
  exchange。Endpoint Retry policy、TLS secret production、key discard 和 key update
  仍待实现。
- 2026-05-23：新增 protected path-validation 与 endpoint-routing 集成测试。
  到达新 UDP tuple 的 datagram 会先被报告为 `path_changed`；只有在匹配的
  protected PATH_RESPONSE 被处理后，调用方才提交
  `EndpointRouter.updateRoutePath()`，之后同一 tuple 会在无 path-change 报告下
  路由。`examples/path_validation.zig` 现在输出 endpoint path-change 与
  path-update 结果。自动 socket-backed path-validation ownership 仍待实现。
- 2026-05-23：扩展 `QuicConnection.pollProtectedShortDatagram()`，支持把 queued
  Application-space `RETIRE_CONNECTION_ID` frame 与未发送的本端
  `NEW_CONNECTION_ID` frame 和可选 ACK 保护为 1-RTT short packet。protected path
  只会在 packet-number、congestion 和 anti-amplification 检查通过后消费 RETIRE
  队列并把本端 connection ID 标记为 sent。测试覆盖 protected NEW/ACK、replacement
  NEW 触发 protected RETIRE+ACK、最终 ACK 清理，以及 anti-amplification block 不标记
  未发送的 NEW_CONNECTION_ID、后续仍可发送。`examples/connection_ids.zig` 现在会演示调用方
  key 的 protected 1-RTT NEW_CONNECTION_ID/RETIRE_CONNECTION_ID exchange。
  Endpoint Retry policy、TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-23：扩展 `QuicConnection.pollProtectedShortDatagram()`，支持把 queued
  Application-space MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS_BIDI/UNI、
  DATA_BLOCKED、STREAM_DATA_BLOCKED 与 STREAMS_BLOCKED_BIDI/UNI frame 和可选
  ACK 保护为 1-RTT short packet。protected path 会先丢弃过期 MAX/BLOCKED，
  并且只在 packet-number、congestion 和 anti-amplification 检查通过后消费 queued
  frame。测试覆盖 protected MAX_DATA/MAX_STREAM_DATA 投递、所有 protected
  BLOCKED 变体，以及 anti-amplification block 不消费 queued MAX/BLOCKED、后续仍可发送。
  `examples/flow_control.zig` 现在演示调用方 key 的 protected short
  STREAM_DATA_BLOCKED + MAX_DATA/MAX_STREAM_DATA exchange，并恢复 stream 发送。
  Endpoint Retry policy、TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-23：扩展 `QuicConnection.pollProtectedShortDatagram()`，支持把 queued
  Application-space CONNECTION_CLOSE 与 APPLICATION_CLOSE frame 保护为 1-RTT
  short packet。protected close path 可在本地 close pending 或 closing 期间使用，
  会推进 packet number 但不计入 bytes-in-flight，只在 packet-size 与
  anti-amplification 检查通过后进入 closing，并保留 close frame 直到 close-state
  过期以支持重发。测试覆盖 protected CONNECTION_CLOSE 投递、APPLICATION_CLOSE
  投递、重发、close timeout 过期，以及 anti-amplification block 不提交 packet number
  且保留 pending close。`examples/graceful_close.zig` 现在演示 protected close
  投递、重发和 protected application close 投递。Endpoint Retry policy、TLS secret
  production、key discard 和 key update 仍待实现。
- 2026-05-23：新增 server-only `sendHandshakeDone()` 和 `issueNewToken()`，
  并扩展 `QuicConnection.pollProtectedShortDatagram()`，支持把 queued
  HANDSHAKE_DONE 与 NEW_TOKEN frame 保护为 1-RTT short packet。protected path
  只在 packet-number、congestion 和 anti-amplification 检查通过后消费队列。
  测试覆盖 side validation、protected HANDSHAKE_DONE 投递与 ACK 清理、
  protected NEW_TOKEN 投递与 client 存储，以及 anti-amplification block 不消费这两个队列。
  `examples/address_validation.zig` 现在演示 protected HANDSHAKE_DONE confirmation
  和 protected NEW_TOKEN storage。Endpoint Retry policy、TLS secret production、
  key discard 和 key update 仍待实现。
- 2026-05-23：新增使用调用方 key 的 protected 0-RTT long-packet 路由。
  `ProtectedLongDatagramKeys.zero_rtt` 让 `processProtectedLongDatagram()`
  可把 coalesced 0-RTT packet 路由到共享的 Application packet number space，
  同时继续执行 0-RTT frame-type 限制；`pollProtectedZeroRttDatagram()` 或
  `pollProtectedLongDatagram()` 可发出一个 client-side protected 0-RTT
  STREAM、RESET_STREAM 或 STOP_SENDING packet，且不会合并 ACK 或 CRYPTO。
  测试覆盖 protected 0-RTT STREAM 投递、Initial+0-RTT coalescing 且缺少 key
  时先校验不改状态，以及 protected 0-RTT ACK 拒绝。`examples/packet_spaces.zig`
  现在演示 protected 0-RTT 共享 Application packet number space，以及 protected
  STREAM/RESET_STREAM/STOP_SENDING retransmission。真实 TLS-backed
  early-data secret ownership、acceptance policy、replay defense、endpoint Retry
  policy、key discard 和 key update 仍待实现。
- 2026-05-23：新增客户端侧 `QuicConnection.processRetryDatagram()`，用于
  Retry packet 路由。该方法会使用 Original Destination Connection ID 校验
  RFC 9001 Retry Integrity Tag，拒绝 server 侧、重复、Initial space 已丢弃
  和格式错误的 Retry datagram 且不修改状态，保存 `latestRetryToken()` 与
  `retrySourceConnectionId()`，并在后续 protected Initial packetization 收到空
  explicit token 时自动使用已保存的 Retry token。测试覆盖 token/Retry SCID
  保存、Initial 自动带 token、篡改拒绝、重复拒绝和 server 侧拒绝。
  `examples/retry_token.zig` 现在演示 connection-layer Retry 处理路径。后续条目
  覆盖内存态 endpoint 级 Retry DCID switching 和 token policy。
- 2026-05-23：新增 server 侧 `QuicConnection.issueRetryDatagram()`，用于连接层
  Retry 签发。它会生成带 RFC 9001 Retry Integrity Tag 的 QUIC v1 Retry
  datagram，注册 opaque token 供一次性校验，记录 Original Destination
  Connection ID 与 Retry Source Connection ID，并通过 `localTransportParameters()`
  导出两者。测试覆盖 Retry integrity、本端 transport-parameter 导出、client
  处理、token 消费、重复签发拒绝和无效输入回滚。`examples/retry_token.zig`
  现在使用这条连接层签发路径。后续条目覆盖内存态 endpoint 级 Retry DCID
  switching 和 token policy。
- 2026-05-23：新增 `quicz.address_validation_token` 以及
  `QuicConnection.issueAddressValidationToken()` /
  `validateAddressValidationToken()`。token 使用 HMAC-SHA256 认证，携带类型、
  originating version、签发时间、寿命和 nonce，并把 peer address 作为 MAC 输入绑定，但不会把地址字节
  序列化进 token。测试覆盖类型/地址/篡改/过期检查、分配失败、认证校验之后的一次性
  Retry token 消费、无需 Retry 一次性状态的 NEW_TOKEN 校验，以及解除
  anti-amplification。`examples/retry_token.zig` 现在使用地址绑定且带过期时间的
  Retry token，`examples/address_validation.zig` 会在后续 server 连接上校验地址绑定
  NEW_TOKEN。
- 2026-05-23：新增 `address_validation_token.ReplayFilter` 和公开 token
  指纹，用于 endpoint 拥有的 NEW_TOKEN replay 防护。该 filter 只保存 token
  MAC 指纹，要求调用方在密码学验证成功后记录 token，重复使用会返回
  `error.TokenReplay`，达到配置容量后会淘汰最旧指纹。测试覆盖重复拒绝、无效
  token 形状以及有界容量淘汰。`examples/address_validation.zig` 现在会在后续
  server 连接解除 anti-amplification 前记录已验证 NEW_TOKEN，并通过 replay
  filter 拒绝第二次使用。完整 endpoint ownership 由后续
  `AddressValidationPolicy` 覆盖；后续条目覆盖 replay-filter snapshot 导出/恢复。
- 2026-05-23：新增 `address_validation_token.validateAnySecret()`、
  `validateAnySecretAndRemember()` 与
  `QuicConnection.validateAddressValidationTokenWithSecrets()`。调用方可以按
  当前 secret、旧 secret 的顺序校验地址 token，支持 token 在 secret 轮换后到期前
  继续可用；验证后记录 helper 会在 MAC、类型、地址和寿命校验成功后写入
  `ReplayFilter`，重复使用返回 `TokenReplay`。测试覆盖旧 secret 签发 token
  由轮换 secret 集校验、空 secret 集/当前 secret only 拒绝、过期错误保留、
  replay 记录，以及连接层 NEW_TOKEN 解除 anti-amplification。
- 2026-05-23：新增 `endpoint.Udp4Address.addressValidationBinding()` 与
  `Udp4Tuple.peerAddressValidationBinding()`。endpoint policy 现在可以用远端
  IPv4 地址和 UDP port 的 6 字节二进制值作为 address-validation token 的
  `peer_address` 输入，避免文本格式差异；本地地址仍由 routing policy 处理，不写入
  peer-address token binding。测试覆盖同一远端不同本地地址可复用 token、远端端口或
  地址变化会拒绝 token。`examples/address_validation.zig` 与
  `examples/retry_token.zig` 现在都用该 endpoint binding，并演示错误远端端口不会解除
  anti-amplification 或消费 Retry token。
- 2026-05-23：新增 `endpoint.AddressValidationPolicy`，这是一个内存态 endpoint
  policy，持有当前 token secret、有界保留的 previous secrets 和有界 replay
  filter。它可以签发绑定 path 的 Retry/NEW_TOKEN，在 secret 轮换后继续接受到期前
  的已签发 token，按 current/previous secrets 校验，并只在验证成功后记录 replay
  状态。测试覆盖轮换 token 校验、错误 path 拒绝、replay 拒绝，以及超过轮换保留数后
  淘汰最旧 secret。`examples/address_validation.zig` 现在使用该 policy 处理
  NEW_TOKEN 签发/轮换/校验/replay，`examples/retry_token.zig` 先用该 policy
  签发并校验 Retry token 的 path，再交给连接层消费一次性 token。持久化 secret
  分发和 replay-filter snapshot 持久化由后续条目覆盖。
- 2026-05-23：新增 `endpoint.AddressValidationSecretSet`、
  `AddressValidationPolicy.exportSecretSet()` 和
  `AddressValidationPolicy.initWithSecretSet()`。endpoint policy 现在可以把
  active/previous token secrets 做成 snapshot，交给外部持久化或 worker 分发，
  并在另一份 policy 中恢复；恢复时会按配置的保留上限裁剪 previous secrets。
  replay-filter snapshot 持久化由下一条覆盖。测试覆盖恢复后的 token 校验和保留数裁剪，
  `examples/address_validation.zig` 现在会通过恢复后的 policy 校验已存储的
  NEW_TOKEN。
- 2026-05-23：新增 `address_validation_token.ReplayFilterSnapshot`、
  `ReplayFilter.exportSnapshot()`、`ReplayFilter.initWithSnapshot()`、
  `AddressValidationPolicy.exportReplayFilter()` 和
  `AddressValidationPolicy.initWithSecretSetAndReplayFilter()`。endpoint policy
  现在可以把已验证 token 指纹做成 snapshot 交给外部存储或 worker 分发，与 token
  secrets 一起恢复，按 `max_replay_entries` 裁剪，并在恢复后继续拒绝已使用 token。
  测试覆盖 replay snapshot 恢复、保留数裁剪，以及 policy 层跨恢复的 replay
  拒绝。`examples/address_validation.zig` 现在会输出恢复后的 replay entry 数量，
  并通过恢复后的 policy 拒绝持久化 replay。生产级共享存储、跨 worker 合并语义和
  持久化淘汰调度仍由外部负责。
- 2026-05-23：新增
  `EndpointRouter.switchInitialDestinationConnectionIdAfterRetry()`，用于
  endpoint 级 Retry DCID switching。server 发送 Retry 后，该 helper 会把
  active Initial route 的原 Destination Connection ID 替换成 Retry Source
  Connection ID，同时保留调用方持有的 connection handle 和 UDP path。它会拒绝
  duplicate target CID、过期 path 输入和 NEW_CONNECTION_ID sequence route。
  测试与 `examples/endpoint_routing.zig` 覆盖旧 DCID 退役，以及后续 Initial
  通过 Retry SCID 路由。
- 2026-05-23：新增 `EndpointRouter.commitPreferredAddressMigration()`，用于
  调用方验证 server preferred address 之后提交迁移。该 helper 会把
  preferred-address connection ID 注册到 preferred UDP tuple，保留同一个
  调用方持有的 connection handle，携带 preferred-address stateless reset token，
  并退役旧 active route。测试和 `examples/endpoint_routing.zig` 覆盖 duplicate
  target 拒绝、stale path 拒绝、zero-length preferred CID 拒绝、旧 route
  退役、active route reset-token 抑制、retired preferred-CID reset-token lookup，
  以及 active-migration-disabled policy 保留。自动 socket-backed preferred-address
  migration 仍待实现。
- 2026-05-23：`applyPeerTransportParameters()` 现在会把 server 的
  `original_destination_connection_id` 与 client 首个发出 Initial 使用的 DCID 做
  比较；使用 Retry 时，还会把 `retry_source_connection_id` 与
  `processRetryDatagram()` 保存的 Retry Source Connection ID 做比较。未处理
  Retry 的 client 会拒绝意外出现的 `retry_source_connection_id`；已处理 Retry
  的 client 会要求这两个参数存在，并在修改 peer limit 前拒绝不匹配值。测试覆盖
  无 Retry 的 `original_destination_connection_id` 缺失、不匹配和成功路径。
  `examples/retry_token.zig` 现在演示 Retry 参数缺失失败和匹配成功路径。
- 2026-05-23：protected Initial 接收现在会把对端首个 Initial Source Connection ID
  保存到 `peerInitialSourceConnectionId()`；当该 SCID 已知时，
  `applyPeerTransportParameters()` 会在修改 limit 前校验对端
  `initial_source_connection_id`。测试覆盖 protected Initial 存储、篡改 packet
  回滚、缺少参数拒绝、不匹配拒绝和匹配成功应用。`examples/crypto_stream.zig`
  现在演示缺少参数失败和匹配 `initial_source_connection_id` 成功路径。
- 2026-05-23：protected Initial 发送现在会把本端首个发出的 Initial Source
  Connection ID 保存到 `localInitialSourceConnectionId()`；当该值已知时，
  `localTransportParameters()` 会把它导出为 `initial_source_connection_id`。
  测试覆盖 idle 不导出、兼容 Initial CRYPTO transmit 和 coalesced
  Initial+Handshake transmit 路径。`examples/crypto_stream.zig` 现在使用 server
  导出的本端 transport parameter，让 client 校验 server Initial SCID。导出参数
  接入 TLS transcript 仍待实现。
- 2026-05-23：server 连接现在会从首个成功打开的 protected client Initial 记录
  Original Destination Connection ID，并通过
  `localTransportParameters().original_destination_connection_id` 导出。
  `examples/crypto_stream.zig` 现在同时演示无 Retry Original DCID 导出、client
  侧校验和 Initial SCID 校验。
- 2026-05-25：收紧 protected Initial packet 的 DCID/token 校验。首个 client
  Initial packetization 和 server 接收现在会拒绝短于 8 字节的 Destination
  Connection ID；client Initial packetization 会在 Retry 前保留已记录的 Original
  DCID、Retry 后使用 Retry Source CID、收到 server Initial 后使用 peer Initial
  SCID；server Initial packetization 与 client 接收会拒绝非空 Initial token。测试
  覆盖发送/接收回滚、server Initial 后 client DCID 选择，coalesced Initial+0-RTT
  测试也改为使用合法的 8 字节首个 client Initial DCID。
- 2026-05-25：新增 RFC 9000 Initial UDP datagram size 处理。client Initial
  datagram 和 server ack-eliciting Initial datagram 会补 PADDING 到至少 1200
  字节；coalesced Initial datagram 只补到整个 UDP datagram 达到限制；server
  ACK-only Initial datagram 保持紧凑；server 接收小于 1200 字节的 Initial UDP
  datagram 时会在 packet-number 或 CRYPTO 状态变化前拒绝。测试覆盖小 datagram
  拒绝、client/server 扩展、ACK-only 不扩展、bytes-in-flight 计数和回滚。
- 2026-05-22：新增 `retryIntegrityTag()`、`verifyRetryIntegrityTag()`、
  `encodeRetryPacketWithIntegrity()` 与 `parseRetryPacketWithIntegrity()`，
  覆盖 Retry Packet Integrity。底层 helper 会基于 Original
  Destination Connection ID 和去掉最终 tag 后的 transmitted Retry bytes
  构造 Retry pseudo-packet，再用版本对应的固定 key 执行 AEAD_AES_128_GCM
  计算 tag；集成 helper 会序列化带合法 tag 的 QUIC Retry packet，并在解析前验证。
  测试覆盖 RFC 9001 和 RFC 9369 Appendix A.4 Retry 向量、集成 encode/verify/parse、
  篡改拒绝、非法 Original DCID 长度、不支持版本拒绝和过短 Retry datagram。
  围绕已导出的 secret/replay snapshot 的生产级 endpoint token-secret 存储/分发
  仍待实现。
- 2026-05-22：新增 `examples/initial_keys.zig` 和
  `zig build run-initial-keys`。该示例会输出 RFC 9001 Appendix A 示例 DCID
  对应的 v1 Initial client/server key、IV、AES header-protection mask 和
  protected packet number，并使用派生出的 AEAD 与 header-protection key
  对一个小型 protected server Initial long-header packet 执行 seal/open。
- 2026-05-23：新增 `nextAes128TrafficSecret()` 和
  `nextAes128PacketProtectionKeys()`，用 RFC 9001 key update 的 `quic ku`
  HKDF label 派生下一组密钥材料。该 helper 会更新 traffic secret、AEAD key
  和 IV，同时保留 header protection key。测试覆盖基于 RFC 9001 Appendix A
  client Initial secret 的固定 `quic ku` 输出，并验证 header protection 在
  update 前后保持稳定。`examples/initial_keys.zig` 现在会输出下一组 traffic
  secret、key、IV 和 header-protection 保留检查。TLS 产出的 1-RTT secret
  集成仍待实现。
- 2026-05-23：新增调用方持有的 protected 1-RTT short packet key-phase
  状态处理。`peekShortPacketKeyPhaseAes128()` 会在移除 header protection 后暴露
  wire key phase，`unprotectShortPacketAes128WithKeyUpdate()` 会选择 current
  或 next packet protection key，`Aes128KeyPhaseState` 会为单个方向跟踪
  current/next key，`pollProtectedShortDatagramWithKeyPhase()` 与
  `pollProtectedShortDatagramWithKeyPhaseState()` 可用显式 key phase 发出
  short packet，`processProtectedShortDatagramWithKeyUpdate()` 与
  `processProtectedShortDatagramWithKeyPhaseState()` 可处理任一 phase 保护的
  packet。测试覆盖 next-key authentication、旧单 key API 拒绝、失败时
  packet-number 与 key-phase 状态不变，以及 key phase 翻转后成功排队
  Application-space ACK。`examples/crypto_stream.zig` 现在通过调用方持有的
  key-phase 状态演示 protected 1-RTT key-update PING。TLS 触发的自动 key-update
  confirmation 和 old-key discard 仍待实现。
- 2026-05-23：新增 connection-installed 1-RTT key update 的 ACK-gated
  发起约束。`initiateOneRttKeyUpdate()` 现在要求 modeled handshake
  confirmed，在 Application ACK 覆盖使用新 key phase 发送的 packet number
  前会拒绝第二次本端 update；如果同一 payload 后续 frame 无效，会回滚该
  ACK-confirmation 状态。测试覆盖 handshake 未 confirmed 拒绝、连续
  update 拒绝、ACK 后重新允许，以及无效 payload 回滚；
  `examples/crypto_stream.zig` 现在会先确认 modeled handshake，再演示
  installed-key key-update PING。完整 TLS-owned live endpoint key-update
  调度和 old-key discard 仍待实现。
- 2026-05-23：新增 `quic/endpoint.zig` 与内存态 `EndpointRouter`。该
  router 会把 destination connection ID 注册到调用方持有的 connection handle
  和 IPv4 UDP 四元组，按 long-header datagram 里编码的 DCID 路由，按已注册
  CID prefix 匹配 short-header datagram，并按精确 UDP tuple 路由 zero-length
  CID，拒绝重复/未知/歧义 CID，拒绝不同 CID 复用 stateless reset token，
  保存可选 NEW_CONNECTION_ID sequence number，
  支持按 CID、sequence 或 retire_prior_to threshold retire route，并允许调用方在路径验证后
  把 route 更新到新的 UDP tuple，再按 `active_migration_disabled` 报告或拒绝
  path change。它可为
  inactive 或 retired destination CID 保留 stateless reset token，在后续
  unknown-CID response 需要时暴露匹配 token，并用调用方提供的 unpredictable
  bytes 写出 stateless reset datagram，同时对 active route 抑制 reset token，
  且要求 reset datagram 小于触发 datagram。`handleDatagram()` 现在会把一个收到的
  datagram 分类为 active route 投递、stateless reset 响应或 drop。
  `switchInitialDestinationConnectionIdAfterRetry()` 会在 Retry 后把 Initial route
  替换为 Retry Source CID，`commitPreferredAddressMigration()` 会在调用方完成 path
  validation 后注册 preferred-address CID、退役旧 route，并保留 connection handle
  与 preferred stateless reset token，`registerReplacementConnectionId()` 会注册 replacement CID，校验 Retire Prior To
  不超过 replacement sequence，并把旧 sequence route 退役作为一个 endpoint policy
  操作。这个 routing skeleton 现在已有 socket-backed caller-owned replacement CID
  retirement 证明；connection 对象归属、socket-owned endpoint Retry issuance/accept
  loop、自动 path validation 和完整 path-migration policy 仍待实现。
- 2026-05-25：新增 supported-version unknown-DCID client Initial datagram 的
  endpoint 分类。`peekInitialAcceptDatagram()` 会无分配解析 version-independent
  long header 以及 Initial token/length 字段，返回后续 server accept loop 需要的
  Original DCID、client Source CID、token、version 和 UDP path metadata；short
  header、Version Negotiation packet、非 Initial long header 与 unsupported
  version 返回空结果，畸形 Initial header 在状态变更前拒绝。
  `handleDatagramWithVersionNegotiation()` 现在会在 route、Version
  Negotiation 和 stateless reset 都不适用时返回 `accept_initial`。测试覆盖
  accept metadata、route precedence、忽略的 packet class、畸形 Initial 拒绝，
  `examples/endpoint_routing.zig` 会打印新 action。
- 2026-05-25：新增
  `EndpointRouter.registerAcceptedInitialConnectionIds()`，用于推进下一步
  server accept loop。调用方接受 Initial 并创建 server connection 后，该
  helper 会把客户端 Original Destination Connection ID 注册为 Initial 重传
  route，并把 server 首个 Initial Source Connection ID 作为 sequence 0 route
  注册给后续对端 packet 使用，同时可携带 stateless reset token policy。
  duplicate/invalid route 失败时会回滚已注册的 Original DCID route，避免
  endpoint 保留半完成 accept 状态。测试与 `examples/endpoint_routing.zig`
  覆盖 accept 后 route precedence、server-SCID routing、sequence retirement、
  inactive-token lookup 和回滚。
- 2026-05-25：新增
  `EndpointRouter.registerClientInitialSourceConnectionId()`，用于 endpoint
  routing 的 client connect 侧。client 发送 Initial 前，调用方可以把 client
  Source CID 安装为 inbound route，让 server Initial 和 Version Negotiation
  response 能路由回调用方持有的连接。该 helper 也通过 tuple routing 支持
  zero-length client SCID，并保证 duplicate/too-long CID 失败不会留下部分写入。
  测试与 `examples/endpoint_routing.zig` 覆盖 server response routing、
  active migration rejection、zero-length tuple routing 和 duplicate rollback。
- 2026-05-25：新增 `EndpointRouter.retireConnectionRoutes()`，用于 endpoint
  connection lifecycle cleanup。调用方现在可以在 connection 关闭后移除该
  connection handle 的所有 active routes，同时保留 stateless reset token 给
  inactive CID 处理使用。测试与 `examples/endpoint_routing.zig` 覆盖多 route
  退役、其它连接保留、关闭后的 inactive-token lookup，以及关闭前 active-route
  token suppression。
- 2026-05-25：新增 `examples/udp_endpoint_loopback.zig` 和
  `zig build run-udp-endpoint-loopback`。示例绑定两个 loopback UDP socket，
  把 QUIC-like unsupported-version Initial 送入 endpoint Version Negotiation
  路径，把 supported Initial 送入 server accept classification 路径，注册
  accepted server Initial Source CID 与 client Initial Source CID route，且这些
  route 由 `EndpointConnectionLifecycle` 持有，并在同一组真实 UDP socket 上验证
  后续 short-header packet 路由。该示例只覆盖 endpoint routing；真实
  protected-packet/TLS socket ownership 仍待实现。
- 2026-05-25：新增 `examples/udp_protected_loopback.zig` 和
  `zig build run-udp-protected-loopback`。示例通过真实 loopback UDP socket
  发送调用方 key 的 protected client Initial 与 server Initial datagram，基于
  accepted Initial metadata 通过 lifecycle owner 注册 endpoint routes，然后在同一组
  socket 上路由并处理 protected 1-RTT PING/ACK exchange。这证明 protected packet
  可以通过 socket-backed endpoint lifecycle routing 交付；TLS-owned key
  production 仍待实现。
- 2026-05-25：新增 `examples/udp_stateless_reset_loopback.zig` 和
  `zig build run-udp-stateless-reset-loopback`。示例绑定两个 loopback UDP socket，
  注册并退役一个 CID，同时保留其 stateless reset token，把 trigger datagram
  投递到 server socket，由 `EndpointConnectionLifecycle.handleDatagram()`
  通过 lifecycle-owned route state 分类为 reset response，再把 reset
  datagram 发回客户端，并验证客户端可以匹配保留的 token。完整 TLS-owned
  connection lifecycle 集成仍待实现。
- 2026-05-22：为 `QuicConnection` 增加按 packet number space 隔离的 ECN
  validation 状态。`recordEcnPacketSentInSpace()` 可在确定性测试中记录
  已建模的 ECT(0) / ECT(1) 发送 packet；ACK_ECN counter 会按新确认的
  ECT packet 和累计发送总量校验；普通 ACK 新确认 ECT packet 时会禁用 ECN
  validation；largest acknowledged 没有增长的 reordered ACK 不会触发失败。
  无效多帧 payload 会回滚 ECN validation 状态。
- 2026-05-23：新增 `endpoint.EcnPathPolicy`，这是一个按 `Udp4Tuple`
  保存 ECN validation state 的内存态 endpoint policy。迁移后的路径会从
  `unknown` 开始，而不是继承其它路径的 capable 或 failed 状态；`mayUseEct()`
  可供后续 endpoint packetization 在 failed path 上停止设置 ECT。真实 IP-header
  ECN marking 仍待实现。
- 2026-05-22：新增 `examples/ecn_validation.zig` 和
  `zig build run-ecn-validation`。该示例演示 ECT(0) ACK_ECN 校验以及
  缺少 counter 的失败路径，以及 endpoint path-identity isolation。
- 2026-05-22：在 `QuicConnection` ACK 处理中增加简化 RFC 9002
  packet-threshold loss detection。当同一 packet number space 中的 largest
  acknowledged packet number 比某个未确认已发送 packet 至少领先 3 个
  packet number 时，该较旧 packet 会从 sent tracking 移除，并作为 lost
  上报给 recovery 状态。无效多帧 payload 会回滚 packet-threshold loss 状态。
- 2026-05-22：新增 RFC 9002 time-threshold loss delay 计算、ACK 驱动的
  time-threshold loss detection，以及确定性的 `checkLossDetectionTimeouts()`
  hook。当前骨架使用 `9/8 * max(latest_rtt, smoothed_rtt)`，并保留 1ms
  granularity 下限；它会按 packet number space 记录下一次 loss deadline，
  当较旧未确认 packet 的 send-time deadline 已经过期时，将其移除并作为 lost
  上报。无效多帧 payload 会回滚该 loss 状态。后续更新已增加 protected-packet
  sidecar retransmission 和 aggregate timer deadline selection；剩余工作是
  socket-owned protected-packet loss/PTO timer lifecycle 集成。
- 2026-05-22：新增 `examples/loss_recovery.zig` 和
  `zig build run-loss-recovery`。该示例演示 ACK 驱动的 packet-threshold 和
  time-threshold loss 移除。
- 2026-05-22：新增 RFC 9002 persistent congestion duration 与响应。当前
  frame-payload recovery 模型会记录第一次 RTT sample 对应 packet 的发送时间，
  把该 sample 之后发送的连续 lost packet 作为 persistent congestion 候选；
  当其发送时间跨度达到 persistent congestion duration 时，会把 congestion
  window 降到 minimum window，并在无效多帧 payload 中回滚该窗口变化。
  `examples/loss_recovery.zig` 已演示这个 congestion-window reduction。
- 2026-05-22：新增 NewReno-style congestion recovery period。当前
  frame-payload recovery 模型不会因为当前 recovery period 开始前发送 packet
  的 loss 再次降低 congestion window，这些 packet 的 ACK 也不会增长
  congestion window。测试覆盖 recovery-state 直接行为和连接层 ACK/loss
  处理，`examples/loss_recovery.zig` 已演示 repeated loss suppression。
- 2026-05-22：新增 `ptoDeadlineMillis()` 与 `checkPtoTimeouts()`，作为
  确定性的 packet-number-space PTO hook。当简化 PTO deadline 到期且 packet
  仍在 flight 时，该 hook 会在每个到期且未 discard 的 Initial、Handshake
  或 Application packet number space 中排队 PING probe，并按空间执行 PTO
  backoff。后续更新让 Application PTO 在 fallback 到 PING 前优先复用 queued
  或 in-flight STREAM data。
- 2026-05-23：让 `checkPtoTimeouts()` 在新增 PING probe 前优先使用已经排队的
  ack-eliciting 数据。到期 space 仍会执行 PTO backoff，但已排队的 Application
  STREAM 数据、按 space 的 CRYPTO 或其他待发送 ack-eliciting frame 可以直接作为
  probe packet。测试覆盖 queued STREAM probe selection 且不会额外排队 PING；
  后续更新已覆盖 ACK-lost 与 PTO-probed 1-RTT STREAM data、PTO-probed
  protected CRYPTO data、ACK-lost frame-payload CRYPTO data、ACK-lost
  protected CRYPTO data、protected 0-RTT STREAM data 和 protected 0-RTT
  RESET_STREAM/STOP_SENDING control data 的克隆。
- 2026-05-25：调整 packet-number-space PTO 计算，Initial 和 Handshake space
  不再计入 `max_ack_delay`，Application PTO 保持现有 peer-delay 项。
  `recovery.Recovery.ptoMsWithoutMaxAckDelay()` 暴露该 timer 基础，
  `ptoDeadlineMillis(.initial/.handshake)` 已使用它；`examples/pto_recovery.zig`
  会打印 100ms initial RTT 下 10ms/20ms 发包得到的 310ms/320ms 可控时钟 deadline。
- 2026-05-22：新增 `examples/pto_recovery.zig` 和
  `zig build run-pto-recovery`。该示例演示 deadline gating、PTO 触发的
  PING 排队、通过 `pollTx()` 发出 Application PING、queued STREAM 数据作为
  PTO probe、in-flight STREAM 数据作为 PTO probe、protected 1-RTT CRYPTO
  作为 PTO probe，以及通过 `pollTxInSpace()` 发出 Initial/Handshake PING。
- 2026-05-22：新增通过 client-side HANDSHAKE_DONE 与 `confirmHandshake()`
  建模 handshake confirmation。RTT 更新现在会忽略 Initial ACK Delay，按对端
  `ack_delay_exponent` 解码 ACK Delay，并在 handshake confirmed 后把解码后的
  ACK Delay 截到对端 `max_ack_delay`。单元测试覆盖 ACK-delay 计算、RTT 影响和
  无效 payload 回滚，`examples/loss_recovery.zig` 也演示该截断。
- 2026-05-22：新增 `discardPacketNumberSpace()`，用于建模 Initial 与
  Handshake packet number space discard。该 hook 会清理被丢弃空间的待发送
  ACK、largest-acknowledged 状态、sent-packet tracking、已排队/已接收的
  CRYPTO 状态、bytes in flight、loss deadline 与 PTO backoff，拒绝后续继续使用
  该 frame-payload 空间，并保持 Application 状态不变。`run-packet-spaces`
  已演示该清理；后续条目会把该 hook 扩展到 installed-key cleanup 和 RFC 9001
  Handshake 边界 Initial discard，剩余 TLS backend 驱动的 key lifecycle 调度仍待实现。
- 2026-05-22：为 `processDatagramInSpace()` 与
  `processDatagramForPacketType()` 增加 RFC 9000 frame-type 校验。Initial
  与 Handshake frame-payload packet type 现在只接受 RFC 9000 Table 3
  中对应 packet type 允许的 frame。0-RTT packet type 共享 Application
  packet number space 记账，但会拒绝 ACK、CRYPTO、HANDSHAKE_DONE、NEW_TOKEN、
  PATH_RESPONSE 与 RETIRE_CONNECTION_ID。RETIRE_CONNECTION_ID 的拒绝遵循
  RFC 9000 Section 12.5 对 0-RTT protocol violation 的允许处理，即使
  Table 3 将该 frame 标为 0/1-RTT packet type 可用。0-RTT 仍接受
  RESET_STREAM、STOP_SENDING 等 application frame。无效多帧 payload 会回滚
  更早状态，例如前置 PING 产生的 pending ACK 或 STREAM receive state。
  `run-packet-spaces` 会演示共享 Application packet number space 与
  0-RTT filtering。
- 2026-05-23：新增 0-RTT RETIRE_CONNECTION_ID 回归测试，证明拒绝发生在
  语义层本地 CID retirement 之前。测试会先发送一个有效本地
  NEW_CONNECTION_ID，再以 0-RTT 输入同 sequence number 的 RETIRE_CONNECTION_ID，
  并验证该包被拒绝、本地 CID 未 retired、未排队 ACK、Application receive
  packet number 未推进。
- 2026-05-22：新增按 packet number space 隔离的 CRYPTO 收发 byte stream，
  通过 `sendCryptoInSpace()`、`recvCryptoInSpace()` 与 `pollTxInSpace()`
  暴露。Initial、Handshake 与 Application CRYPTO offset、队列、接收缓冲、
  ACK 和 sent-packet tracking 现在可独立测试。`examples/crypto_stream.zig`
  与 `zig build run-crypto-stream` 已演示建模的 TLS bridge flow，其中 Initial
  flight 会经过 protected Initial transmit 与 receive bridge；真实 TLS backend、
  真实 TLS-backed early-data secret ownership、完整 endpoint datagram routing 与后续
  encryption-level key lifecycle 调度仍待实现。
- 2026-05-23：新增按 packet number space 隔离的乱序 CRYPTO 接收缓冲。
  超过连续接收 offset 的 CRYPTO frame 会先进入 pending，缺口补齐后再对
  `recvCryptoInSpace()` 可见；已经连续缓存或完全匹配 pending bytes 的相同
  重传会被忽略，冲突重叠仍作为无效 payload 失败并回滚。测试覆盖乱序投递、
  连续和 pending 重复数据、冲突拒绝以及 pending 状态回滚；
  `examples/crypto_stream.zig` 现在会在 protected-packet flow 之前演示
  out-of-order Handshake CRYPTO 重组。
- 2026-05-23：新增可插拔 `CryptoBackend` bridge 和
  `driveCryptoBackendInSpace()`。连接层现在可把本端 transport-parameter
  extension bytes 交给调用方 backend，应用 backend 返回的对端
  transport-parameter bytes，把连续的 per-packet-number-space CRYPTO 字节交给
  backend，把 backend 产出的字节通过 `sendCryptoInSpace()` 排队，返回
  `CryptoBackendProgress`，并在 backend 报告完成时标记建模 handshake
  confirmed。测试用 mock backend 覆盖本端/对端 transport-parameter byte
  handoff、非法对端 transport-parameter 在排队出站输出前拒绝、乱序
  Handshake CRYPTO 投递、分块 backend 输出排队、handshake confirmation，
  以及 zero-length scratch buffer 在消费前拒绝；`examples/crypto_stream.zig`
  现在会打印 mock backend bridge flow。
- 2026-05-23：新增通过 `CryptoBackend` 的 mock 1-RTT traffic-secret handoff
  和连接已安装 short-packet key-phase state。`OneRttTrafficSecrets` 携带本端
  与对端 write secret，`driveCryptoBackendInSpace()` 可安装派生出的
  AES-128-GCM packet-protection keys，
  `pollProtectedShortDatagramWithInstalledKeys()` /
  `processProtectedShortDatagramWithInstalledKeys()` 可在不由调用方传 key 的情况下
  收发 protected 1-RTT short packet。测试覆盖 backend secret 安装、
  installed-key PING/ACK exchange、handshake-confirmed 且 ACK-gated 的本端
  key-update 发起、对端 key phase 只在 authentication 和 frame 处理成功后推进，
  以及失败 packet 状态保持；
  `examples/crypto_stream.zig` 现在会打印 installed-key short-packet exchange
  状态。真实 TLS 1.3 transcript 处理、真实 TLS-backed early-data secret ownership、
  transport-parameter transcript ownership、key discard 和 socket-backed 本地
  1-RTT 建立仍待实现。
- 2026-05-23：新增通过 `CryptoBackend` 的 mock Handshake traffic-secret
  handoff 和 installed-key Handshake long-packet helper。
  `HandshakeTrafficSecrets` 携带本端和对端 write secret，
  `driveCryptoBackendInSpace()` 可安装派生后的 AES-128-GCM Handshake key，
  `pollProtectedHandshakeDatagramWithInstalledKeys()` /
  `processProtectedHandshakeDatagramWithInstalledKeys()` 可在不由调用方传 key
  的情况下收发 protected Handshake CRYPTO/ACK/PING packet。测试覆盖 backend
  secret 安装、tampered packet 不推进状态、Handshake CRYPTO delivery 和
  protected ACK cleanup；`examples/crypto_stream.zig` 会打印 installed-key
  Handshake exchange。真实 TLS 1.3 transcript 处理、真实 TLS-backed early-data
  secret ownership、TLS 触发的自动 key discard 调度和 socket-backed 本地
  1-RTT 建立仍待实现。
- 2026-05-23：新增 backend-confirmed no-output Handshake discard。当
  `driveCryptoBackendInSpace(.handshake, ...)` 报告 handshake confirmation，
  且本次调用没有排队 outbound Handshake CRYPTO 时，现在会丢弃 Handshake
  recovery/CRYPTO 状态和已安装 Handshake key。如果 backend 仍排队了 outbound
  Handshake CRYPTO，则保留该 space，让该 flight 先发送。测试覆盖两条分支，
  `examples/crypto_stream.zig` 会打印
  `backend_confirmed_no_output ... discarded=true ... keys_present=false`。
  真实 TLS transcript ownership 和完整 endpoint 驱动调度仍待实现。
- 2026-05-23：新增通过 `CryptoBackend` 的 mock 0-RTT traffic-secret handoff
  和 installed-key 0-RTT long-packet helper。`ZeroRttTrafficSecrets` 携带可选的
  本端与对端 early-data write secret，`driveCryptoBackendInSpace()` 可安装派生后的
  AES-128-GCM 0-RTT key，
  `pollProtectedZeroRttDatagramWithInstalledKeys()` /
  `processProtectedZeroRttDatagramWithInstalledKeys()` 可在不由调用方传 key
  的情况下收发 protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING packet。
  测试覆盖 backend secret 安装、tampered packet 不推进状态、STREAM delivery 和
  protected ACK cleanup；`examples/crypto_stream.zig` 会打印 installed-key 0-RTT
  exchange。真实 TLS-backed early-data secret ownership、TLS 0-RTT
  acceptance/replay policy、TLS 触发的自动 key discard 调度和 socket-backed 本地
  1-RTT 建立仍待实现。
- 2026-05-23：新增显式 installed-key 0-RTT accept/reject gate。安装 peer
  early-data key 后默认保持未接受；`acceptZeroRtt()` 会允许
  `processProtectedZeroRttDatagramWithInstalledKeys()`，`rejectZeroRtt()` 会在使用前丢弃
  已安装 peer key。丢弃 0-RTT key 时也会清空 accepted 标记。测试覆盖 accept
  前拒绝、accept 后接收、reject 后 key 丢弃和 discard cleanup；
  `examples/crypto_stream.zig` 现在会在 installed-key early-data exchange 前显式
  接受 server 0-RTT。完整 TLS-backed early-data ownership 和 replay policy
  仍待实现。
- 2026-05-23：新增显式 installed-key discard cleanup。丢弃 Handshake
  packet number space 时，现在会在 recovery、ACK 与 CRYPTO 状态之外同步清理连接已安装的
  Handshake packet-protection key；`discardZeroRttProtectionKeys()` 会清理已安装
  early-data key，但不丢弃共享的 Application packet number space。测试覆盖两条清理路径，
  并验证 installed-key helper 后续会拒绝使用已丢弃 key。剩余 TLS 触发的 Handshake
  discard 调度仍待实现。
- 2026-05-23：新增建模 1-RTT 边界的 0-RTT key discard。client 安装 1-RTT
  key 时会清理已安装的 0-RTT key；server 安装 1-RTT key 时仍保留 0-RTT receive
  key，只有在 protected 1-RTT short packet 完成认证且 Application-frame payload
  被接受后才清理。测试覆盖 client cleanup、server 失败保留和 server 成功 cleanup；
  `examples/crypto_stream.zig` 会在 client 安装 1-RTT 后打印 `client_zero_keys=false`，
  并在 server 接受 1-RTT 后打印 `server_zero_keys=false`。完整 TLS 0-RTT
  replay policy 和 socket-backed 本地 1-RTT 建立仍待实现。
- 2026-05-23：把 server 侧 `sendHandshakeDone()` confirmation 接入
  Handshake packet-number-space discard。server 排队 HANDSHAKE_DONE 时现在会清理
  Handshake recovery/CRYPTO 状态和已安装 Handshake key，同时保留 1-RTT
  HANDSHAKE_DONE frame 等待发送；Handshake space 丢弃后重新安装 Handshake key
  会被拒绝。单元测试覆盖该生命周期，`run-address-validation` 会打印
  `server_handshake_discarded=true`。TLS backend 驱动的自动调度仍待实现。
- 2026-05-23：把 client 侧 HANDSHAKE_DONE confirmation 接入 Handshake
  packet-number-space discard。有效 HANDSHAKE_DONE payload 现在只会在整个 payload
  被接受后，清理 Handshake recovery/CRYPTO 状态和已安装 Handshake key；无效多帧
  payload 会回滚 confirmation，并保留 Handshake space 与 key。protected
  HANDSHAKE_DONE 测试覆盖同一行为。TLS backend 驱动的自动调度仍待实现。
- 2026-05-23：把 RFC 9001 Initial key discard 边界接入现有 Handshake packet
  发送/接收路径。client 侧成功发送 Handshake packet、server 侧成功接收 Handshake
  packet 后，现在只会在 send/receive commit 成功后清理 Initial ACK/recovery/CRYPTO
  状态；发送被阻塞、输出 buffer 太小、无效 payload 和 packet 认证失败都会保留 Initial
  状态。测试覆盖 frame-payload 与 protected Handshake 路径，`examples/pto_recovery.zig`
  现在从 server 侧演示独立 Initial/Handshake PTO probe，因为 server 发送 Handshake
  packet 不会丢弃 Initial 状态。剩余 TLS backend 驱动的 key lifecycle 调度仍待实现。

## 公共接口计划

传输实现应保留当前实验性的 payload API 供聚焦测试使用，同时增加真实的
protected-packet API。

需要新增的公开或近公开模型：

- `TransportParameters`
- `TransportError`
- `ConnectionId`
- `ConnectionState`
- `HandshakeState`
- `PacketNumberSpace`
- `EcnCodepoint`
- `EcnValidationState`
- `EndpointRouter`
- `StreamState`
- `CryptoBackend` 或 `TlsBackend`

TLS 必须通过接口隔离。连接状态机不得硬编码某个 TLS 库或后端。

## Examples 计划

示例只在对应能力已实现且能通过 `build.zig` 运行时再加入。

| 示例 | 用途 | 状态 |
| --- | --- | --- |
| `echo_client` / `echo_server` | 当前内存态 frame-payload echo 基线。 | 已存在 |
| `codec_roundtrip` | 演示 varint、packet header、RFC 9369 QUIC v2 long-header type-bit 映射、short-header spin-bit 保留、long/short-packet envelope、header packet number 截断/重建、packet number 编码、RFC 8999 Version Negotiation packet codec、client-side VN selection 和 RFC 9368 downgrade-check state、frame、包含 RFC 9368 `version_information` 的 transport parameter、连接层参数暴露（含 TLS extension bytes 和 server preferred_address）与包含 `VERSION_NEGOTIATION_ERROR` 的 transport error codec。 | 已存在 |
| `transport_parameters` | 专门演示 transport parameter 用法：本端 TLS extension byte 导出、对端 byte 解析/应用、server-only 参数角色过滤、preferred-address/reset-token 存储、有效 idle timeout 与对端 stream limit enforcement。 | 已存在 |
| `crypto_stream` | 当前乱序 Handshake CRYPTO 重组、ACK 驱动的 frame-payload Handshake CRYPTO loss requeue/retransmission、ACK 驱动的 protected 1-RTT CRYPTO loss requeue/retransmission、mock `CryptoBackend` bridge 投递/输出排队/本端和对端 TP handoff/Handshake、0-RTT 与 1-RTT secret handoff/confirmation、backend-confirmed no-output Handshake discard、显式 handshake-state 可观测状态、带合法首个 client Initial DCID 和 1200 字节 Initial datagram 流程的 protected Initial 与 Handshake CRYPTO transmit/receive bridge、installed-key Handshake 与显式 accept 后的 0-RTT long-packet exchange、无 Retry Original DCID 导出/校验、通过 `localTransportParameters()` 导出本端 Initial SCID、coalesced server Initial+Handshake transmit/receive、peer Initial SCID 捕获与 `initial_source_connection_id` 校验、protected client Initial ACK-only + Handshake PING/ACK probe、建模 handshake confirmation、调用方 key 的 protected 1-RTT PING/ACK、CRYPTO/ACK、STREAM/ACK、RESET_STREAM/ACK、STOP_SENDING/RESET_STREAM exchange、ACK-gated installed-key 1-RTT key-update PING、调用方持有 key-phase 状态的 key-update PING，以及可配置 short-header spin-bit 状态。 | 已存在 |
| `initial_keys` | 基于 client Initial DCID 的 RFC 9001 QUIC v1 和 RFC 9369 QUIC v2 Initial secret/key/IV/header-protection key 派生、RFC 9001 `quic ku` key-update 派生、protected Initial long-packet seal/open 与 AES header-protection masking。 | 已存在 |
| `endpoint_routing` | 当前内存态 endpoint DCID/IPv4 UDP 四元组 routing、long-header DCID peeking、unsupported-version RFC 8999 Version Negotiation response generation、client Initial Source CID route registration、supported-version unknown-DCID Initial accept classification、accepted Initial Original DCID/server Initial SCID route registration、short-header registered-CID matching、zero-length CID tuple routing、Retry Source CID route switching、调用方验证后的 preferred-address migration commit、sequence/retire-prior-to/connection-handle route retirement、stateless reset token reuse rejection、调用方验证后的 path update、active-migration-disabled rejection、route retirement、inactive CID 的 stateless reset token lookup、用调用方提供 unpredictable bytes 构造 reset datagram，以及 route/version-negotiation/reset/drop/accept receive action classification。 | 已存在 |
| `endpoint_recovery_timers` | Endpoint-owned recovery timer scheduling：endpoint lifecycle route ownership、跨 caller-owned connection handle 选择最早 aggregate timer、deadline 前 no-op refresh、PTO service/re-arm、ACK 驱动 disarm、loss-time service、最终 timer disarm、connection-handle route retirement、protected long-header send/receive timer refresh、caller-keyed Initial/Handshake CRYPTO-space long-packet send/receive timer refresh、caller-keyed 0-RTT long-packet send/receive timer refresh、caller-keyed protected 1-RTT short-packet send/receive timer refresh、explicit key-phase/key-update short-packet timer refresh、caller-owned key-phase-state short-packet send/receive timer refresh、installed-key Handshake/0-RTT long-packet send/receive timer refresh，以及 installed-key protected 1-RTT short-packet send/receive timer refresh。 | 已存在 |
| `udp_endpoint_loopback` | Socket-backed loopback UDP endpoint routing：lifecycle-owned unsupported-version Initial 到 Version Negotiation response delivery、client-side VN selection、supported Initial accept classification、client Initial Source CID response routing、accepted server Initial Source CID registration，以及 short-header registered-CID routing。 | 已存在 |
| `udp_zero_cid_loopback` | Socket-backed loopback UDP zero-length CID：lifecycle-owned short/long datagram 按 UDP tuple identity 路由、按 path 退役 zero-CID route，以及把 route path 更新到新 tuple。 | 已存在 |
| `udp_preferred_address_loopback` | Socket-backed loopback UDP preferred-address：lifecycle-owned 调用方验证后的 preferred route commit、旧 route 退役、preferred CID 在 preferred server address 上路由、stray path 上 active-migration-disabled 拒绝，以及退役后的 reset-token lookup。 | 已存在 |
| `udp_replacement_cid_loopback` | Socket-backed loopback UDP replacement CID：lifecycle-owned NEW_CONNECTION_ID-style replacement route registration、retire_prior_to route retirement、inactive old-CID reset-token lookup、active replacement token suppression、invalid retire_prior_to rejection，以及 active-migration-disabled stray-path rejection。 | 已存在 |
| `udp_connection_ids_loopback` | Socket-backed loopback UDP connection ID：protected NEW_CONNECTION_ID delivery、lifecycle-owned endpoint replacement route update、inactive old-CID reset-token lookup、protected RETIRE_CONNECTION_ID 经 active replacement CID 路由、server-side local CID retirement 和 ACK cleanup。 | 已存在 |
| `udp_protected_loopback` | Socket-backed loopback UDP lifecycle protected packet：lifecycle-owned caller-keyed protected client Initial route registration、server accept route registration、protected server Initial response routing、routed 1-RTT PING 和 routed 1-RTT ACK。 | 已存在 |
| `udp_flow_control_loopback` | Socket-backed loopback UDP flow control：lifecycle-owned protected STREAM delivery 到 receive limit、protected STREAM_DATA_BLOCKED routing、接收侧 MAX_DATA/MAX_STREAM_DATA credit refresh delivery、带 FIN 的 resumed STREAM data，以及 final ACK cleanup。 | 已存在 |
| `udp_spin_bit_loopback` | Socket-backed loopback UDP spin bit：启用单路径 spin-bit signaling、protected short PING/ACK routing、第一轮 false spin、带 `path_changed` 的迁移端口第二轮 true-spin PING、lifecycle-owned route update/reset、reset ACK spin 和 final ACK cleanup。 | 已存在 |
| `udp_ecn_validation_loopback` | Socket-backed loopback UDP ECN validation：modeled ECT(0) protected short PING routing、protected ACK_ECN success、ACK_ECN CE 驱动的 NewReno recovery 响应、active UDP tuple 的 lifecycle-owned endpoint ECN state update，以及不声称真实 IP-header ECN marking 的 migrated-path ECN isolation。 | 已存在 |
| `udp_loss_recovery_loopback` | Socket-backed loopback UDP lifecycle loss recovery：lifecycle-owned protected short PING routing、protected ACK 驱动的 packet-threshold loss，以及 lifecycle timer 驱动的 time-threshold cleanup 和最终 timer disarm。 | 已存在 |
| `udp_congestion_recovery_loopback` | Socket-backed loopback UDP lifecycle congestion recovery：lifecycle-owned protected short PING/ACK routing、NewReno recovery-period 重复 loss 抑制，以及 persistent congestion 降到 minimum congestion window。 | 已存在 |
| `udp_pto_recovery_loopback` | Socket-backed loopback UDP lifecycle PTO recovery：lifecycle timer 驱动的 ACK-loss PTO deadline、protected PING fallback probe delivery、queued STREAM data 作为 protected PTO probe、in-flight STREAM/CRYPTO data 作为 protected PTO probe、重复 receive/CRYPTO range 丢弃、ACK cleanup 和最终 timer disarm。 | 已存在 |
| `udp_stream_retransmission_loopback` | Socket-backed loopback UDP lifecycle STREAM retransmission：lifecycle-owned sparse protected ACK routing 把 1-RTT STREAM packet 标记为 lost，sender 发出新的 protected STREAM retransmission packet，receiver 幂等丢弃重复 stream range，并由 final ACK 清空 bytes in flight。 | 已存在 |
| `udp_key_update_loopback` | Socket-backed loopback UDP key update：lifecycle-owned route selection with installed 1-RTT traffic secret、本端 key update 发起、next key-phase PING routing、认证后的 peer key-phase advancement、ACK delivery，以及 ACK-gated second-update re-enable。 | 已存在 |
| `udp_path_validation_loopback` | Socket-backed loopback UDP path-validation：protected PATH_CHALLENGE 投递到新的对端端口、PATH_RESPONSE 以 `path_changed` 路由、验证后通过 `EndpointConnectionLifecycle` 提交 route path update，以及新路径上的 confirmed routing。 | 已存在 |
| `udp_retry_loopback` | Socket-backed loopback UDP lifecycle Retry/address-validation：lifecycle-owned server Retry delivery、Retry Source CID route switching、带 replay rejection 的地址绑定 token 校验、follow-up protected Initial routing，以及 Retry CID transport-parameter validation。 | 已存在 |
| `udp_close_lifecycle_loopback` | Socket-backed loopback UDP close lifecycle：lifecycle-owned client/server route registration、protected CONNECTION_CLOSE delivery、connection-handle route retirement、保留的 inactive-CID stateless reset token lookup、reset emission 和 client token match。 | 已存在 |
| `udp_stateless_reset_loopback` | Socket-backed loopback UDP stateless reset：lifecycle-owned retired-CID route retirement、trigger datagram classification、server reset datagram 发出，以及 client token match。 | 已存在 |
| `udp_echo_client` / `udp_echo_server` | 真实 QUIC-over-UDP/TLS stream echo。 | 计划中 |
| `uni_stream` | 当前内存态单向 stream 发送/接收、方向校验、重复 STREAM 重传丢弃与 FIN completion 可观测。 | 已存在 |
| `stream_reset` | 当前本地 RESET_STREAM 发出、final-size 可观测、未发送 STREAM 丢弃行为，以及 reset 后 late STREAM 忽略。 | 已存在 |
| `stop_sending` | 当前本地 STOP_SENDING 发出、对端 RESET_STREAM 响应、Data Recvd 抑制、对端发起 bidirectional stream 的 pre-STREAM STOP_SENDING、隐式低编号接收 stream 创建，以及 reset 后 ACK-loss STREAM 抑制。 | 已存在 |
| `flow_control` | 演示 connection、stream、stream-count、接收侧 MAX、可配置目标 receive window、完成 stream 后 MAX_STREAMS credit、peer-BLOCKED MAX 重发/增长、对端发起 bidirectional stream 的 pre-STREAM MAX_STREAM_DATA 与隐式低编号接收 stream 创建、final-size MAX_STREAM_DATA 抑制、stale STREAM_DATA_BLOCKED 抑制，以及调用方 key 的 protected short MAX/BLOCKED exchange 行为。 | 已存在 |
| `graceful_close` | 当前内存态和调用方 key protected short CONNECTION_CLOSE/APPLICATION_CLOSE 收发、peer close 诊断、重发与 closing/draining 状态行为。 | 已存在 |
| `idle_timeout` | 当前 max_idle_timeout transport parameter 应用、活动 deadline 刷新和 active-to-closed 过期。 | 已存在 |
| `packet_spaces` | 当前 frame-payload Initial/Handshake/Application ACK/recovery 隔离、RFC 9001 Initial discard、会清理 ECN 状态的 Initial/Handshake discard cleanup、0-RTT packet-type filtering，以及使用调用方 key 的 protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING 投递和 ACK-loss retransmission。 | 已存在 |
| `path_validation` | 当前 frame-payload PATH_CHALLENGE 超时重试、成功、重试耗尽、调用方 key 的 protected 1-RTT PATH_CHALLENGE/PATH_RESPONSE exchange，以及 protected PATH_RESPONSE 验证后的 `EndpointConnectionLifecycle` route path update。 | 已存在 |
| `connection_ids` | 当前带 stateless-reset-token uniqueness checks 的本端 NEW_CONNECTION_ID 签发、对端 RETIRE_CONNECTION_ID 处理、带 retire_prior_to route retirement 的 lifecycle-owned endpoint replacement-CID registration，以及调用方 key 的 protected 1-RTT NEW_CONNECTION_ID/RETIRE_CONNECTION_ID exchange。 | 已存在 |
| `stateless_reset` | 当前 constant-time stateless reset token 匹配、误判拒绝和 lifecycle-owned endpoint inactive-CID reset action construction。 | 已存在 |
| `ecn_validation` | 当前 frame-payload ECT 发送建模、ACK_ECN counter 校验、ACK_ECN CE 拥塞响应和 endpoint path-identity ECN state isolation。 | 已存在 |
| `loss_recovery` | 当前 frame-payload packet-threshold loss、time-threshold loss、aggregate loss-time timer service、NewReno underutilized-cwnd suppression、slow-start/congestion-avoidance 字节计数与 batched-ACK 增长、recovery period、新拥塞事件后一次性 STREAM recovery probe、minimum-window ssthresh clamp、不受 PTO backoff 放大的 persistent congestion 与 ACK-delay 处理。 | 已存在 |
| `pto_recovery` | 当前 frame-payload Initial/Handshake/Application PTO hook，包含 aggregate PTO timer service、Initial/Handshake RTT ACK-delay suppression、Initial/Handshake max_ack_delay suppression、已 armed 的单个 PTO probe 绕过 congestion window、PING fallback probe、其他 in-flight packet number space 的 cross-space peer probe、queued STREAM data probe selection、in-flight STREAM retransmission probe selection 和 protected 1-RTT CRYPTO PTO probe selection。 | 已存在 |
| `address_validation` | 当前建模的 server anti-amplification 预算、显式 peer-address validation、protected HANDSHAKE_DONE/NEW_TOKEN 投递、server 侧 HANDSHAKE_DONE 触发的 Handshake discard、endpoint peer-address binding、`AddressValidationPolicy` NEW_TOKEN 签发/轮换/originating-version binding/secret-set 和 replay-filter 导出恢复/校验/replay 拒绝，以及 address-validation unblocking。 | 已存在 |
| `retry_token` | 当前 v1/v2 Retry packet integrity-tag encode/verify/parse、server 侧 Retry datagram 签发、客户端侧 Retry datagram 处理、Retry CID transport-parameter 校验/导出、endpoint peer-address binding、`AddressValidationPolicy` Retry token 签发/path 校验、一次性 Retry token 消费与 address-validation unblocking。 | 已存在 |
| `interop_client` | 手动或可选外部服务互通检查。 | 计划中 |

## 验证规则

- 每个 transport 行为改动都必须能映射到本文的标准领域。
- 新增 codec 或状态机行为必须覆盖正常路径、边界值、畸形输入和回滚测试。
- TLS、packet protection、timer、Retry、stateless reset、ECN validation、
  loss recovery、congestion control、endpoint routing 等高风险逻辑必须使用
  确定性输入测试。
- 本地基线验证命令固定为：

```bash
zig build test --summary all
zig build
zig build run-server
zig build run-client
zig build run-codec
zig build run-transport-parameters
zig build run-flow-control
zig build run-uni-stream
zig build run-stream-reset
zig build run-stop-sending
zig build run-crypto-stream
zig build run-graceful-close
zig build run-idle-timeout
zig build run-packet-spaces
zig build run-ecn-validation
zig build run-loss-recovery
zig build run-pto-recovery
zig build run-endpoint-recovery-timers
zig build run-path-validation
zig build run-address-validation
zig build run-retry-token
zig build run-connection-ids
zig build run-stateless-reset
zig build run-initial-keys
zig build run-endpoint-routing
zig build run-udp-endpoint-loopback
zig build run-udp-zero-cid-loopback
zig build run-udp-preferred-address-loopback
zig build run-udp-replacement-cid-loopback
zig build run-udp-connection-ids-loopback
zig build run-udp-protected-loopback
zig build run-udp-flow-control-loopback
zig build run-udp-spin-bit-loopback
zig build run-udp-ecn-validation-loopback
zig build run-udp-loss-recovery-loopback
zig build run-udp-congestion-recovery-loopback
zig build run-udp-pto-recovery-loopback
zig build run-udp-key-update-loopback
zig build run-udp-path-validation-loopback
zig build run-udp-retry-loopback
zig build run-udp-close-lifecycle-loopback
zig build run-udp-stateless-reset-loopback
```

- 外部互通检查在本地 protected UDP client/server 路径存在前可以是可选项；
  失败时必须记录对端实现、对端版本和最小可复现 trace。

## 里程碑

1. 标准矩阵和文档保持最新。
2. RFC 8999 / 9000 的 packet、frame、transport parameter 和 error-code 支持完成。
3. 连接状态机、packet number spaces 和 protected datagram API 可用。
4. RFC 9001 TLS 集成与 packet protection 可建立本地 1-RTT。
5. RFC 9000 transport 行为覆盖 stream、flow control、connection ID、Retry/token、path validation、close/reset。
6. RFC 9002 recovery 与 congestion control 通过可控时钟测试。
7. 分层 examples 和至少一个外部互通路径可用。
