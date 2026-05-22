# QUIC 传输协议实现任务

`quicz` 的目标是在 Zig 中实现 IETF QUIC 传输协议。本文把该目标拆成
可逐步实现、可验证、可回滚的任务。

## 范围

第一轮实现范围限定为 QUIC 传输核心：

- RFC 8999：QUIC 版本无关属性
- RFC 9000：QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001：Using TLS to Secure QUIC
- RFC 9002：QUIC Loss Detection and Congestion Control

暂缓的标准和扩展：

- QUIC v2，RFC 9369
- Compatible Version Negotiation，RFC 9368
- QUIC DATAGRAM，RFC 9221
- HTTP/3 和 QPACK
- Multipath 以及其他 QUIC WG 进行中的草案

当前代码仍是实验性的 frame-payload 传输骨架。`pollTx` 和
`processDatagram` 只流转未加密 QUIC frame payload 字节；连接层现在有一个
窄范围的 Initial CRYPTO protected long-packet send/receive bridge，但尚不能
完整生成或消费 QUIC-over-UDP packet。

## 任务矩阵

| 领域 | 当前状态 | 目标结果 | 验证方式 |
| --- | --- | --- | --- |
| 标准追踪 | 部分完成 | 将每个核心 RFC 领域标记为 done、partial、missing 或 deferred。 | Markdown review 加 `zig build test`。 |
| RFC 8999 / 9000 packet codec | 部分完成 | 完成版本无关 packet、version negotiation、Retry、long/short header、packet number 与 transport error 值。 | roundtrip、边界值、截断、非法值、分配失败测试。 |
| RFC 9000 frame codec | frame 集合已覆盖 + 部分 packet-type 校验 | 覆盖所有 RFC 9000 transport frame，并统一严格校验和错误映射。 | 每类 frame 的合法、截断、非法、未知输入编解码测试。 |
| Transport parameters | 部分连接层暴露 | 增加 transport parameter 的类型化解析、序列化、校验和握手暴露。 | roundtrip、重复/非法参数、连接层应用/导出和默认值测试。 |
| 连接状态机 | 部分 close-state + idle timeout | 建模 Initial、Handshake、0-RTT、1-RTT、idle timeout、closing、draining、closed 状态。 | 现有测试覆盖 close/drain 迁移、close 过期、idle 过期和非法 packet 回滚；后续 protected-packet 测试覆盖 key-state 迁移。 |
| Packet number spaces | 部分 frame-payload ACK/recovery + CRYPTO 隔离 + Initial protected CRYPTO send/receive bridge + frame-type filtering + discard cleanup | 维护独立 Initial、Handshake、Application packet number space，并在后续把 protected packet 路由到匹配空间且遵守真实 TLS key discard 规则。 | 现有 ACK/recovery、CRYPTO 隔离、Initial protected send/receive、forbidden-frame 与 discard 测试证明空间隔离和清理；后续 protected coalesced 测试证明完整路由正确。 |
| 真实 datagram API | Initial protected CRYPTO send/receive bridge + protected long-packet helper | 在当前 frame-payload 骨架之上增加受保护 QUIC datagram 收发 API。 | 现有 helper 测试覆盖一个受保护 Initial packet；连接层测试覆盖 protected Initial CRYPTO 发出/解密/投递；后续本地 client/server loopback 必须可交换受保护 packet。 |
| TLS 集成 | 已有 CRYPTO bridge hook，尚无 TLS backend | 使用可插拔 TLS 后端接口，由 CRYPTO frame 驱动握手。 | 握手 transcript 测试和本地 1-RTT 建立测试。 |
| Packet protection | 部分 v1 Initial keys + AES-GCM payload/header protection + protected long-packet helper | 实现 Initial、Handshake、0-RTT、1-RTT 密钥派生、header protection、AEAD、key discard 和 key update。 | RFC 向量或固定向量测试 key derivation 与 packet protection。 |
| Streams | 部分接收重组 + FIN completion + 本地 reset/stop 可观测 | 在当前内存态重组骨架之外继续完成 stream 状态机、FIN/reset 规则和读写行为。 | 双向、单向、FIN、reset、STOP_SENDING、乱序、重叠、回滚、final-size 测试。 |
| Flow control | 部分 receive MAX 与 stream-count 刷新 + BLOCKED 可观测/重发 | 完成自适应 MAX/BLOCKED 策略响应。 | connection、stream 与 stream-count 级 blocked/unblocked 测试。 |
| Connection IDs | 部分本端/对端生命周期，尚无 DCID routing | 增加 DCID routing 集成和 endpoint 级替换策略。 | 现有测试覆盖本端 NEW_CONNECTION_ID 签发、对端 RETIRE 处理、对端签发 NEW_CONNECTION_ID 生命周期、重复、limit 和回滚；后续 endpoint 测试覆盖 routing。 |
| Tokens and Retry | 部分 codec + Retry Integrity Tag + NEW_TOKEN 存储 + 建模的 server anti-amplification 发送限制 + 显式一次性 Retry token 校验 | 实现加密 token 生成、过期、endpoint 地址绑定和完整地址验证策略。 | 现有测试覆盖 Retry packet codec、RFC 9001 Retry Integrity Tag、NEW_TOKEN 存储、建模的 3x anti-amplification 限制和一次性 Retry token 消费；后续 endpoint 测试覆盖加密/地址绑定 token 策略。 |
| Path validation | 部分 timeout/retry，尚无 endpoint identity | 在真实 UDP routing 存在后绑定 endpoint path 身份。 | 现有测试覆盖匹配、重复、不匹配、回滚、超时重试和重试耗尽；后续 endpoint 测试覆盖 path identity。 |
| Stateless reset | 部分 helper + 连接层检测 | 等 UDP routing 存在后增加 endpoint 级 unknown-CID stateless reset 发出。 | 现有测试覆盖 reset token 命中、误判拒绝、短 datagram 拒绝和 retired token 忽略；后续 endpoint 测试覆盖 unknown-CID 发出。 |
| ECN validation | 部分 frame-payload ACK_ECN 校验 | 等 UDP routing 存在后把 ECN validation 绑定到真实 network path 和 IP ECN 标记。 | 现有测试覆盖 ECT(0) 成功、缺少 ACK_ECN 失败、counter 不足、counter 总量超过已发送 ECT packet、reordered ACK 处理和回滚；后续 endpoint 测试覆盖 path identity 与 IP-header marking。 |
| RFC 9002 recovery | 部分 ACK delay + packet/time-threshold loss + NewReno recovery period + persistent congestion + packet-space PTO PING hook | 实现完整 protected-packet PTO/loss timer 调度和剩余 NewReno 细节。 | 现有测试覆盖 ACK、ACK delay exponent scaling、handshake confirmed 后 max_ack_delay 截断、packet-threshold loss、ACK 驱动和 timeout 驱动的 time-threshold loss、NewReno recovery-period 抑制、persistent congestion、回滚、packet-number-space PTO PING 排队/backoff 和拥塞窗口算术；后续可控时钟测试覆盖 protected-packet PTO data retransmission。 |
| UDP endpoint routing | 未实现 | 按 DCID、本地/远端地址四元组和连接状态路由 UDP datagram。 | endpoint 的 client connect、server accept、迁移拒绝、未知 CID 测试。 |
| 互通 | 未实现 | 至少与一个外部 QUIC 实现验证最小 echo flow。 | 手动或可选 CI 脚本记录对端实现和版本。 |

## 进展记录

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
  spin bit 置位时的编码、解析和显式 packet-number 重建。运行时 spin-bit
  启用和更新策略仍属于后续 connection/path-state 工作。
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
  编码、Version Negotiation、STREAM frame、transport parameter、连接层 transport-parameter 暴露与
  transport error helper 的 roundtrip。
- 2026-05-22：新增 `QuicConnection.localTransportParameters()` 和
  `applyPeerTransportParameters()`。本端参数会暴露配置的接收限制、
  `disable_active_migration` 和配置的 server-only `stateless_reset_token`，
  对端参数会更新发送侧 connection/stream credit、
  stream-count limit、ACK delay 策略、outbound datagram 大小，以及可观测的
  对端 active-migration policy，并保存对端 `stateless_reset_token` transport
  parameter 以供后续 endpoint reset detection 使用。测试覆盖本端导出、对端应用、
  非法 server-only 对端参数，以及 active connection ID limit 校验；TLS
  transcript 集成、read-only token exposure 之外的 stateless reset endpoint handling 和 UDP migration
  enforcement 仍待完成。
- 2026-05-22：新增 `QuicConnection.sendPathChallenge()`，支持 outbound
  PATH_CHALLENGE 排队、匹配 PATH_RESPONSE 校验、重复或不匹配 response 拒绝，
  并补充无效多帧 payload 的回滚测试；timeout/retry 策略仍待实现。
- 2026-05-22：在 `QuicConnection` 增加对端签发 connection ID 生命周期跟踪。
  NEW_CONNECTION_ID 现在会保存 active peer CID、拒绝 sequence number 相同但
  内容不一致的重复帧、遵守配置的 active CID limit，并通过 retire_prior_to
  排队 RETIRE_CONNECTION_ID；无效多帧 payload 会回滚部分 CID 状态。本端 CID
  签发与 DCID routing 仍待实现。
- 2026-05-22：在 `QuicConnection` 增加本端 connection ID 签发。
  `issueConnectionId()` 会复制本端 CID 字节、分配 NEW_CONNECTION_ID sequence
  number、遵守对端 active CID limit、拒绝重复本端 CID，并把未发送 CID 排队给
  `pollTx()`。入站 RETIRE_CONNECTION_ID 现在会把已发送本端 CID 标记为 retired，
  并在无效多帧 payload 中回滚 retirement。DCID routing 和 endpoint 级替换策略仍待实现。
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
  自适应 receive-window autotuning 仍待实现。
- 2026-05-22：新增对端发起 FIN stream 完全消费后的接收侧
  MAX_STREAMS_BIDI/UNI 刷新，包括通过 `recvOnStream()` 观察到的零长度
  FIN stream。连接会对每个完成 stream 只释放一次 receive stream-count
  credit，排队对应 MAX_STREAMS frame，并由 `examples/flow_control.zig`
  演示被 stream-count 阻塞的发送端在刷新后打开下一个 bidirectional stream。
- 2026-05-22：新增 `examples/uni_stream.zig` 和
  `zig build run-uni-stream`。该示例在当前 frame-payload 骨架中演示
  client 与 server 发起的 unidirectional stream 传递，并验证 receive-only
  的对端单向 stream 会拒绝反向发送。
- 2026-05-22：在 `QuicConnection` 增加入站乱序 STREAM range 缓存。
  非重叠 range 会在接收时计入流控，只在缺口补齐后暴露给
  `recvOnStream()`。测试覆盖缺失前缀之前先收到 FIN、重叠拒绝、
  无效 payload 回滚，以及带 pending range 时的 RESET_STREAM final-size
  记账。
- 2026-05-22：新增 `recvStreamFinalSize()` 与 `recvStreamFinished()`，
  调用方现在可以观察 STREAM FIN final size，以及所有字节被消费后的接收侧
  成功完成状态。RESET_STREAM final size 仍会暴露，但不算 FIN completion。
  测试覆盖乱序 FIN completion、reset 行为和无效 receive-only stream 方向。
- 2026-05-22：新增 `QuicConnection.resetStream()` 与
  `examples/stream_reset.zig`，并增加 `zig build run-stream-reset`。该 API
  可中止已打开的本地发送侧和已观察到的对端 bidirectional stream 回复发送侧，
  使用当前发送 offset 作为 final size 排队单个 RESET_STREAM，拒绝 receive-only
  方向和未打开 stream，并在 reset 发出后丢弃未发送的 STREAM 数据。
- 2026-05-22：新增 `QuicConnection.stopSending()` 与
  `examples/stop_sending.zig`，并增加 `zig build run-stop-sending`。该 API
  会为已打开的本地 bidirectional 接收侧和已观察到的对端发起接收 stream
  排队 STOP_SENDING，拒绝 send-only 和未观察到的 stream，去重本地 stop
  请求，并演示对端 RESET_STREAM 响应。
- 2026-05-22：在 `QuicConnection` 增加客户端侧 NEW_TOKEN 存储。
  client 连接会按 `Config.max_stored_new_tokens` 上限保存 opaque token
  字节，并通过 `latestNewToken()` 暴露最新 token。测试覆盖存储、容量、
  server 侧拒绝和无效 payload 回滚；加密 token 生成和 endpoint 地址绑定策略仍待实现。
- 2026-05-22：在 `QuicConnection` 增加本端 close 发出能力，包含
  `closeConnection()` 与 `closeApplication()`。它们会排队 CONNECTION_CLOSE
  变体，`pollTx()` 会在进入本端 closing 状态时发出 close frame；测试覆盖
  payload 编码、closing 状态 API 拒绝、非法值拒绝，以及超尺寸 close 不改变状态。
- 2026-05-22：增加显式 `ConnectionState` 模型，并通过
  `connectionState()` 与 `closeDeadlineMillis()` 暴露。本端 close 进入
  `closing`，对端 close 进入 `draining`，两者都会在当前简化的 3x PTO
  超时后进入 `closed`。测试覆盖本端 close 过期、对端 close 过期，以及无效
  payload 回滚到 `active`。加密 token 和完整 endpoint 地址验证策略仍待实现。
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
  限制以及 token 不可复用。加密 token 生成、过期和 UDP endpoint 地址绑定仍待实现。
- 2026-05-22：增加显式 `PacketNumberSpace` 模型，覆盖 Initial、Handshake
  与 Application 的 frame-payload 处理。`recordPacketSentInSpace()`、
  `receiveAckInSpace()`、`queueAckForReceivedPacketInSpace()` 与
  `processDatagramInSpace()` 会按空间隔离 ACK 生成、sent-packet tracking
  和简化 recovery 状态。`FramePacketType` 与
  `processDatagramForPacketType()` 会在共享 Application packet number space
  记账的同时区分 0-RTT 与 1-RTT 的 frame-type 校验。测试覆盖 ACK/recovery
  隔离、接收侧 ACK 生成隔离，以及 0-RTT forbidden-frame 回滚。
  protected-packet 路由、TLS key discard，以及 0-RTT/1-RTT key-state 集成仍待实现。
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
  PATH_RESPONSE 验证成功，以及重试预算耗尽。
- 2026-05-22：新增 `examples/connection_ids.zig` 和
  `zig build run-connection-ids`。该示例演示本端 NEW_CONNECTION_ID 签发、
  对端 RETIRE_CONNECTION_ID 处理，以及带 retire_prior_to 的替换 CID 签发。
- 2026-05-22：在 `quicz.packet` 增加 stateless reset helper，并在连接层增加
  只读 reset 检测。`encodeStatelessReset()` 使用调用方提供的不可预测字节和
  16 字节 token 序列化 reset datagram，`matchesStatelessReset()` 比较尾部
  token，`QuicConnection.detectStatelessReset()` 匹配 active peer-issued CID
  的 reset token 并忽略 retired CID。endpoint 级 unknown-CID 发出仍等待 UDP routing。
- 2026-05-22：新增 `examples/stateless_reset.zig` 和
  `zig build run-stateless-reset`。该示例演示匹配对端 stateless reset token
  以及拒绝错误 token。
- 2026-05-22：新增 `quicz.protection.deriveInitialSecrets()`，用于 RFC 9001
  QUIC v1 Initial secret 派生。它会基于第一个 client Initial DCID，通过 TLS
  HKDF-Expand-Label 派生 Initial PRK、client/server Initial secret、
  AEAD_AES_128_GCM key、IV 和 AES header-protection key。
  `aes128HeaderProtectionMask()` 与 `applyHeaderProtectionMask()` 现在覆盖
  RFC 9001 AES header-protection mask，以及可逆的 first-byte / packet-number
  mask 应用。测试覆盖 RFC 9001 Appendix A.1 与 A.2 向量、QUIC v2 在暂缓范围内的拒绝、
  非法 CID 长度拒绝、packet-number 长度校验和 short-header first-byte masking。
- 2026-05-22：新增 `packetProtectionNonce()`、`protectAes128Payload()` 与
  `unprotectAes128Payload()`，覆盖 RFC 9001 AEAD_AES_128_GCM payload
  protection，包括 packet number XOR nonce 构造和 associated-data 认证。
  测试覆盖 RFC 9001 Appendix A.3 Server Initial protected payload、解密往返、
  认证失败错误映射、非法 packet number 拒绝与 buffer 长度校验。完整
  protected-packet 组包、protected-packet 路由、Handshake/1-RTT traffic
  secret、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `protectLongPacketAes128()` 与
  `unprotectLongPacketAes128()`，把 long-header 序列化、AEAD_AES_128_GCM
  payload protection、认证 tag、header protection 采样、packet number
  解除 mask、packet number 重建和认证解密组合成一个 protected long-header
  packet helper。测试覆盖 RFC 9001 Appendix A.3 Server Initial final protected
  packet、open 往返、认证失败和 header-protection sample 过短拒绝。Endpoint
  routing、coalesced-packet receive loop、Handshake/1-RTT traffic secret、key
  discard 和 key update 仍待实现。
- 2026-05-22：新增 `QuicConnection.processInitialProtectedDatagram()`。
  该连接层 bridge 会用调用方提供的 RFC 9001 Initial keys 解开一个 QUIC v1
  protected Initial long packet，校验 packet type、packet number 和单 packet
  datagram 边界，再把 plaintext frame payload 投递到 Initial packet number
  space。测试覆盖受保护 Initial CRYPTO 投递、ACK 生成、next peer packet
  number 前进，以及篡改 packet 的状态回滚。发送侧 protected packetization、
  coalesced receive loop、Handshake/1-RTT traffic secret、key discard 和 key
  update 仍待实现。
- 2026-05-22：新增 `QuicConnection.pollInitialProtectedDatagram()`，覆盖
  Initial CRYPTO bridge 的发送侧。它会从 Initial CRYPTO send queue 发出一个
  protected QUIC v1 Initial long packet，使用选定的 packet-number encoding，
  只在 header-protection sample 需要时补 PADDING，并把 protected datagram
  字节数计入 sent-packet、recovery、anti-amplification 和 idle-timeout 记账。
  测试覆盖 protected send 到 `processInitialProtectedDatagram()`、packet number
  前进、bytes-in-flight 记账，以及没有 Initial CRYPTO 排队时保持 idle。
  ACK-only、PING-only、coalesced protected packet、Handshake/1-RTT traffic
  secret、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `retryIntegrityTag()`、`verifyRetryIntegrityTag()`、
  `encodeRetryPacketWithIntegrity()` 与 `parseRetryPacketWithIntegrity()`，
  覆盖 RFC 9001 Retry Packet Integrity。底层 helper 会基于 Original
  Destination Connection ID 和去掉最终 tag 后的 transmitted Retry bytes
  构造 Retry pseudo-packet，再用固定 key 的 AEAD_AES_128_GCM 计算 tag；
  集成 helper 会序列化带合法 tag 的 QUIC v1 Retry packet，并在解析前验证。
  测试覆盖 RFC 9001 Appendix A.4 Retry 向量、集成 encode/verify/parse、
  篡改拒绝、非法 Original DCID 长度、不支持版本拒绝和过短 Retry datagram。
  加密 Retry token 生成、过期和地址绑定仍属于后续 endpoint policy。
- 2026-05-22：新增 `examples/initial_keys.zig` 和
  `zig build run-initial-keys`。该示例会输出 RFC 9001 Appendix A 示例 DCID
  对应的 v1 Initial client/server key、IV、AES header-protection mask 和
  protected packet number，并使用派生出的 AEAD 与 header-protection key
  对一个小型 protected server Initial long-header packet 执行 seal/open。
- 2026-05-22：为 `QuicConnection` 增加按 packet number space 隔离的 ECN
  validation 状态。`recordEcnPacketSentInSpace()` 可在确定性测试中记录
  已建模的 ECT(0) / ECT(1) 发送 packet；ACK_ECN counter 会按新确认的
  ECT packet 和累计发送总量校验；普通 ACK 新确认 ECT packet 时会禁用 ECN
  validation；largest acknowledged 没有增长的 reordered ACK 不会触发失败。
  无效多帧 payload 会回滚 ECN validation 状态。
- 2026-05-22：新增 `examples/ecn_validation.zig` 和
  `zig build run-ecn-validation`。该示例演示 ECT(0) ACK_ECN 校验以及
  缺少 counter 的失败路径。
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
  上报。无效多帧 payload 会回滚该 loss 状态。完整 protected-packet PTO/loss
  timer 调度仍待实现。
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
  backoff。protected-packet PTO data retransmission 仍待实现。
- 2026-05-22：新增 `examples/pto_recovery.zig` 和
  `zig build run-pto-recovery`。该示例演示 deadline gating、PTO 触发的
  PING 排队、通过 `pollTx()` 发出 Application PING，以及通过
  `pollTxInSpace()` 发出 Initial/Handshake PING。
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
  已演示该清理；真实 TLS key discard wiring 仍待实现。
- 2026-05-22：为 `processDatagramInSpace()` 与
  `processDatagramForPacketType()` 增加 RFC 9000 frame-type 校验。Initial
  与 Handshake frame-payload packet type 现在只接受 RFC 9000 Table 3
  中对应 packet type 允许的 frame。0-RTT packet type 共享 Application
  packet number space 记账，但会拒绝 ACK、CRYPTO、HANDSHAKE_DONE、NEW_TOKEN、
  PATH_RESPONSE 与 RETIRE_CONNECTION_ID，同时接受 RESET_STREAM、STOP_SENDING
  等 application frame。无效多帧 payload 会回滚更早状态，例如前置 PING
  产生的 pending ACK 或 STREAM receive state。`run-packet-spaces`
  会演示共享 Application packet number space 与 0-RTT filtering。
- 2026-05-22：新增按 packet number space 隔离的 CRYPTO 收发 byte stream，
  通过 `sendCryptoInSpace()`、`recvCryptoInSpace()` 与 `pollTxInSpace()`
  暴露。Initial、Handshake 与 Application CRYPTO offset、队列、接收缓冲、
  ACK 和 sent-packet tracking 现在可独立测试。`examples/crypto_stream.zig`
  与 `zig build run-crypto-stream` 已演示建模的 TLS bridge flow，其中 Initial
  flight 会经过 protected Initial transmit 与 receive bridge；真实 TLS backend、
  protected coalescing 和后续 encryption level 仍待实现。

## 公共接口计划

传输实现应保留当前实验性的 payload API 供聚焦测试使用，同时增加真实的
protected-packet API。

需要新增的公开或近公开模型：

- `TransportParameters`
- `TransportError`
- `ConnectionId`
- `ConnectionState`
- `PacketNumberSpace`
- `EcnCodepoint`
- `EcnValidationState`
- `StreamState`
- `CryptoBackend` 或 `TlsBackend`
- 用于 UDP 四元组和 DCID 路由的 endpoint/datagram 层

TLS 必须通过接口隔离。连接状态机不得硬编码某个 TLS 库或后端。

## Examples 计划

示例只在对应能力已实现且能通过 `build.zig` 运行时再加入。

| 示例 | 用途 | 状态 |
| --- | --- | --- |
| `echo_client` / `echo_server` | 当前内存态 frame-payload echo 基线。 | 已存在 |
| `codec_roundtrip` | 演示 varint、packet header、short-header spin-bit 保留、long/short-packet envelope、header packet number 截断/重建、packet number 编码、frame、transport parameter、连接层参数暴露与 transport error codec。 | 已存在 |
| `crypto_stream` | 当前 protected Initial CRYPTO transmit/receive bridge、frame-payload Handshake CRYPTO flow 与建模 handshake confirmation。 | 已存在 |
| `initial_keys` | 基于 client Initial DCID 的 RFC 9001 QUIC v1 Initial secret/key/IV/header-protection key 派生、protected Initial long-packet seal/open 与 AES header-protection masking。 | 已存在 |
| `udp_echo_client` / `udp_echo_server` | 真实 QUIC-over-UDP/TLS stream echo。 | 计划中 |
| `uni_stream` | 当前内存态单向 stream 发送/接收、方向校验与 FIN completion 可观测。 | 已存在 |
| `stream_reset` | 当前本地 RESET_STREAM 发出、final-size 可观测和未发送 STREAM 丢弃行为。 | 已存在 |
| `stop_sending` | 当前本地 STOP_SENDING 发出和对端 RESET_STREAM 响应。 | 已存在 |
| `flow_control` | 演示 connection、stream、stream-count、接收侧 MAX、完成 stream 后 MAX_STREAMS credit，以及 peer-BLOCKED MAX 重发行为。 | 已存在 |
| `graceful_close` | 当前内存态 CONNECTION_CLOSE/APPLICATION_CLOSE 收发、重发与 closing/draining 状态行为。 | 已存在 |
| `idle_timeout` | 当前 max_idle_timeout transport parameter 应用、活动 deadline 刷新和 active-to-closed 过期。 | 已存在 |
| `packet_spaces` | 当前 frame-payload Initial/Handshake/Application ACK/recovery 隔离、Initial/Handshake discard cleanup 与 0-RTT packet-type filtering。 | 已存在 |
| `path_validation` | 当前 frame-payload PATH_CHALLENGE 超时重试、成功和重试耗尽。 | 已存在 |
| `connection_ids` | 当前本端 NEW_CONNECTION_ID 签发和对端 RETIRE_CONNECTION_ID 处理。 | 已存在 |
| `stateless_reset` | 当前 stateless reset token 匹配和误判拒绝 helper。 | 已存在 |
| `ecn_validation` | 当前 frame-payload ECT 发送建模与 ACK_ECN counter 校验。 | 已存在 |
| `loss_recovery` | 当前 frame-payload packet-threshold loss、time-threshold loss、NewReno recovery period、persistent congestion 与 ACK-delay 处理。 | 已存在 |
| `pto_recovery` | 当前 frame-payload Initial/Handshake/Application PTO PING timeout hook。 | 已存在 |
| `address_validation` | 当前建模的 server anti-amplification 预算与显式 peer-address validation。 | 已存在 |
| `retry_token` | 当前 Retry packet integrity-tag encode/verify/parse、token loopback、一次性 token 消费与 address-validation unblocking。 | 已存在 |
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
zig build run-path-validation
zig build run-address-validation
zig build run-retry-token
zig build run-connection-ids
zig build run-stateless-reset
zig build run-initial-keys
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
