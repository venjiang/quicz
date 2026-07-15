# QUIC 传输协议实现任务

`quicz` 的目标是在 Zig 中实现 IETF QUIC 传输协议。本文把该目标拆成
可逐步实现、可验证、可回滚的任务。

## 范围

`quicz` 会追踪 IETF QUIC 标准，但实际实现目标不是覆盖所有可选协议特性。对成熟
QUIC 协议栈的内部对照只用于提炼共同 transport 能力基线。第一轮可用目标是 QUIC v1
transport、TLS 集成、client/server endpoint、stream I/O、transport-parameter 配置、
packet/timer 驱动、loss recovery、congestion 行为和互通。

HTTP/3、DATAGRAM、qlog、PMTU/GSO、QUIC v2 或其他扩展值得追踪，但不是 `quicz`
第一轮可互通 transport 里程碑的前置条件。

实现策略：成熟库已有的非核心能力不自研，只要能用窄 adapter 干净接入，就优先接入
维护良好的库。`quicz` 自己负责 QUIC transport state、packet processing、recovery、
endpoint lifecycle 和公开 Zig API。TLS、HTTP/3/QPACK、qlog、GSO/GRO 等平台 socket
加速以及其他成熟配套能力，默认通过 adapter 集成；只有明确记录没有合适库能满足
transport 边界时，才考虑自研。

第一轮实现范围仍限定为 QUIC 传输核心：

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

## 实用 Transport 基线

| 功能 | 实用目标 | quicz 状态 |
| --- | --- | --- |
| UDP client/server endpoint | 第一轮可用里程碑必须具备。由同一个 endpoint owner 驱动 accept/connect、packet receive/send、timer、route cleanup 和 close。 | 部分完成：`Tls13ServerEndpoint` 持有动态分配或有界的 TLS server record、ingress 分类、route-bound Version Negotiation/stateless-reset response pairing、lifecycle routing/timer、route-bound accepted/routed Initial 和 Handshake TLS backend output drain、endpoint-owned long-packet Initial/Handshake dispatch 与 route-bound output、installed-key coalesced Initial/Handshake datagram dispatch，以及 unsupported coalesced long-datagram rejection、route-bound Retry follow-up Initial 验证与 TLS output drain、原子 record 退役、route-owned installed-key short-packet receive、route-bound installed-key feed/output polling、route-bound due recovery output、route-bound protected close 发送、通过已提交 route 发出 close-on-frame-error、due idle/close 的 record 与 route 退役、process server 基于已提交 route tuple 的 datagram send selection，以及 process server 验证后 route migration；`Tls13ClientEndpoint` 持有一个 client transport、CID route、调用方选择的 route migration、route-bound Initial begin output、Version Negotiation follow-up route 注册和 endpoint-owned restart Initial 发送、route-bound receive-generated Initial/Handshake output、route-bound application output、route-bound close-on-frame-error output、route-bound due recovery output、recovery-timer mirror、route-bound protected close 发送，以及 due idle/close 的 route 与 timer 退役。process client/server 的 UDP receive capacity 已各自与配置的 local datagram limit 对齐。调用方仍持有 UDP I/O 与接纳策略；仍缺少生产级多连接 event-loop policy。 |
| TLS 1.3 集成 | 必须具备。纯 Zig TLS 1.3（`src/quic/tls13.zig` + `src/quic/tls13_backend.zig`）通过 `CryptoBackend` 接口接入；OpenSSL C adapter 为废弃路径。 | 部分完成：client 与 server TLS transport 持有 protected I/O，并统一选择和处理 recovery、idle、close 与 key-discard deadline；每个并发 server record 持有 `Tls13ServerTransport`（Connection、TLS backend，以及本端/对端/Original DCID 的固定副本）。服务端 Certificate 消息保留配置的 leaf-first DER certificate chain；配置 bundle 的 client 会在信任锚前逐跳校验收到的 leaf-to-issuer chain。纯 Zig TLS client 会拒绝缺失或未 offer 的 server ALPN selection，拒绝畸形 ServerHello 基础字段，拒绝重复的已知 ServerHello 与 EncryptedExtensions extension，拒绝 extension vector 后 trailing bytes，拒绝非空 server Certificate request context，拒绝畸形 CertificateVerify signature vector，并拒绝畸形 NewSessionTicket length/vector/ticket 边界；配置了名称的纯 Zig TLS server 会校验 ClientHello SNI，拒绝畸形 ClientHello 基础字段与 extension vector length，拒绝非空 ClientHello legacy_session_id，拒绝 ClientHello extensions 后 trailing bytes，拒绝重复的已知 ClientHello extension，要求 early_data 为空，要求 pre_shared_key 位于最后，要求兼容的 PSK key-exchange mode，拒绝畸形 pre_shared_key identity/binder vector，并在 server flight 前校验 X25519/signature-algorithm 支持。下方 `quic-go` 证据完成真实 TLS-owned handshake 与两条带 FIN 的 1-RTT STREAM echo，不使用 mock key 或 OpenSSL；仍缺少生产级 endpoint-owned event loop。 |
| QUIC v1 packet protection | 必须具备。Initial、Handshake、启用时的 0-RTT 和 1-RTT packet 必须由 TLS-owned 路径生成和消费。 | 部分完成：已有 v1/v2 Initial、Retry integrity、protected long/short helper、受保护 packet 解密和状态更新前的接收侧 UDP datagram 大小拒绝，以及 mock installed-key 路径。 |
| Stream | 必须具备。Bidirectional/unidirectional stream 的 open、read、write、FIN、reset、STOP_SENDING 和 stream limit 必须能跑在 protected UDP 上。 | 部分完成：TLS-owned client/server transport 已暴露 bidirectional 和 unidirectional 的 open/write/read/FIN，以及 RESET_STREAM 和 STOP_SENDING。TLS-backed endpoint UDP loopback 已验证 RESET_STREAM 与 FIN 驱动的 MAX_STREAMS_BIDI 额度释放；独立 `quic-go` client 已验证 stream 0 到 4 到 8 到 12 的连续 stream-count 额度释放、RESET_STREAM(41)、STOP_SENDING(42) 后对端回送 RESET_STREAM(42)，以及 client 单向 stream 2 / server 单向 stream 3 的 FIN 交换。更广泛的 stream-limit 互通仍不完整。 |
| Flow control | 必须具备。Connection、stream 和 stream-count flow control 必须能跑在 protected UDP 上。 | 部分完成：已有 frame-payload 和 protected loopback 覆盖；frame-payload 与 protected 0/1-RTT STREAM 写入会按实际 packet budget（1-RTT 含 ACK 空间）重新分片；quic-go client 已跨 Zig server 2 KiB stream 与 8 KiB connection 初始窗口完成 12 KiB stream echo。 |
| ACK/loss/PTO recovery | 必须具备。ACK processing、packet/time-threshold loss、PTO、retransmission 和 timer service 必须驱动 endpoint loop。 | 部分完成：已有确定性 recovery model 和 socket-backed loopback；有界 Zig server 已完成外部 1-RTT 与 Initial-space PTO recovery，生产 lifecycle 集成仍未完成。 |
| Congestion control | 至少需要 NewReno-style 基线。CUBIC 或可配置 controller 是后续性能工作。 | 部分完成：已有简化 NewReno-style 行为；缺少生产调优和可配置 controller。 |
| Connection ID 和 stateless reset | 必须具备。Routing、CID issue/retire、reset-token handling、close cleanup 和 inactive-CID reset emission 必须接入 endpoint lifecycle。 | 部分完成：已有 endpoint router、连接层 reset receive-to-draining 状态、endpoint installed-key feed 的 active-route reset 处理与 recovery timer disarm、client endpoint active reset receive-to-draining 处理、server endpoint route-bound active reset 上报及 close-deadline record 退役、server endpoint inactive-reset response path pairing、lifecycle helper 和 socket-backed loopback。TLS client/server transport 会为发包选择最新未退役的 peer `NEW_CONNECTION_ID`，并在没有该值时回退到已认证 Initial SCID；并发 TLS process server 现为每个接纳的连接生成独立的 8 字节 CSPRNG Initial SCID。完整 TLS-owned lifecycle 集成仍未完成。 |
| Retry 和 address validation | 服务端健壮性和互通必须具备。 | 部分完成：并发 Retry 使用每个进程的新 token secret 与每次签发的新 nonce 熵；已有 token policy、Retry validation、address-validation loopback 和 TLS extension byte 校验；缺少生产存储/replay policy。 |
| Path validation 和迁移 | 需要单路径 validation 和 route update；完整 multipath 不在范围内。 | 部分完成：已有 PATH_CHALLENGE/PATH_RESPONSE 和 route-update loopback；endpoint-owned server output 与 process server datagram send 现在可在已验证迁移后使用已提交 route tuple。独立进程 Zig migration 运行已在客户端迁移端口后完成 STREAM echo，并输出 `path_challenge_queued=true`、`route_updated=true` 和 `migrated=true`。生产 path policy 和外部迁移证据仍未完成。 |
| 0-RTT | 第一轮 1-RTT stream echo 互通之后推进；不阻塞当前里程碑。 | 部分完成：已有显式 accept/reject 和 mock installed-key 0-RTT 路径；缺少真实 TLS replay policy。 |
| RFC 9221 DATAGRAM | 可选扩展，不属于第一轮 transport 里程碑。 | Deferred。 |
| HTTP/3 和 QPACK | transport 可互通后再做的应用层工作。 | Deferred。 |
| QUIC v2 和 RFC 9368 compatible version negotiation | 可选扩展，除非选定互通目标要求。 | 已有部分 primitive；完整行为 deferred。 |
| qlog、PMTU discovery、GSO/GRO、高级 congestion selection | transport loop 可用后的运维/性能扩展。 | Deferred 或未实现。 |
| 外部互通 | 声称第一轮可用 transport 里程碑前必须具备。 | 部分完成：客户端专用二进制已与两个来自不同实现家族的本机独立服务端完成证书校验的 QUIC/TLS 握手，并通过强制 Retry 的 `quic-go` v0.59.0 server、以及另一次由 peer 丢弃一个 post-handshake 1-RTT 包以触发 PTO recovery 的运行完成证书校验的双向 STREAM FIN echo；仅支持 v1 的 `quic-go` server 会对 Zig v2 Initial 返回 Version Negotiation，Zig 校验后创建全新的 v1 连接并完成证书校验 stream echo。Go 与 Rust 客户端已和本地 Zig server 完成证书校验的双向 STREAM FIN echo，包含有界 Retry 路径。`quic-go` client 还证明 Zig server 在 stream 0 到 4 到 8 到 12 的连续 stream-count 额度释放、接收 RESET_STREAM(41)、server 的 STOP_SENDING(42) 后收到对端 RESET_STREAM(42)、单向 stream 2 到 3 的 FIN 交换，以及丢弃 4 个 post-stream Zig datagram 或握手完成前 4 个 server-flight datagram 后的服务端 PTO recovery。更广泛的服务端和应用层场景尚未验证。 |

并发纯 Zig server 现经由其拥有的 `EndpointConnectionRegistry` 分发已路由的
1-RTT short packet，涵盖 lifecycle route lookup、installed-key 接收和
stateless-reset 处理。`Tls13ServerEndpoint` 会在同一 record 边界完成所有安装
Handshake key 的已路由 Initial（包括保留的 coalesced Initial/Handshake）及其
Handshake backend output 和有界 route-bound drain；Retry follow-up 与已路由
Handshake input 也使用同一 record boundary。这只是
endpoint ownership 的增量证据，并非完整生产级 event loop。

Client endpoint 的错误路径不会再把无关待发送应用包误当作 close-on-error 输出：
`Tls13ClientEndpoint.receiveWithRoutePathOrClose()` 只有在 `InvalidPacket` 已让连接进入
`closing` 时才取 route-bound application datagram。route mismatch 和其他未进入 closing
的无效输入会保留已排队 application output，等待正常 poll。
Server endpoint 的 installed-key feed 也遵循同一规则：
`Tls13ServerEndpoint.feedInstalledKeyDatagramWithRoutePath()` 只有在选中 record 的连接进入
`closing` 后才为 `InvalidPacket` poll route-bound 1-RTT datagram，避免解密/认证失败消耗
无关已排队输出。
底层 lifecycle helper
`EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndUpdatePathOrCloseAndPollDatagram()`
也会把认证后的 close-on-frame-error 表示为 `feed_error` 和可选 close datagram，同时保留
未进入 closing 的无效输入下已排队输出。
调用方持 key 的 long-header
`processProtectedLongDatagramInSpaceOrCloseAndPollDatagram()` 也采用同一边界：认证后的
Initial/Handshake frame 错误会直接返回已排队 CONNECTION_CLOSE datagram；畸形且未进入
closing 的输入仍抛错，并保留已排队输出给正常 poll。
有界 drain 版本 `processProtectedLongDatagramInSpaceOrCloseAndDrainDatagrams()` 也遵循同一
规则：认证后的 frame 错误会 drain close output；畸形且未进入 closing 的输入不会 drain
无关已排队输出。
调用方持 key 的 long-header backend helper
`driveCryptoBackendInSpaceOrCloseAndPollProtectedLongCryptoDatagram()`、
`driveCryptoBackendInSpaceOrCloseAndDrainProtectedLongCryptoDatagrams()` 及其
process/routed wrapper 也使用同一 close 边界：peer transport-parameter 错误或认证后的
receive frame 错误会直接从触发连接返回 protected close datagram，不再要求调用方另行
poll output。
installed-key Handshake OrClose helper 也采用同一边界：receive-side frame 错误和 backend
peer-parameter 错误会直接返回或 drain 触发连接上的 protected Handshake close datagram，
包括 routed backend drain/poll wrapper。
installed-key 1-RTT short OrClose helper 对 Application-space receive 和 backend 错误也
采用同一边界：direct/routed poll/drain helper 会从选中的连接返回 protected short close
datagram；route mismatch 和未进入 closing 的 invalid packet 仍在输出前失败。
Client endpoint 的 due-recovery service 现在会按到期 packet number space 取输出，不再只
走 Application short-packet 路径。`Tls13ClientTransport.pollRecoveryDatagram()` 会根据
已服务的 RFC 9002 timer 发出 Initial、Handshake 或 Application protected output，
`Tls13ClientEndpoint` 再把该输出绑定到已提交 route。测试覆盖 Initial 与 Handshake
PTO route output，并保留已有 Application PTO route output 证据。

### Packet number 重排证据

受保护 long-header 与 1-RTT short-packet 接收路径都会保留有界的已收 packet
number range 历史。它们接受已认证的前向间隙和延迟包，在 frame side effect 前拒绝
重复包，并为不连续接收生成 ACK range。`received packet ranges merge reordered
packets and encode ACK gaps`、`protected long datagram bridge accepts a
retransmitted Handshake packet number` 与 `processProtectedShortDatagram
acknowledges reordered packets with ACK ranges` 测试分别覆盖 range 合并、long-header
重传、重复包拒绝和 ACK 编码。`zig build run-interop-event-loopback -- loss` 会丢弃首个
client 1-RTT 带 FIN 的 STREAM datagram，并验证 PTO 驱动重传和成功的双向 FIN transfer
（`pto_recovered=true`）。

`zig build run-interop-event-loopback -- congestion` 在同一纯 Zig TLS-owned UDP
事件循环中执行受控的 NewReno loss exchange：丢弃首个 ack-eliciting 1-RTT PING，投递
后续三个 PING，并在处理握手遗留 control output 后 drain server 的 sparse ACK。接收端断言
packet number gap（`next_peer_packet=4`），发送端断言 packet-threshold congestion response
（`cwnd_before=12000`、`cwnd_after=6000`）。

`zig build run-interop-event-loopback -- persistent` 在同一 TLS-owned 路径先建立真实
RTT sample，再丢弃三个有受控时序的连续 PING，只投递第四个，并处理 lifecycle-routed
server ACK。观测到的 persistent-congestion duration 为 411ms，丢弃包发送跨度为
1090ms，congestion window 从 12000 降至 1200-byte datagram 对应的 minimum 2400。

`zig build run-interop-event-loopback -- key-update` 会先 drain 遗留 control
output，再通过真实 UDP 驱动两次 TLS-owned 1-RTT key phase 轮转。首个 server ACK
解除 client update gate；endpoint 将 server 保留 key 的 discard deadline 作为
`.key_discard` 暴露，并经正常 due-deadline 路径处理，随后拒绝使用过期上一代 key 的
重放包（`stale_rejected=true`）。

`zig build run-interop-event-loopback -- path` 在同一纯 Zig TLS-owned 握手后，
将 client 切换到单独绑定的新 UDP port，把受保护的 `PATH_CHALLENGE` 投递到新 tuple，
再将匹配的 `PATH_RESPONSE` 经 server lifecycle 路由回来。server 在已认证 response
消费 outstanding challenge 前保持旧 route，随后才提交新 tuple（`tls_path_validation=true`、
`server_route_updated=true`）。同一 live socket 路径现在还会从已提交 route tuple
发送后续普通 1-RTT PING 到迁移后的 client socket（`post_migration_output=true`）。
聚焦 endpoint 测试也证明，validation 后可读取已提交的 router tuple，并且
endpoint-owned TLS server 可把后续普通 1-RTT output 与该已提交 tuple 配对。

这为 Initial/Handshake/1-RTT packet number space 提供聚焦覆盖。完整的外部
client-to-server STREAM transfer 通过前，不能将其视为外部服务端互通证据。

### 独立进程本地 Zig 互通证据

`zig build run-tls13-process-interop` 会分别启动独立编译的
`quicz-tls13-process-echo-server` 与 `quicz-tls13-process-echo-client`。
两个进程通过真实 loopback UDP socket 完成纯 Zig TLS 持有的
Initial/Handshake/1-RTT 流程，记录对端 Initial source connection ID，并完成
stream 0 与 4 独立完成以 FIN 结束的 bidirectional STREAM echo
（`echo_streams=2 echo_bytes=10`）。服务端通过
`EndpointConnectionLifecycle` 分类并接受首个 Initial；只有认证成功后才注册
Original DCID 与 server SCID route，然后由 TLS 产生第一份响应。客户端在绑定 UDP
socket 后注册自己的 SCID route。两端后续 Handshake 与 1-RTT STREAM 的收发都会使用
这些已注册 route 和 lifecycle timer refresh；process server 会通过 endpoint 已提交的
route tuple 发送 managed connection output，而不是固定使用接纳时的 peer address。客户端 endpoint 将 Initial/Retry/Handshake 状态推进交给
其 `Tls13ClientTransport`；握手后按该 transport 的 recovery、idle、close 与 key-discard deadline
选择 UDP receive 等待，due recovery 会重传有界的 1-RTT output。设置
`QUICZ_PROCESS_INTEROP_CLIENT_COMPLETION=migrate` 时，client 会在握手后切换到新的
UDP socket，server 会排队 PATH_CHALLENGE，并在 PATH_RESPONSE 验证后提交 route，
迁移后的 stream echo 完成（`path_challenge_queued=true`、`route_updated=true`、
`migrated=true`）。该可复现命令默认并发启动两个带 tag 的 client
process。服务端在同一 UDP socket 上用一个 `EndpointConnectionLifecycle` 分类和路由所有
datagram，并由有界、endpoint-owned 的 `EndpointConnectionRegistry` 持有每条
`Connection` 与其 `Tls13Backend` record；固定容量形式会预分配 record hash map、配置的 route/reset-token 表、
recovery timer，以及 lifecycle 的 deadline、due-recovery poll view 与 installed-key receive view。因此容量以内的 record 接纳、CID route 建立与 timer arm 都不会扩容。不同 tag 使 Initial DCID 和 SCID 不会冲突。每个 FIN-terminated echo 匹配后，客户端都会发送受保护的
`CONNECTION_CLOSE`；服务端只处理该连接的 route、进入 draining 并保持该 route 可路由，直到
close deadline 到期才退役该 handle 的 route（`close_cleanup=true`）。endpoint-owned registry 在活跃容量已满时
自行拒绝新 record，且只在 record 退役后释放容量；服务端仅在每条已接受连接都退役后退出。
`sequential` 仍作为显式兼容模式保留。

服务端现在把有限的 completion target 与同时活跃连接容量分开：可选的第五个 server
参数 `max_active_connections` 指定活跃上限；省略时仍沿用旧行为，即 completion target
同时也是容量上限。
在 concurrent 模式传入 `completion_target=0` 会创建有界的长生命周期 endpoint：它一直
服务到被中断，且必须显式给出正数活跃连接上限。close/idle record 退役后仍会先释放槽位，
随后才能接收新的 Initial。容量已满时会重发匹配的 Retry；其余新的 Initial 会被丢弃而不会
终止 endpoint。真实单槽位运行已观察到这些丢弃，静默 Go client 退役后第二个经证书校验的
Go echo 成功完成，并且只在最终汇总中报告 `capacity_dropped_initials=4`。
`QUICZ_PROCESS_INTEROP_CONNECTIONS=3 QUICZ_PROCESS_INTEROP_MAX_ACTIVE_CONNECTIONS=1 QUICZ_PROCESS_INTEROP_MODE=rolling zig build run-tls13-process-interop`
会经同一个 concurrent lifecycle 路径依次运行三次 TLS-owned echo。它证明 protected close
退役后会释放唯一的 route/map 槽位，下一条 Initial 才可被接收。这是可复用的有界容量证据，
不是无上限的生产 endpoint policy；`sequential` 仍作为显式兼容模式保留。

lifecycle 现在通过 `initWithRouterOptions()` 让调用方同时限制 active destination-CID
route 与保留的 stateless-reset token。进程 server 以库层上限为每条活跃连接预留两个
route 槽位。容量耗尽时，已接收 Initial 的第二个 CID 无法安装会回滚第一个 route；token
容量耗尽时只拒绝新 token，不会扰动已有 route 或保留 token。

并发路径读取单调 `awake` clock，只等待
`nextDeadlineAcrossConnections()` 选出的最早 lifecycle deadline，并在下一次 receive 前通过
lifecycle 的有界 output drain 处理该 deadline。进程服务端接受可选
`idle_timeout_millis` 参数，常驻调用默认 30 秒；可复现 interop harness 默认显式传入
1000 ms。执行
`QUICZ_PROCESS_INTEROP_CLIENT_COMPLETION=idle zig build run-tls13-process-interop`
会让两个 client 在验证 echo 后保持静默，并证明每个 map entry 都在自己的 idle deadline 被独立
退役（`idle_cleanup=true`）。可用 `QUICZ_PROCESS_INTEROP_IDLE_TIMEOUT_MS` 测试其他有界
timeout。这仍是有界测试 policy，不是完整的生产 timeout policy。

同一有界路径还包含一个刻意构造的本地 recovery 证明。执行
`QUICZ_PROCESS_INTEROP_CONNECTIONS=1 QUICZ_PROCESS_INTEROP_CLIENT_COMPLETION=loss zig build run-tls13-process-interop`
会让 Zig client 丢弃握手后的前四个响应。服务端使用 100 ms 的 initial RTT estimate，使 recovery
deadline 早于仅供测试的 idle deadline；lifecycle 会 service 随后的 PTO（`pto_serviced=true`）、
重传受保护的 stream 数据，client 随后报告 `pto_recovered=true`。这验证有界 demo 的 socket-loop
recovery 排序，不构成生产 RTT 或 timeout policy。

`QUICZ_PROCESS_INTEROP_RETRY=true zig build run-tls13-process-interop` 会启用并发
server 的有界 Retry 路径。它签发绑定 UDP path 和 v1 的一次性 address-validation token；对于
重传的无 token Initial 保留并重发同一个 Retry，只有 lifecycle 先认证 packet、再校验并消费 token 后才接受 follow-up
Initial。未认证的 follow-up 不会改变 token 和 replay 状态。Zig client 仅重置 Initial send state，使用 Retry SCID 和重新派生的 Initial key 重发缓存的
ClientHello，然后报告 `retry_validated=true`。重新执行的证书校验 Go 与 Rust client 也都通过该 Retry
路径完成了两条 stream、十字节的双向 FIN echo。静态 demo secret 与内存 replay filter 仍是有界本地 policy，不是生产 key
storage 或分布式 replay protection。

到达 idle deadline 但尚未验证的 Retry 条目只会退役自己的 route 和内存，不会计入已完成的
accepted connection；因此不会在 `accepted_count` 达到请求总数之前提前结束有界 server。

同一并发服务端通过 lifecycle-owned helper 接收 coalesced 的外部
Initial/Handshake：它保留完整 UDP 长度以校验 Initial size，同时按编码边界认证每个
long-header packet。随附的独立 Go 与 Rust client 都分别通过该服务端的有界 Retry 路径完成了
证书校验的两条 stream、十字节双向 FIN echo；服务端分别在 Go 的 protected close 后和 Rust 的 idle deadline 后
独立回收连接。

这是本地 Zig 到 Zig 的集成门槛，不是外部互通。它使用本地确定性测试证书，客户端
关闭证书校验；它不能替代下方的证书校验外部互通证据。

### Go 与 Rust 客户端互通示例

`examples/interop/go_echo_client` 与 `examples/interop/rust_echo_client`
是连接一次性 Zig echo server 的独立 QUIC 客户端。两者都要求调用方提供 PEM 信任锚和
SNI，保持证书校验开启，协商 `hq-interop`，在 stream 0 和 4 分别发送带 FIN 的 `hello` 与
`world`，并且每条 stream 都收到对应 echo 与 FIN 后才报告成功。本仓库的本地开发命令如下：

```sh
zig-out/bin/quicz-tls13-process-echo-server 127.0.0.1 4443
(cd examples/interop/go_echo_client && go run . -addr 127.0.0.1:4443 -ca ../testdata/quicz-echo-ca.pem -server-name localhost)
(cd examples/interop/rust_echo_client && cargo run -- 127.0.0.1:4443 ../testdata/quicz-echo-ca.pem localhost)
```

两个客户端对 Zig server 都在验证两条双向 STREAM FIN exchange 后输出
`handshake_done=true echo_streams=2 echo_bytes=10`。2026-07-15 在默认 30 秒 server idle policy 和有界 Retry
路径下，顺序运行 Go 与 Rust client 也都完成。当前两 client Go 并发运行也通过同一个双槽位
endpoint 完成两次握手与 echo，两条 route 均保留至 draining period 结束，且
`capacity_dropped_initials=0`。server 会跨多个 Initial packet 重组有上限的
ClientHello，逐个处理共包的 Initial/Handshake packet 后再消费 Handshake packet，并在对应
key space 已丢弃后仅路由迟到的 long-header ACK 流量而不再解密；它也接受先于 stream payload
到达的 1-RTT ACK/control packet。该 PEM 文件只是在 `localhost` 和 `127.0.0.1` 上使用的本地
测试信任锚，不是部署凭据或公共 CA。

### 外部证书校验握手与 STREAM Echo 证据

`zig build run-interop-external-client -- <server_ip> <server_port>
<absolute_ca_pem> [server_name]` 运行客户端专用路径。它加载调用方提供的 CA bundle，
使用真实墙钟和 SNI，保持证书校验开启，并通过真实 UDP socket 驱动由
`Tls13ClientEndpoint` 持有的 TLS Initial、Handshake 和 1-RTT key。一个 UDP datagram 中共包的 long-header packet 会先被
依次处理，再处理其后的 1-RTT short-header packet。针对两个来自不同实现家族、均使用
ECDSA P-256 证书的本机独立服务端，命令均输出
`external_handshake_done=true certificate_verified=true alpn=hq-interop`。其中一个 peer
在完整长头包之后用全零尾部填充首个 UDP 响应；示例只在 UDP 边界丢弃这种精确的全零
数据报尾部。任何非零尾部仍按普通受保护短头包处理。

同一客户端在证书校验握手后会打开 stream 0 与 4，分别发送带 FIN 的 `hello`、`world`，并要求
每条收到匹配 echo 与对端 FIN。仓库内的一次性 `quic-go` v0.59.0 fixture 会在运行时生成
localhost CA PEM；Zig client 对该独立 peer 输出
`external_handshake_done=true certificate_verified=true alpn=hq-interop echo_streams=2 echo_bytes=10`。
这证明外部 server 真实解析受保护的 1-RTT multiplexed STREAM、完成 echo 并关闭发送侧，而不只是 TLS 握手。

外部客户端还会在握手确认前接受一个有效的 v1 Retry：它以 original DCID 验证 Retry integrity tag，
使用 Retry SCID 和重新派生的 Initial key 重发缓存的 ClientHello，并自动携带保存的 token。一个通过
`Transport.VerifySourceAddress` 强制 Retry 的独立 `quic-go` v0.59.0 server 完成了同样的证书校验
双向 FIN echo。这是由真实 peer 驱动的 Retry 行为，不是本地 token fixture。

同一 endpoint-owned client 还对仅支持 v1 的 `quic-go` server 完成了真实的 v2 到 v1
Version Negotiation handoff：它连同旧 route 退役旧 endpoint，再使用新 CID 创建新 endpoint，最后完成证书校验的 FIN echo。

其应用接收循环使用单调时钟和 connection 的下一个 loss-detection deadline，而不是 packet-count
时钟。一个独立 `quic-go` v0.59.0 server wrapper 在 UDP 边界丢弃首个 post-handshake
short-header packet，随后输出 `dropped_first_one_rtt=true` 与
`echoed_bytes=5 response_fin=true`；Zig client 在保持相同证书校验和 FIN echo 的同时输出
`pto_recovered=true`。这证明了一个由真实外部 peer 驱动的 1-RTT STREAM 丢包/PTO 重传路径，
而不只是本地 loss simulation。

这仍只是窄范围的外部互通证据。version negotiation、更广泛的服务端
行为和应用层协议互通仍需验证，里程碑不能据此视为完成。

## RFC 覆盖状态

状态值使用 `Done`、`Partial`、`Missing` 和 `Deferred`。`Partial` 表示仓库
已经有该领域的部分代码和测试，但剩余行为仍保留在下面的任务矩阵中。

| 标准领域 | 状态 | 当前证据 | 剩余证明 |
| --- | --- | --- | --- |
| RFC 8999 版本无关属性 | Partial | Version Negotiation packet codec、endpoint unsupported-version Version Negotiation response helper、client-side validation/selection state、reserved-version greasing detection/selection skip、long/short packet envelope、包含首个 client Initial DCID 长度约束的 connection ID 校验、stateless reset helper、packet codec/example 测试，以及带 protected follow-up Initial emission 的 socket-backed UDP endpoint routing loopback。`Tls13ClientTransport` 现只暴露经校验的选版和 follow-up config，要求调用方创建全新连接；仅支持 v1 的 `quic-go` server 已外部验证 v2 Initial → Version Negotiation → 全新 v1 TLS/STREAM echo。 | 更广泛的 TLS-owned socket routing 和版本无关行为仍未完成。 |
| RFC 9000 传输协议 | Partial | 含 ACK/ACK_ECN range 校验的 frame codec、transport parameter、连接状态、stream、flow control、connection ID、Retry/token、path validation、close/reset 行为、endpoint idle/close route-timer 清理、endpoint routing helper、受保护 packet 解密和状态更新前的本地 UDP datagram 大小拒绝、endpoint installed-key feed 与 client endpoint active-route stateless reset receive-to-draining 处理、server endpoint 通过 route lookup 直接解析 owned record 的 installed-key short-packet receive、server endpoint route-bound Retry follow-up validation/TLS output、route-bound long-packet Initial/Handshake dispatch、installed-key coalesced Initial/Handshake datagram dispatch、unsupported coalesced long-datagram rejection 和 protected close 发送与终态 record cleanup、lifecycle-owned caller-keyed protected UDP packet loopback、socket-backed UDP path-validation route-update loopback、socket-backed UDP lifecycle Retry/address-validation loopback、Connection 级 TLS-owned 路径的 protected close、path validation、stateless reset、flow-control window update、MAX_STREAMS、DATA_BLOCKED/STREAM_DATA_BLOCKED/STREAMS_BLOCKED、NEW_TOKEN、Retry、HANDSHAKE_DONE、application close 帧交换验证和示例，以及纯 Zig TLS-owned UDP migration：验证 PATH_CHALLENGE/PATH_RESPONSE，且 server endpoint 仅在验证后提交 route。 | 仍需完整 protected/TLS socket-backed client/server loopback、完整 endpoint 生命周期和外部互通。 |
| RFC 9001 TLS 与 packet protection | Partial | QUIC v1 Initial secret 派生、AEAD/header-protection helper、Retry Integrity Tag、protected packet helper、mock CRYPTO backend handoff、installed-key 测试、client endpoint route-bound Retry follow-up Initial output、ACK-gated installed-key key-update 发起和 Connection 级 TLS-owned 路径的 1-RTT key update（KEY_PHASE 翻转 + 下一代 keys）验证。endpoint lifecycle 现在将保留 key 的到期作为 `.key_discard` deadline 调度；纯 Zig TLS-owned UDP 事件循环证明两次实时 key update、ACK gate、due-deadline old-key discard，以及对过期 key 重放包的拒绝。 | 仍需真实 TLS backend transcript 集成、TLS 持有的 traffic-secret production，以及超出已证明单连接轮转的更广泛 live key-update policy/互通。 |
| RFC 9002 loss detection 与 congestion control | Partial | 触碰 recovery state 前拒绝 invalid ACK/ACK_ECN range、largest-acknowledged RTT sampling、跨 packet number space 的 connection-level RTT 估计共享与 PTO backoff（含 client Initial ACK reset suppression）、Initial/Handshake RTT ACK-delay suppression 与 Application ACK delay scaling/capping、packet/time-threshold loss、带 closing/draining disarm、anti-amplification-limited server PTO disarm/rearm、新 datagram 解除发送阻塞时的 expired-PTO service 和 client no-in-flight anti-deadlock PTO 的 aggregate loss-time-before-PTO timer deadline selection/service、endpoint-owned 多连接 recovery timer scheduling、server endpoint due recovery output 与已提交 route tuple 绑定、client endpoint due recovery output 与已提交 route tuple 绑定、跨 packet number space bytes-in-flight 拥塞发送准入、peer max_udp_payload_size recovery max_datagram_size/initial-cwnd resync、把 route retirement 与 timer disarm 绑定到同一 endpoint state owner 的 connection lifecycle helper、caller-keyed protected long/Initial-Handshake CRYPTO-space/0-RTT/short-packet、explicit key-phase/key-update short-packet、caller-owned key-phase short-packet、installed-key Handshake/0-RTT long-packet 和 installed-key protected short-packet timer refresh、已 armed 的单个 PTO probe 可绕过 congestion window、ACK 驱动的 frame-payload STREAM/CRYPTO、protected CRYPTO、protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission requeue 和已 ACK 的 RESET_STREAM 过期重传抑制、带 underutilized-cwnd suppression 的 NewReno slow-start/congestion-avoidance 字节计数与 batched-ACK 增长、recovery-period 行为、新拥塞事件后一次性 recovery probe 和 minimum-window ssthresh clamp、不受 PTO backoff 放大的 persistent congestion duration/response、min-RTT refresh、recovery-period 清理/重新进入与非连续抑制、ACK_ECN CE 驱动的 NewReno recovery 响应、带 Initial/Handshake max_ack_delay suppression 与 handshake confirmation 前 Application PTO gating 的 packet-space PTO PING/new-data/in-flight-CRYPTO/protected-0-RTT-control/protected-0-RTT-STREAM/in-flight-STREAM/cross-space probe hook、ECN validation 按 connection path 隔离且在连接退役时清理、socket-backed UDP lifecycle loss/PTO recovery、lifecycle congestion-recovery 与 lifecycle STREAM-retransmission loopback、Connection 级 TLS-owned 路径的 ACK 清理 in-flight + RTT 采样 + PTO backoff（deadline 翻倍）验证、纯 Zig TLS-owned UDP event loop 中 sparse ACK 驱动的 packet-threshold loss 将 NewReno congestion window 从 12000 降至 6000 的证据，以及 TLS-owned 的真实 RTT persistent-congestion exchange 将其降至 2400 的证据。 | 仍需完整 TLS-owned socket-owned protected-packet loss/PTO timer lifecycle 集成，以及剩余 recovery 边界的 controlled-clock 测试。 |
| RFC 9221 QUIC DATAGRAM | Deferred | 明确不在第一轮 transport-core 范围内。 | 核心 transport loop 可用后单独追踪。 |
| RFC 9368 Compatible Version Negotiation | Partial | 已有 `version_information` transport parameter codec、显式 directional first-flight compatibility relation helper 用于 compatible-version selection、连接层导出/应用校验（含 VN 后 server Version Information downgrade checks）、server-side compatible Version Information apply/byte/close 路径、经 backend 驱动的 compatible peer transport-parameter handoff 与 peer Version Information snapshot、已解析 `version_information` 语义失败到 `VERSION_NEGOTIATION_ERROR` 的 close 分类、reserved Available Versions 可出现但永不被选中、`VERSION_NEGOTIATION_ERROR` 错误码、client-side incompatible VN packet validation/selection state、VN follow-up config propagation、lifecycle-owned old-attempt route/timer retirement、带 handoff/restart 失败清理的 follow-up Initial route registration、endpoint-owned follow-up connection handoff，以及 lifecycle-owned protected follow-up Initial emission。 | 仍需完整 incompatible/compatible negotiation 状态机、TLS-owned socket retry-loop integration 和互通证明。 |
| RFC 9369 QUIC v2 | Partial | 已有版本常量、long-header packet type bit 映射、按配置使用 v2 protected long-packet 与 Retry wire-version、Retry packet codec 映射、v2 Retry Integrity Tag helper、address-validation token originating-version binding、RFC 9368 `version_information` transport-parameter 支持，以及 RFC 9369 Initial salt 和 `quicv2` packet-protection label 派生，测试覆盖 Appendix A.1/A.4 向量。 | 仍需完整 compatible version negotiation 状态、endpoint routing、TLS-owned packetization 和互通证明。 |
| HTTP/3 和 QPACK | Deferred | 应用层协议不在本 transport-core 计划内。 | transport interop 完成后另起应用层任务。 |

当前代码仍是实验性的 frame-payload 传输骨架。`pollTx` 和
`processDatagram` 只流转未加密 QUIC frame payload 字节；连接层现在有一个
窄范围的 Initial/Handshake CRYPTO/ACK/PING protected long-packet coalesced
send/receive bridge、installed-key Handshake long-packet helper、首个 client Initial DCID 长度与 server Initial token 校验、使用调用方 key 或连接已安装 key 的 0-RTT
STREAM/RESET_STREAM/STOP_SENDING protected long-packet 路由，以及使用调用方 key 的 1-RTT protected short-packet
PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge，并带调用方持有和连接已安装的 key-phase 状态 helper，以及 socket-backed UDP endpoint routing、lifecycle Retry/address-validation routing、lifecycle caller-keyed protected packet/lifecycle loss-recovery/lifecycle congestion-recovery/lifecycle PTO-recovery/lifecycle STREAM-retransmission loopback 和验证驱动的 UDP path-validation route update，但尚不能完整生成或消费 TLS-owned QUIC-over-UDP packet。

## 当前阶段边界

截至 2026-07-03，实现已从 mock/installed-key 阶段进入 **TLS-owned** 阶段。
纯 Zig TLS 1.3 实现（`src/quic/tls13.zig` + `src/quic/tls13_backend.zig`）驱动
真实 `Connection` 与 `EndpointConnectionLifecycle` 实例，通过 loopback UDP 完成完整
TLS 1.3 握手（ClientHello → ServerHello flight → client Finished →
`handshake_confirmed`），安装 TLS-owned Initial/Handshake/1-RTT traffic secret，
并验证 STREAM echo、RESET_STREAM、STOP_SENDING、NEW_CONNECTION_ID、NEW_TOKEN、
HANDSHAKE_DONE、protected close、PTO probe、ALPN selection validation、SNI validation、ClientHello extension validation、duplicate-extension rejection、PSK/early-data validation、key-share/signature-algorithm validation 与
recovery-timer service——全程无 mock 密钥、无 OpenSSL。

现有聚焦证据已经包含证书校验的外部 STREAM echo、TLS-owned PTO 重传与受控的
NewReno/persistent-congestion 响应、TLS-owned Retry 重试、stateless reset 处理、
PATH_CHALLENGE/PATH_RESPONSE 驱动的 route migration，以及单 UDP socket、单 lifecycle
owner、具备单调 deadline idle cleanup 的有界双 client 并发进程服务端。RFC 行仍保持
`Partial`：该服务端是有界的长生命周期本地证明，不是生产 endpoint policy；更广泛的
TLS-owned client/server policy、0-RTT replay policy 和更宽的外部行为仍未证明。

主线任务仍是 IETF QUIC transport 实现。下一阶段将有界 demo ownership 证明推进为生产级
endpoint-owned connection map 和 event loop，同时保持已验证的纯 Zig TLS 路径与外部互通
证据。剩余验收条件是：长生命周期的生产容量和 timeout policy、超出有界测试 map 的所有
active connection 由 lifecycle 统一完成 receive/send/timer/close routing、超出固定测试数量
后的有界资源与 route retirement，以及更广泛可复现的多连接 smoke test。这是生产 ownership
边界，不得削弱既有证据。

echo 路径之后，transport core 要保持可嵌入，不把生产级 socket 策略写死在 demo 中。
lifecycle core 现在已经暴露第一版面向 socket 和 TLS-backend loop 的 API 形态：`feedDatagram`、
`feedDatagramWithInstalledKeys`、`feedDatagramWithInstalledKeysAcrossConnections`、
`feedDatagramWithInstalledKeysAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDrainDatagramsWithInstalledKeyOptions`、
`processAcceptedProtectedInitialWithCryptoBackendAndSelectNextDeadline`、
`processAcceptedProtectedInitialWithCryptoBackendOrCloseAndSelectNextDeadline`、
`processAcceptedProtectedInitialWithCryptoBackendAndPollDatagram`、
`processAcceptedProtectedInitialWithCryptoBackendOrCloseAndPollDatagram`、
`processAcceptedProtectedInitialWithCryptoBackendAndDrainDatagrams`、
`processAcceptedProtectedInitialWithCryptoBackendOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline`、
`drainProtectedLongCryptoDatagramsInSpace`、
`driveCryptoBackendInSpaceAndPollProtectedLongCryptoDatagram`、
`driveCryptoBackendInSpaceOrCloseAndPollProtectedLongCryptoDatagram`、
`driveCryptoBackendInSpaceAndDrainProtectedLongCryptoDatagrams`、
`driveCryptoBackendInSpaceOrCloseAndDrainProtectedLongCryptoDatagrams`、
`processProtectedLongDatagramInSpaceAndPollDatagram`、
`processProtectedLongDatagramInSpaceOrCloseAndPollDatagram`、
`processProtectedLongDatagramInSpaceAndDrainDatagrams`、
`processProtectedLongDatagramInSpaceOrCloseAndDrainDatagrams`、
`processRoutedProtectedLongDatagramInSpaceAndPollDatagram`、
`processRoutedProtectedLongDatagramInSpaceOrCloseAndPollDatagram`、
`processRoutedProtectedLongDatagramInSpaceAndDrainDatagrams`、
`processRoutedProtectedLongDatagramInSpaceOrCloseAndDrainDatagrams`、
`processProtectedLongDatagramInSpaceAndDriveCryptoBackendAndPollDatagram`、
`processProtectedLongDatagramInSpaceAndDriveCryptoBackendOrCloseAndPollDatagram`、
`processProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams`、
`processProtectedLongDatagramInSpaceAndDriveCryptoBackendOrCloseAndDrainDatagrams`、
`processProtectedLongDatagramInSpaceAndDriveCryptoBackendInSpaceAndSelectNextDeadline`、
`processProtectedLongDatagramInSpaceAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendAndPollDatagram`、
`processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendOrCloseAndPollDatagram`、
`processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams`、
`processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendOrCloseAndDrainDatagrams`、
`processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendInSpaceAndSelectNextDeadline`、
`processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`processProtectedHandshakeDatagramWithInstalledKeysAndPollDatagram`、
`processProtectedHandshakeDatagramWithInstalledKeysOrCloseAndPollDatagram`、
`processProtectedHandshakeDatagramWithInstalledKeysAndDrainDatagrams`、
`processProtectedHandshakeDatagramWithInstalledKeysOrCloseAndDrainDatagrams`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndPollDatagram`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysOrCloseAndPollDatagram`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDrainDatagrams`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysOrCloseAndDrainDatagrams`、
`processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndPollDatagram`、
`processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams`、
`processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendOrCloseAndPollDatagram`、
`processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendOrCloseAndDrainDatagrams`、
`processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndSelectNextDeadline`、
`processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndPollDatagram`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendOrCloseAndPollDatagram`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendOrCloseAndDrainDatagrams`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndSelectNextDeadline`、
`processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`processProtectedZeroRttDatagramAndPollShortDatagram`、
`processProtectedZeroRttDatagramAndDrainShortDatagrams`、
`processProtectedZeroRttDatagramOrCloseAndPollShortDatagram`、
`processProtectedZeroRttDatagramOrCloseAndDrainShortDatagrams`、
`processRoutedProtectedZeroRttDatagramAndPollShortDatagram`、
`processRoutedProtectedZeroRttDatagramAndDrainShortDatagrams`、
`processRoutedProtectedZeroRttDatagramOrCloseAndPollShortDatagram`、
`processRoutedProtectedZeroRttDatagramOrCloseAndDrainShortDatagrams`、
`processProtectedZeroRttDatagramWithInstalledKeysAndPollShortDatagram`、
`processProtectedZeroRttDatagramWithInstalledKeysAndDrainShortDatagrams`、
`processProtectedZeroRttDatagramWithInstalledKeysOrCloseAndPollShortDatagram`、
`processProtectedZeroRttDatagramWithInstalledKeysOrCloseAndDrainShortDatagrams`、
`processRoutedProtectedZeroRttDatagramWithInstalledKeysAndPollShortDatagram`、
`processRoutedProtectedZeroRttDatagramWithInstalledKeysAndDrainShortDatagrams`、
`processRoutedProtectedZeroRttDatagramWithInstalledKeysOrCloseAndPollShortDatagram`、
`processRoutedProtectedZeroRttDatagramWithInstalledKeysOrCloseAndDrainShortDatagrams`、
`processProtectedShortDatagramAndPollDatagram`、
`processProtectedShortDatagramOrCloseAndPollDatagram`、
`processRoutedProtectedShortDatagramAndPollDatagram`、
`processRoutedProtectedShortDatagramOrCloseAndPollDatagram`、
`processProtectedShortDatagramAndDrainDatagrams`、
`processProtectedShortDatagramOrCloseAndDrainDatagrams`、
`processRoutedProtectedShortDatagramAndDrainDatagrams`、
`processRoutedProtectedShortDatagramOrCloseAndDrainDatagrams`、
`processProtectedShortDatagramAndSelectNextDeadline`、
`processProtectedShortDatagramOrCloseAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramOrCloseAndSelectNextDeadline`、
`processProtectedShortDatagramWithKeyUpdateAndPollDatagram`、
`processProtectedShortDatagramWithKeyUpdateOrCloseAndPollDatagram`、
`processRoutedProtectedShortDatagramWithKeyUpdateAndPollDatagram`、
`processRoutedProtectedShortDatagramWithKeyUpdateOrCloseAndPollDatagram`、
`processProtectedShortDatagramWithKeyUpdateAndDrainDatagrams`、
`processProtectedShortDatagramWithKeyUpdateOrCloseAndDrainDatagrams`、
`processRoutedProtectedShortDatagramWithKeyUpdateAndDrainDatagrams`、
`processRoutedProtectedShortDatagramWithKeyUpdateOrCloseAndDrainDatagrams`、
`processProtectedShortDatagramWithKeyUpdateAndSelectNextDeadline`、
`processProtectedShortDatagramWithKeyUpdateOrCloseAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithKeyUpdateAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithKeyUpdateOrCloseAndSelectNextDeadline`、
`processProtectedShortDatagramWithKeyPhaseStateAndPollDatagram`、
`processProtectedShortDatagramWithKeyPhaseStateOrCloseAndPollDatagram`、
`processRoutedProtectedShortDatagramWithKeyPhaseStateAndPollDatagram`、
`processRoutedProtectedShortDatagramWithKeyPhaseStateOrCloseAndPollDatagram`、
`processProtectedShortDatagramWithKeyPhaseStateAndDrainDatagrams`、
`processProtectedShortDatagramWithKeyPhaseStateOrCloseAndDrainDatagrams`、
`processRoutedProtectedShortDatagramWithKeyPhaseStateAndDrainDatagrams`、
`processRoutedProtectedShortDatagramWithKeyPhaseStateOrCloseAndDrainDatagrams`、
`processProtectedShortDatagramWithKeyPhaseStateAndSelectNextDeadline`、
`processProtectedShortDatagramWithKeyPhaseStateOrCloseAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithKeyPhaseStateAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithKeyPhaseStateOrCloseAndSelectNextDeadline`、
`processProtectedShortDatagramWithInstalledKeysAndPollDatagram`、
`processProtectedShortDatagramWithInstalledKeysOrCloseAndPollDatagram`、
`processProtectedShortDatagramWithInstalledKeysAndDrainDatagrams`、
`processProtectedShortDatagramWithInstalledKeysAndDrainDatagramsWithInstalledKeyOptions`、
`processProtectedShortDatagramWithInstalledKeysOrCloseAndDrainDatagrams`、
`processProtectedShortDatagramWithInstalledKeysOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processProtectedShortDatagramWithInstalledKeysAndSelectNextDeadline`、
`processProtectedShortDatagramWithInstalledKeysOrCloseAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithInstalledKeysOrCloseAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDrainDatagramsWithInstalledKeyOptions`、
`processRoutedProtectedShortDatagramWithInstalledKeysOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndSelectNextDeadline`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagram`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagram`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagrams`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagrams`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`、
`processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`、
`processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagram`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWork`、`processPendingWorkAcrossConnections`、
`processPendingWorkAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndSelectNextDeadline`、`processPendingWorkAndPollDatagram`、
`processPendingWorkAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAcrossConnectionsAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAcrossConnectionsAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesAndSelectNextDeadline`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesAndPollDatagram`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesAndDrainDatagrams`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesOrCloseAndSelectNextDeadline`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesOrCloseAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesOrCloseAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesOrCloseAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesOrCloseAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesOrCloseAndPollDatagram`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesOrCloseAndDrainDatagrams`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesOrCloseAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesWithCompatibleVersionAndSelectNextDeadline`、
`processPendingWorkAndDriveCryptoBackendAcrossSpacesWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesWithCompatibleVersionAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagram`、
`processPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagrams`、
`processPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`、
`processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`、
`processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processPendingWorkAndDrainDatagrams`、
`processPendingWorkAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAndPollDatagram`、
`processDueDeadlineAndDrainDatagrams`、
`processDueDeadlineAndSelectNextDeadline`、
`processDueDeadlineAcrossConnectionsAndSelectNextDeadline`、
`processDueDeadlineAndDriveCryptoBackendInSpaceAndSelectNextDeadline`、
`processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesAndSelectNextDeadline`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesOrCloseAndSelectNextDeadline`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesAndPollDatagram`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesAndDrainDatagrams`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesOrCloseAndPollDatagram`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesOrCloseAndDrainDatagrams`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesOrCloseAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendInSpaceAndPollDatagram`、
`processDueDeadlineAndDriveCryptoBackendInSpaceAndDrainDatagrams`、
`processDueDeadlineAndDriveCryptoBackendInSpaceAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendInSpaceAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram`、
`processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams`、
`processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesWithCompatibleVersionAndSelectNextDeadline`、
`processDueDeadlineAndDriveCryptoBackendAcrossSpacesWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAcrossConnectionsAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndSelectNextDeadline`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesAndSelectNextDeadline`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesOrCloseAndSelectNextDeadline`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesOrCloseAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesOrCloseAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesOrCloseAndPollDatagramWithInstalledKeyOptions`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesWithCompatibleVersionAndSelectNextDeadline`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`pollDatagram`、`drainDatagramsAcrossConnections`、
`pollDatagramAcrossConnections`、`driveCryptoBackendsInSpaceAndArmConnections`、
`driveCryptoBackendsInSpaceAndSelectNextDeadline`、
`driveCryptoBackendInSpaceAndSelectNextDeadline`、
`driveCryptoBackendsInSpaceAndPollDatagram`、
`driveCryptoBackendInSpaceAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceAndDrainDatagrams`、
`driveCryptoBackendInSpaceAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceOrCloseAndArmConnections`、
`driveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline`、
`driveCryptoBackendInSpaceOrCloseAndSelectNextDeadline`、
`driveCryptoBackendsInSpaceOrCloseAndPollDatagram`、
`driveCryptoBackendInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceOrCloseAndDrainDatagrams`、
`driveCryptoBackendInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceWithCompatibleVersionAndArmConnections`、
`driveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`driveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionAndArmConnections`、
`driveCryptoBackendAcrossSpacesWithCompatibleVersionAndArmConnection`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionAndSelectNextDeadline`、
`driveCryptoBackendAcrossSpacesWithCompatibleVersionAndSelectNextDeadline`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionAndPollDatagram`、
`driveCryptoBackendAcrossSpacesWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionAndDrainDatagrams`、
`driveCryptoBackendAcrossSpacesWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram`、
`driveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams`、
`driveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndArmConnections`、
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionOrCloseAndArmConnections`、
`driveCryptoBackendAcrossSpacesWithCompatibleVersionOrCloseAndArmConnection`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`driveCryptoBackendAcrossSpacesWithCompatibleVersionOrCloseAndSelectNextDeadline`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionOrCloseAndPollDatagram`、
`driveCryptoBackendAcrossSpacesWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionOrCloseAndDrainDatagrams`、
`driveCryptoBackendAcrossSpacesWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsAcrossSpacesWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram`、
`driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams`、
`driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions`、
`driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions`、
`nextDeadline` 和
`nextDeadlineAcrossConnections`，
由同一个 lifecycle owner 驱动 timer、route cleanup、close、
installed-key packet receive、跨连接 receive dispatch、due-deadline service、
跨连接 pending-work sweep、跨连接 due-deadline dispatch、recovery-wakeup packet output、
installed-key packet output、caller-owned output queue 的 bounded drain、跨连接
output dispatch、cross-connection pending-work-to-output loop step、
receive-to-next-deadline loop step、
cross-connection pending-work-to-next-deadline loop step、
cross-connection pending-work-to-bounded-drain loop step、
cross-connection due-deadline-to-next-deadline loop step、receive-to-backend-to-output loop step、receive-to-backend-to-bounded-drain
loop step、receive-to-output loop step、receive-to-bounded-drain loop step、跨连接 TLS backend drive、
backend-drive-to-next-deadline loop step、
backend-drive-to-datagram output step、backend-drive-to-bounded-drain output step、
explicit key-update 1-RTT receive-to-output loop step、
explicit key-update 1-RTT receive-to-bounded-drain loop step、
caller-owned key-phase 1-RTT receive-to-output loop step、
caller-owned key-phase 1-RTT receive-to-bounded-drain loop step、
single-connection installed-key 1-RTT receive-to-output loop step、
single-connection installed-key 1-RTT receive-to-bounded-drain loop step、
backend-drive-to-caller-keyed long-header drain step、
close-propagating backend-drive-to-caller-keyed long-header drain step、
caller-keyed receive-to-backend-to-bounded-drain loop step、
caller-keyed receive-to-backend-close-to-bounded-drain loop step、
routed caller-keyed receive-to-backend-to-bounded-drain loop step、
routed caller-keyed receive-to-backend-close-to-bounded-drain loop step、
installed-key Handshake receive-to-backend-to-bounded-drain loop step、
close-propagating installed-key Handshake backend-drain loop step、
routed installed-key 1-RTT receive-to-output loop step、
routed installed-key 1-RTT receive-to-bounded-drain loop step、
single-connection installed-key receive-to-backend-to-output loop step、
single-connection installed-key receive-to-backend-to-bounded-drain loop step、
single-connection installed-key receive-to-backend-close-to-output loop step、
single-connection installed-key receive-to-backend-close-to-bounded-drain loop step、
single-connection compatible-version receive-to-backend-to-output loop step、
single-connection compatible-version receive-to-backend-close-to-output loop step、
single-connection pending-work-to-backend-to-output loop step、
single-connection pending-work-to-backend-to-bounded-drain loop step、
single-connection pending-work-to-backend-close-to-output loop step、
single-connection pending-work-to-backend-close-to-bounded-drain loop step、
single-connection compatible-version pending-work-to-backend-to-output loop step、
single-connection compatible-version pending-work-to-backend-close-to-output loop step、
single-connection due-deadline-to-backend-to-output loop step、
single-connection due-deadline-to-backend-close-to-output loop step、
single-connection compatible-version due-deadline-to-backend-to-output loop step、
single-connection compatible-version due-deadline-to-backend-close-to-output loop step、
single-connection due-deadline-to-backend-to-bounded-drain loop step、
single-connection due-deadline-to-backend-close-to-bounded-drain loop step、
pending-work-to-bounded-drain loop step、pending-work-to-backend-to-output loop step、due-deadline-to-backend-to-output loop
step、pending-work-to-backend-to-bounded-drain loop step、due-deadline-to-backend-to-bounded-drain
loop step、due-deadline-to-bounded-drain loop step、routed installed-key 1-RTT
receive-to-bounded-drain loop step、
cross-connection due-deadline terminal-cleanup backend suppression、
close-propagating TLS backend drive、RFC 9368 compatible-version backend sweep，
以及 caller-owned connection map 上的 event-loop wakeup selection。
`EndpointConnectionDeadline.installedKeyPollOptions()` 会把
`nextDeadline()` 返回的 recovery wakeup 映射为 Handshake 和 1-RTT 路径的
installed-key poll options。生产级 socket 策略、完整 TLS-owned handshake driving 和
live key lifecycle 仍待实现。第一版互通入口只承接
`handshake` 和 `transfer`；真实 TLS-owned 二进制不存在时必须返回明确 blocker，不得伪装成功。
真实 TLS 和互通路径还需要同步输出可排障证据，包括 keylog，以及 handshake、transport
parameter、traffic-secret installation、packet number space、ACK/loss/PTO、key discard、
close 和 route cleanup 事件。

后续 mock-only loopback 只有在补齐下方矩阵中的明确缺口时才计入进展。若缺口没有
命名，且验证证据没有写回本文，不应把新增 mock 示例视为完成 QUIC 的进展。

## 任务矩阵

| 领域 | 当前状态 | 目标结果 | 验证方式 |
| --- | --- | --- | --- |
| 标准追踪 | 已有核心/延后 RFC 覆盖状态表 | 随实现推进，持续把每个核心 RFC 领域标记为 done、partial、missing 或 deferred。 | Markdown review 加 `zig build test`。 |
| RFC 8999 / 9000 packet codec | 部分完成，已具备 v2 type-bit 感知、endpoint unsupported-version VN response helper 和 client-side VN selection/follow-up route and connection handoff state | 完成版本无关 packet、version negotiation、Retry、long/short header、packet number 与 transport error 值。 | 现有测试覆盖 v1/v2 long-header packet type bit 映射、Retry codec 映射、reserved-version greasing detection/selection skip、Version Negotiation response 的 CID echo、client-side VN CID validation、Original Version ignore、mutual-version selection、follow-up config derivation、follow-up Initial route registration、follow-up connection handoff、首个 client Initial DCID 长度校验、server Initial token 拒绝、Initial UDP datagram 1200 字节扩展/丢弃检查、roundtrip、边界值、截断、非法值和分配失败；`run-codec` 输出 reserved-version skip 证据，`run-udp-endpoint-loopback` 证明 Version Negotiation、client-side VN selection、lifecycle-owned follow-up route replacement and connection handoff 与 Initial classification 的 socket-backed endpoint routing。 |
| RFC 9000 frame codec | frame 集合已覆盖 + frame type 最短 varint 校验 + ACK/ACK_ECN range 校验和显式 close 传播 + 未知类型拒绝 + 包含 0-RTT ACK/ACK_ECN 拒绝的 packet-type 校验 + ACK/ACK_ECN 确认未发送 packet 拒绝、MAX_STREAMS/STREAMS_BLOCKED count overflow、STREAM/RESET_STREAM/PATH_RESPONSE、冲突 STREAM data、STOP_SENDING/MAX_STREAM_DATA/STREAM_DATA_BLOCKED stream-control 校验、NEW_CONNECTION_ID limit/reuse、RETIRE_CONNECTION_ID unknown/unsent 和 role-specific NEW_TOKEN/HANDSHAKE_DONE 语义 close 分类和显式 close 传播 | 覆盖所有 RFC 9000 transport frame，并统一严格校验和错误映射。 | 每类 frame 的合法、截断、非法、未知输入编解码测试，以及会计算出负 packet number 的 ACK/ACK_ECN range；connection-level ACK/ACK_ECN 处理会在 recovery 副作用前拒绝同类 invalid range；`frameDecodeErrorCode()` 将畸形 frame decode 失败映射为 `FRAME_ENCODING_ERROR`；`framePacketTypeErrorCode()` 将语法合法但出现在禁止 packet type 中的 frame 映射为 `PROTOCOL_VIOLATION`；`processDatagramOrClose()`、`processDatagramInSpaceOrClose()`、`processDatagramForPacketTypeOrClose()` 和 protected long/short `*OrClose` receive wrapper（含 direct/routed `EndpointConnectionLifecycle` 变体）会为已分类 frame-payload 错误排队 CONNECTION_CLOSE，旧 receive API 继续保持只回滚不关闭的行为；测试覆盖非法 ACK/ACK_ECN range close 传播、0-RTT ACK/ACK_ECN packet-type close 传播、ACK/ACK_ECN 确认从未发送 packet、flow-control、MAX_STREAMS/STREAMS_BLOCKED overflow、stream-limit、stream-control stream-state 与 stream-count 失败、final-size、冲突 STREAM data、未匹配 PATH_RESPONSE、active connection-ID limit overflow、`retire_prior_to` 下的合法 replacement、重复 NEW_CONNECTION_ID 幂等保留、NEW_CONNECTION_ID sequence/CID mismatch、跨 sequence 的 CID reuse 拒绝、reset-token reuse、RETIRE_CONNECTION_ID unknown/unsent close 传播、已发送 CID retire accept、server 收到 NEW_TOKEN 和 server 收到 HANDSHAKE_DONE 的语义 close 传播。 |
| Transport parameters | 类型化 codec + reserved-parameter greasing helper/ignore + 连接层暴露 + preferred_address 导出/应用 + RFC 9368 `version_information` 导出/应用校验（含 VN-triggered server downgrade checks、server-side compatible Version Information apply/byte 路径、peer Version Information snapshot，以及已解析 version-negotiation 语义失败到 `VERSION_NEGOTIATION_ERROR` 的 close 分类） + TLS extension byte 编码/应用 + CryptoBackend byte handoff 以及带 selected-version progress reporting 的 strict、compatible、close-propagating peer-parameter drive + 与 peer recovery policy 分离的本端 ACK delay 导出 + peer max_udp_payload_size recovery resync + codec error 分类和显式 close 传播到 `TRANSPORT_PARAMETER_ERROR` | 把已导出的参数完整接入 TLS backend transcript handshake，并补齐完整 version-negotiation 状态 ownership。 | 现有 roundtrip、reserved/unknown parameter ignore、重复/非法参数、连接层应用/导出、TLS extension byte 编码/应用、mock-backend 本端/对端 byte handoff、server preferred_address、`version_information`、VN-triggered downgrade checks、compatible-version selection apply、peer Version Information snapshot、默认值、本端/对端 ACK delay 分离、max_udp_payload_size-driven recovery resync，以及 `transportParameterErrorCode()` 测试覆盖 codec 与连接层表面；`applyPeerTransportParameterBytesOrClose()` 与 `driveCryptoBackendInSpaceOrClose()` 测试覆盖畸形 extension、非法对端参数 close emission 和已解析 RFC 9368 version-negotiation 语义 close emission，旧 apply/drive API 继续保持只回滚行为；`driveCryptoBackendInSpaceWithCompatibleVersion*()` 测试覆盖 backend-driven compatible Version Information selection、selected-version progress reporting，以及拉取 backend output 前的 close emission；`run-transport-parameters` 打印 reserved-parameter ignore、compatible-version selection、peer Version Information snapshot、recovery datagram-size/cwnd 和 transport-parameter auto-close 证据；`run-crypto-stream` 从 backend progress 打印 protected backend transport-parameter auto-close 和 compatible Version Information handoff 证据；`run-codec` 打印 transport-parameter close-code 分类和 `downgrade_close=0x11`；后续真实 TLS backend 和 endpoint 测试证明 transcript 集成与完整版本协商。 |
| 连接状态机 | 部分 close-state + peer close 诊断 + idle timeout + 显式 handshake progress 状态 + stateless reset receive-to-draining 状态 | 建模 Initial、Handshake、0-RTT、1-RTT、idle timeout、closing、draining、closed 状态。 | 现有测试覆盖 close/drain 迁移、stateless reset token 命中后进入 draining 且不记录 peer close 诊断、不保留 pending close output、closing/draining 入站 datagram 不解析丢弃、peer close 诊断、close 过期、idle 过期、idle/close timeout 到期后的 endpoint lifecycle route/timer 清理、Initial 到 Handshake 到 Confirmed 的 handshake progress，以及非法 packet 回滚；`run-udp-close-lifecycle-loopback` 会打印 socket-backed protected close/drain state、close-deadline 证据和 timeout-driven route cleanup 证据；后续 protected-packet 测试覆盖 key-state 迁移。 |
| Packet number spaces | 部分 frame-payload ACK/recovery + CRYPTO 隔离和接收重组 + 带 caller-keyed Initial/Handshake CONNECTION_CLOSE emission、installed-key Handshake CONNECTION_CLOSE emission、首个 client Initial DCID 长度、server Initial token 校验和 RFC 9000 Initial UDP datagram size 检查的 Initial/Handshake protected CRYPTO/ACK/PING/CONNECTION_CLOSE coalesced send/receive bridge + 使用调用方 key 或连接已安装 key 的 0-RTT protected long STREAM/RESET_STREAM/STOP_SENDING 路由 + 1-RTT protected short PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge + frame-type filtering + RFC 9001 client 发送 Handshake / server 接收 Handshake 后的 Initial discard + 会清理已安装 Handshake key 和 ECN 状态的 discard cleanup + 有效 client 侧 HANDSHAKE_DONE、server 侧 sendHandshakeDone、backend-confirmed no-output 以及 backend-confirmed post-final-outbound-CRYPTO 触发的 Handshake-space discard | 维护独立 Initial、Handshake、Application packet number space，并在后续把 protected packet 路由到匹配空间且遵守剩余 TLS 触发的 key discard 规则。 | 现有 ACK/recovery、CRYPTO 隔离、乱序 CRYPTO 接收、Initial/Handshake protected send/receive（含首个 client Initial DCID 拒绝、server Initial token 拒绝、caller-keyed Initial/Handshake 和 installed-key Handshake close emission、Initial UDP datagram 1200 字节扩展/丢弃检查）、coalesced send/receive、使用调用方 key 和连接已安装 key 的 0-RTT protected STREAM/RESET_STREAM/STOP_SENDING、1-RTT protected PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive、forbidden-frame、RFC 9001 Initial discard、显式 discard、installed Handshake key cleanup、ECN state cleanup 与有效 HANDSHAKE_DONE/backend-confirmed cleanup 测试证明空间隔离和清理；后续 protected endpoint 测试证明完整路由正确。 |
| 真实 datagram API | 带首个 client Initial DCID 长度、server Initial token 校验和 RFC 9000 Initial UDP datagram size 检查的 Initial/Handshake protected CRYPTO/ACK/PING/CONNECTION_CLOSE coalesced send/receive bridge + lifecycle-owned caller-keyed protected Initial/1-RTT short socket loopback + 使用调用方 key 或连接已安装 key 的 0-RTT protected long STREAM/RESET_STREAM/STOP_SENDING 路由 + protected 1-RTT short PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive bridge + 调用方持有和 ACK-gated installed-key key-phase 状态 1-RTT short-packet bridge + 可配置单路径 spin-bit policy + protected long/short-packet helper + 内存态 endpoint DCID/IPv4 四元组 router + VN/protected follow-up Initial/Initial/short-header classification 的 socket-backed endpoint routing loopback + socket-backed zero-length CID tuple-routing loopback + socket-backed preferred-address route-migration loopback + socket-backed replacement-CID route-retirement loopback + socket-backed lifecycle connection-ID NEW/RETIRE loopback + socket-backed lifecycle flow-control credit-refresh loopback + socket-backed ECN ACK_ECN validation/CE response loopback + socket-backed lifecycle loss-recovery loopback + socket-backed lifecycle congestion-recovery loopback + socket-backed lifecycle PTO recovery loopback + socket-backed lifecycle STREAM retransmission loopback + socket-backed lifecycle installed-key key-update loopback + socket-backed path-validation route-update loopback + socket-backed lifecycle Retry/address-validation loopback + socket-backed close-triggered route retirement + zero-length CID tuple routing + sequence/retire-prior-to route retirement + endpoint reset-token uniqueness checks + caller-validated path update + retired-CID stateless reset token lookup/datagram construction + socket-backed retired-CID stateless reset emission loopback + route/reset/drop receive classification | 在当前 frame-payload 骨架之上增加受保护 QUIC datagram 收发 API。 | 现有 helper 测试覆盖受保护 Initial packet、protected short-packet roundtrip、key-phase short-packet selection、protected long-packet boundary peeking、endpoint DCID routing（含 zero-length CID tuple routing、sequence/retire-prior-to route retirement、endpoint reset-token reuse rejection 和 caller-validated path update）、route retirement 后的 stateless reset token lookup/datagram construction，以及 endpoint receive action classification；`examples/udp_endpoint_loopback.zig` 覆盖真实 loopback UDP Version Negotiation response delivery、protected follow-up Initial emission/server processing、supported Initial accept、client Initial SCID response routing 和 server Initial SCID short-header routing；`examples/udp_zero_cid_loopback.zig` 覆盖真实 loopback UDP 上 short/long datagram 按 zero-length destination CID 的本地/远端 tuple 路由、按 path 退役，以及 route path update；`examples/udp_preferred_address_loopback.zig` 覆盖真实 loopback UDP preferred-address migration commit、当前 route 退役、preferred CID 在 preferred server address 上路由、active-migration-disabled policy 对 stray path 的拒绝，以及退役后的 reset-token lookup；`examples/udp_replacement_cid_loopback.zig` 覆盖真实 loopback UDP replacement-CID registration with `retire_prior_to`、retired sequence route 的 inactive reset-token lookup、active replacement CID routing、invalid sequence rejection，以及 stray path 上 active-migration-disabled rejection；`examples/udp_connection_ids_loopback.zig` 覆盖真实 loopback UDP lifecycle-routed protected NEW_CONNECTION_ID delivery、通过 lifecycle owner 更新新签发 CID 的 endpoint replacement route、inactive old-CID reset-token lookup、lifecycle-routed protected RETIRE_CONNECTION_ID 经 active replacement CID 路由、server-side local CID retirement 和 lifecycle-routed ACK cleanup；`examples/udp_flow_control_loopback.zig` 覆盖真实 loopback UDP lifecycle-owned protected STREAM delivery 到 receive limit、protected STREAM_DATA_BLOCKED routing、接收侧 MAX_DATA/MAX_STREAM_DATA credit refresh delivery、resumed STREAM data 和 final ACK cleanup；`examples/udp_ecn_validation_loopback.zig` 覆盖真实 loopback UDP 投递建模 ECT(0) protected PING、protected ACK_ECN validation、ACK_ECN CE 驱动的 NewReno recovery 响应、当前 UDP tuple 的 endpoint ECN state update，以及迁移路径 ECN 隔离；该示例不声称真实 IP-header ECN marking；`examples/udp_loss_recovery_loopback.zig` 覆盖真实 loopback UDP protected short PING delivery，随后用 protected ACK 驱动 packet-threshold loss，并用 lifecycle timer 驱动 time-threshold cleanup 和最终 timer disarm；`examples/udp_congestion_recovery_loopback.zig` 覆盖真实 loopback UDP lifecycle-owned protected short PING/ACK routing，随后验证 NewReno recovery-period 对重复 loss reduction 的抑制，以及 persistent congestion 把 congestion window 降到 minimum window；`examples/udp_pto_recovery_loopback.zig` 覆盖真实 loopback UDP lifecycle timer 驱动的 ACK loss 后 PTO、protected PING fallback probe delivery、queued STREAM data 和 in-flight STREAM/CRYPTO data 作为 PTO probe、重复 receive/CRYPTO range 丢弃、ACK cleanup 和最终 timer disarm；`examples/udp_stream_retransmission_loopback.zig` 覆盖 lifecycle-owned route selection 下 ACK 驱动的 1-RTT STREAM retransmission 和 final ACK cleanup；`examples/udp_key_update_loopback.zig` 覆盖真实 loopback UDP lifecycle-owned installed-key key update initiation、next key-phase packet routing、authenticated receive 后 peer key-phase advancement、ACK delivery、key-update ACK gating 和 second-update re-enable；`examples/udp_protected_loopback.zig` 覆盖 lifecycle-owned 真实 loopback UDP protected client Initial route registration、protected server Initial routing、routed client 1-RTT PING 和 routed server 1-RTT ACK；`examples/udp_path_validation_loopback.zig` 覆盖真实 loopback UDP PATH_CHALLENGE 投递到新的对端端口、PATH_RESPONSE 以 `path_changed` 路由、验证后由 lifecycle helper 提交 route path update，以及新路径上的 confirmed routing；`examples/udp_retry_loopback.zig` 覆盖 lifecycle-owned 真实 loopback UDP Retry delivery、Retry Source CID route switching、address-bound Retry token validation、replay rejection、follow-up protected Initial routing 和 Retry transport-parameter checks；`examples/udp_close_lifecycle_loopback.zig` 覆盖 UDP 上的 protected close delivery、connection-handle route retirement、保留的 inactive-CID reset-token lookup、reset emission 和 client token matching；`examples/udp_stateless_reset_loopback.zig` 覆盖真实 loopback UDP reset trigger 接收分类、server reset 发出和 client token 匹配；连接层测试覆盖 protected Initial/Handshake CRYPTO、protected Initial/Handshake CONNECTION_CLOSE、首个 client Initial DCID 拒绝、server Initial token 拒绝、Initial UDP datagram 1200 字节扩展/丢弃检查、ACK-only、PING、使用调用方 key 和连接已安装 key 的 0-RTT STREAM/RESET_STREAM/STOP_SENDING、coalesced send/receive、protected 1-RTT PING/ACK/CRYPTO/HANDSHAKE_DONE/NEW_TOKEN/NEW_CONNECTION_ID/PATH_CHALLENGE/PATH_RESPONSE/RETIRE_CONNECTION_ID/MAX_*/BLOCKED/STREAM/RESET_STREAM/STOP_SENDING/CONNECTION_CLOSE transmit/receive、installed-key short PING/ACK exchange、installed-key ACK-gated key-update 发起、key-phase 状态版 PING receive 与失败状态保持，以及 enabled/disabled spin-bit 状态更新和 invalid-packet 状态保持；后续 socket-backed client/server loopback 必须使用 TLS-owned keys 和 endpoint lifecycle ownership。 |
| TLS 集成 | 已有带 per-space 乱序接收缓冲和接收缓冲超限 close 传播的 CRYPTO bridge hook、可插拔 backend drive helper、transport-parameter byte handoff、strict/compatible/protected close-propagating peer-parameter drive、selected compatible-version progress reporting、mock Handshake/0-RTT/1-RTT traffic-secret handoff、C-ABI `TlsBackend` 到 `CryptoBackend` adapter、backend-confirmed no-output 和 post-final-outbound-CRYPTO Handshake discard、socket-backed mock CryptoBackend Handshake CRYPTO stream loopback、显式 installed-key 0-RTT accept/reject、建模 1-RTT 边界的 0-RTT discard、OpenSSL callback-mode transcript 证据（含复制并解析按角色区分的 peer transport-parameter bytes，以及手动 Initial/Handshake transcript、同一 context 的 1-RTT STREAM echo、Handshake key discard、protected close 和 route cleanup 通过 socket/lifecycle 路由）和 OpenSSL-backed adapter wrapper 证据；缺少完整 endpoint-owned live TLS handshake/socket loop | 使用可插拔 TLS 后端接口，由 CRYPTO frame 驱动握手，并把具体 C TLS 库绑定保持在 transport core 外部。 | 现有 mock-backend 和 `TlsBackend` adapter 测试覆盖 CRYPTO 投递、CRYPTO 接收缓冲超限拒绝和 close emission、本端/对端 transport-parameter byte handoff、带 selected-version progress 的 compatible backend Version Information handoff、C-ABI status-code/output-buffer 到 `driveCryptoBackendInSpace()` 的适配、backend 输出排队和保留、无效 peer transport-parameter 不拉取输出的拒绝路径、无效 peer transport-parameter 不拉取输出的 close emission、installed-key protected Handshake CONNECTION_CLOSE emission、Handshake、0-RTT 与 1-RTT traffic-secret 安装、handshake confirmation、backend-confirmed no-output 和 post-final-outbound-CRYPTO Handshake discard、installed-key 0-RTT accept 前拒绝、accept 后接收 0-RTT、reject 后丢弃 key、client 安装 1-RTT key 后清理 0-RTT、server 接受 1-RTT receive 后清理 0-RTT 和 scratch-buffer 边界；`run-udp-crypto-stream-loopback` 覆盖 socket-backed mock `CryptoBackend` Handshake key 安装、transport-parameter byte handoff、protected Handshake CRYPTO flight delivery、backend receive/output 和 routed ACK cleanup；`run-crypto-stream` 覆盖 CRYPTO buffer-limit close、protected close-propagating backend transport-parameter error 和 compatible backend Version Information handoff；`run-tls-openssl-pair-transcript` 和 `run-tls-openssl-backend-adapter` 覆盖当前 OpenSSL callback-mode transcript、已消费的 pair-transcript server transport parameters、keylog 可观测性、traffic-secret handoff、protected loopback UDP 投递、direct server-probe Handshake consumption/confirmation 证据、server connection backend 1-RTT pull、OpenSSL secret callback、peer stream-count limit enforcement、confirmation 与 discard 证据、paired loopback server backend-consumed Handshake CRYPTO 与确认清理证据、Application PTO、key discard、close 和 route cleanup 证据；完整 live endpoint-owned TLS loop 和互通仍用于证明完整集成。 |
| Packet protection | 部分 v1/v2 Initial keys + 按配置使用 v2 protected long-packet wire-version/type-bit + AES-GCM payload/header protection + protected long/short-packet helper + caller-keyed protected UDP loopback + socket-backed lifecycle installed-key key-update loopback + unprotected spin-bit peek + v1/v2 Retry Integrity Tag helper + `quic ku` key-update 派生 + 连接已安装 Handshake 和 0-RTT long-packet key + 显式 installed-key 0-RTT accept/reject + RFC 9001 Handshake send/receive 边界的 Initial discard + 显式 installed Handshake/0-RTT key discard hook + client 侧 HANDSHAKE_DONE、server 侧 sendHandshakeDone、backend-confirmed no-output 与 backend-confirmed post-final-outbound-CRYPTO 触发的 Handshake key discard + 建模 1-RTT 边界触发的 client/server 0-RTT key discard + 调用方持有和连接已安装的 1-RTT key-phase 状态 helper、ACK-gated installed-key update 发起与显式 short-packet key-phase 收发 | 实现真实 TLS-backed early-data secret ownership、真实 TLS Handshake/1-RTT secret production、header protection、AEAD、剩余 TLS 触发的 Handshake key discard、完整 TLS 0-RTT acceptance/replay policy、完整 TLS-owned live key-update 调度/old-key discard，以及 configured Initial/long-packet/Retry primitive 之外的剩余 RFC 9369 packet protection 行为。 | 现有 RFC 向量和固定向量测试覆盖 v1 与 v2 Initial 派生、按配置发出 v2 protected Initial wire-version/type-bit 且 v1 连接会拒绝 v2 Initial、header protection、AEAD protection、protected packet、v1 与 v2 Retry Integrity Tag、spin-bit peeking、`quic ku` key-update 派生、调用方持有 key-phase 状态迁移、调用方 key 的 key-phase packet selection、mock Handshake/0-RTT/1-RTT traffic-secret 安装、Handshake send/receive 后 RFC 9001 Initial discard、installed-key Handshake long-packet exchange、caller-keyed Initial/Handshake 和 installed-key Handshake close emission、installed-key 0-RTT long-packet exchange、installed-key 0-RTT accept 前拒绝、accept 后接收 0-RTT、reject 后丢弃 key、显式 installed-key discard cleanup、有效 HANDSHAKE_DONE 和 backend-confirmed no-output/post-final-outbound-CRYPTO cleanup、client 安装 1-RTT key 后 0-RTT cleanup、server 1-RTT receive 失败保留和成功 cleanup、installed-key short-packet exchange、installed-key key-phase 成功接收后推进、handshake confirmation 前拒绝 installed-key key-update、ACK-gated repeat rejection、ACK 后重新允许、invalid-payload rollback、`run-udp-protected-loopback` socket delivery、`run-initial-keys` configured v2 Initial packetization 证据，以及 `run-udp-key-update-loopback` 通过真实 loopback UDP socket 证明 lifecycle-owned installed-key key update；后续 TLS/endpoint 测试覆盖真实 traffic-secret 使用、剩余自动 Handshake key discard 和完整 TLS-owned live key-update 调度。 |
| Spin bit | 可配置单路径 short-header spin-bit state + protected spin-bit peek + lifecycle-owned route-update spin-bit reset + socket-backed UDP lifecycle spin-bit route-update loopback | 保持默认禁用行为，并在后续把多路径 spin-bit 实例绑定到完整 endpoint path lifecycle。 | 现有测试覆盖 enabled/disabled spin-bit 更新、invalid-packet 状态保持，以及 committed route path update 后由 lifecycle 重置 spin bit；`run-udp-spin-bit-loopback` 证明真实 loopback UDP socket 上 lifecycle-routed 第一轮 false-spin PING/ACK receive path、迁移端口上的 lifecycle-routed 第二轮 true-spin PING 以 `path_changed` 路由、lifecycle route update 后 spin reset、reset ACK spin 和 ACK cleanup。 |
| Streams | 部分接收重组与重复重传丢弃 + FIN completion + 本地 reset/stop 可观测 + 公开 `StreamState` 快照（含 Data Read/Reset Read 接收状态和 Data Acked/Reset Acked 发送状态）+ 隐式低编号接收 stream 创建 + pre-STREAM peer-bidirectional STOP_SENDING 处理 | 在当前内存态重组骨架之外继续完成 stream 状态机、FIN/reset 规则和读写行为。 | 双向、单向、FIN、reset、STOP_SENDING、stream 状态快照、乱序、重复重传、冲突重叠、回滚、final-size 测试。 |
| Flow control | 部分 receive MAX 与 stream-count 刷新 + MAX_STREAMS overflow 拒绝 + 可配置 receive data/stream-count window + BLOCKED 可观测/重发/增长 + 隐式低编号接收 stream 创建 + STREAM_DATA_BLOCKED 接收状态校验 + pre-STREAM peer-bidirectional MAX_STREAM_DATA 处理 + protected short-packet 与 socket-backed UDP credit-refresh exchange | 完成剩余自适应 MAX/BLOCKED 策略响应。 | connection、stream 与 stream-count 级 blocked/unblocked 测试，包含 MAX_STREAMS > 2^60 拒绝、目标 receive-window 刷新、peer-BLOCKED 增长、stream-count-window 增长、接收侧 stream-state 校验、调用方 key protected short-packet flow-control exchange，以及 `run-udp-flow-control-loopback` 对 STREAM/STREAM_DATA_BLOCKED/MAX_DATA/MAX_STREAM_DATA/resumed STREAM/final ACK 的 lifecycle-routed socket delivery。 |
| Connection IDs | 部分本端/对端生命周期 + stateless-reset-token uniqueness checks + endpoint sequence/retire-prior-to DCID route table + lifecycle-owned endpoint issue/register replacement-CID helper + connection-handle route retirement + socket-backed replacement-CID route-retirement loopback + socket-backed lifecycle connection-ID NEW/RETIRE loopback | 增加围绕 DCID routing 和 replacement policy 的完整 socket-owned connection lifecycle 集成。 | 现有测试覆盖本端 NEW_CONNECTION_ID 签发、带 retire_prior_to 感知 peer active-CID-limit 的 replacement、对端 RETIRE 处理、对端签发 NEW_CONNECTION_ID 生命周期、receive-path duplicate CID/token 拒绝、limit、回滚、endpoint route 注册、endpoint reset-token reuse rejection、带 retire_prior_to 应用的 endpoint 与 lifecycle-owned issue/register replacement-CID route update、按 CID、sequence number、retire_prior_to threshold 或 connection handle 的 route retirement，以及 unknown/ambiguous CID 拒绝；`run-udp-replacement-cid-loopback` 证明真实 loopback UDP socket 上的 replacement route registration、retire_prior_to retirement、inactive reset-token lookup、active replacement routing、invalid sequence rejection 和 active-migration-disabled rejection；`run-udp-connection-ids-loopback` 证明真实 loopback UDP socket 上的 protected NEW_CONNECTION_ID delivery、lifecycle issue/register route installation、active replacement CID route probing、protected RETIRE_CONNECTION_ID 经 active replacement CID 路由、server local-CID retirement、inactive reset-token lookup 和 ACK cleanup；后续 endpoint 测试覆盖完整 socket-owned connection lifecycle 集成。 |
| Tokens and Retry | 部分 codec + v1/v2 Retry Integrity Tag helper + 按配置使用 v2 server Retry datagram issuance 和 client Retry processing + server 侧 NEW_TOKEN 签发 + client 侧 NEW_TOKEN 存储 + 建模的 server anti-amplification 发送限制 + HMAC-SHA256 地址绑定、带过期时间并绑定 originating version 的 token 生成/校验 + endpoint IPv4 peer-address token binding + 带轮换 secret、secret-set 导出/恢复、replay-filter snapshot 导出/恢复和 replay 拒绝的内存态 endpoint 地址验证策略 + lifecycle-owned token validation，可解除 server connection 的地址验证限制并刷新 endpoint recovery scheduling + lifecycle-owned 一次性 Retry token 校验/消费 + server 侧 Retry datagram 签发 + 客户端侧 Retry datagram 处理与 handshake CID transport-parameter 校验/导出 + socket-backed UDP lifecycle Retry/address-validation loopback | 围绕已导出的 secret/replay snapshot 增加生产级 endpoint token secret 存储/分发，并接入 socket-owned endpoint lifecycle。 | 现有测试覆盖 Retry packet codec、RFC 9001 与 RFC 9369 Retry Integrity Tag 向量、按配置执行 v2 Retry issue/process/token reuse、protected NEW_TOKEN 签发/存储、建模的 3x anti-amplification 限制、HMAC 地址 token 的类型/地址/篡改/过期/version mismatch 检查、endpoint remote IPv4/port token binding、内存态 endpoint secret 轮换、secret-set 导出/恢复及保留数裁剪、replay-filter snapshot 导出/恢复及保留数裁剪、有界 replay-filter 的重复和容量行为、验证后记录 replay 指纹、lifecycle-owned path-token validation unblock/timer refresh、lifecycle-owned Retry path-token 校验和一次性 token 消费、server 侧 Retry datagram 签发、客户端侧 Retry datagram 处理、`initial_source_connection_id`、`original_destination_connection_id` 与 `retry_source_connection_id` 校验/导出；`run-address-validation` 和 `run-udp-address-validation-loopback` 证明 lifecycle-owned NEW_TOKEN validation 会解除后续 server 发送限制；`run-retry-token` 和 `run-udp-retry-loopback` 证明 lifecycle-owned Retry token validation、replay rejection、token 消费和通过 TLS extension bytes 执行 Retry CID transport-parameter validation；后续 endpoint 测试覆盖生产级 secret/replay 存储集成。 |
| Path validation | 部分 timeout/retry + 重复 pending PATH_RESPONSE 抑制 + 带 anti-amplification fallback 的 1200 字节 protected exchange + `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramAndUpdatePath*()` 只在 authenticated PATH_RESPONSE validation 消费 outstanding challenge 后提交 route update，且提供 close-propagating `OrClose` 变体 + socket-backed UDP lifecycle path-validation route-update loopback | 继续覆盖剩余完整 socket-owned endpoint path identity 场景。 | 现有测试覆盖匹配、重复 challenge 抑制、重复/不匹配 response、回滚、超时重试、重试耗尽、protected PATH_CHALLENGE/PATH_RESPONSE datagram 扩展、anti-amplification fallback、protected PATH_RESPONSE 验证后的 endpoint route path update、lifecycle-owned caller-validated route path update、validation-driven lifecycle route path update，以及认证后 frame 错误 close 传播且不提交 route update；`run-path-validation` 打印 protected datagram 大小和 lifecycle update 结果，`run-udp-path-validation-loopback` 证明同一带 close-propagating receive 的验证驱动 lifecycle route-update 流程可在 loopback UDP socket 和新对端端口上运行，并覆盖验证前 protected PING 只报告 `path_changed` 但不提交 endpoint route update 的路径。 |
| Stateless reset | 部分 helper + constant-time token match + 连接层检测 + 连接层 reset receive-to-draining 状态 + NEW_CONNECTION_ID token uniqueness checks + endpoint inactive-CID reset datagram construction + 通过 `EndpointConnectionLifecycle` 暴露的 route/reset/drop receive classification + socket-backed UDP reset emission loopback + socket-backed close-triggered lifecycle route retirement/reset loopback | 把 reset emission 接入 socket 拥有的 endpoint lifecycle 和 connection close/drop policy。 | 现有测试覆盖 reset token 命中、误判拒绝、短 datagram 拒绝、跨 CID duplicate-token 拒绝、retired token 忽略、active token receive 使连接进入 draining、reset receive 后抑制 pending close output、active route token 抑制、retired route token lookup、inactive-route reset datagram construction、smaller-than-trigger sizing、route/reset/drop receive action classification、lifecycle-owned route/reset/drop after timer-disarming retirement、server endpoint route-bound active reset 上报及 close-deadline record/route cleanup、server endpoint inactive-reset response path pairing，以及 ambiguous reset-token CID 拒绝；`run-stateless-reset` 演示 endpoint inactive-CID reset action；`run-udp-stateless-reset-loopback` 演示真实 UDP active-route suppression、unknown-CID drop classification、退役后的 trigger 投递、reset 发出和客户端 token 匹配；`run-udp-close-lifecycle-loopback` 演示 protected close delivery、lifecycle-routed protected receive auto-close、`EndpointConnectionLifecycle` connection-handle route retirement、保留 reset token lookup、reset emission 和 client token matching；后续 endpoint 测试覆盖完整 TLS-owned lifecycle 集成。 |
| ECN validation | 部分 frame-payload ACK_ECN 校验 + ACK_ECN CE 驱动的 NewReno recovery 响应 + lifecycle-owned endpoint UDP-path ECN state policy + socket-backed UDP lifecycle ACK_ECN validation/CE response loopback | 等 socket packetization 暴露 packet ECN mark 后，把 ECN validation 绑定到真实 IP ECN 标记。 | 现有测试覆盖 ECT(0) 成功、CE counter 拥塞响应、NewReno recovery period 内重复 CE 抑制、缺少 ACK_ECN 失败、counter 不足、counter 总量超过已发送 ECT packet、reordered ACK 处理、回滚、endpoint path-identity state isolation，以及 connection ECN validation state 到 UDP path identity 的 lifecycle-owned mirroring；`run-udp-ecn-validation-loopback` 覆盖 lifecycle-routed modeled ECT(0) protected PING delivery、lifecycle-routed protected ACK_ECN 成功、lifecycle-routed ECN-CE ACK_ECN 拥塞响应、当前 UDP tuple 的 `EndpointConnectionLifecycle` ECN state update，以及不声称真实 IP-header ECN marking 的迁移路径隔离。 |
| RFC 9002 recovery | 部分 largest-acknowledged RTT sampling + 跨 packet number space 的 connection-level RTT 估计共享与 PTO backoff（含 client Initial ACK reset suppression） + Initial/Handshake RTT ACK-delay suppression + Application ACK delay scaling/capping + packet/time-threshold loss + 带 closing/draining disarm、anti-amplification-limited server PTO disarm/rearm、新 datagram 解除发送阻塞时的 expired-PTO service 和 client no-in-flight anti-deadlock PTO 的 aggregate loss-time-before-PTO timer deadline selection/service + endpoint-owned 多连接 recovery timer scheduling + 跨 packet number space bytes-in-flight 拥塞发送准入 + peer max_udp_payload_size recovery max_datagram_size/initial-cwnd resync + 已 armed 的单个 PTO probe 绕过 congestion window + ACK 驱动的 frame-payload STREAM/CRYPTO、protected CRYPTO、protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING retransmission requeue 和已 ACK 的 RESET_STREAM 过期重传抑制 + NewReno underutilized-cwnd suppression、slow-start/congestion-avoidance 字节计数与 batched-ACK 增长、recovery period、新拥塞事件后一次性 recovery probe 和 minimum-window ssthresh clamp + 不受 PTO backoff 放大的 persistent congestion duration/response、min-RTT refresh、recovery-period 清理/重新进入与非连续抑制 + ACK_ECN CE 驱动的 NewReno recovery 响应 + 带 Initial/Handshake max_ack_delay suppression 与 handshake confirmation 前 Application PTO gating 的 packet-space PTO PING/new-data/in-flight-CRYPTO/protected-0-RTT-control/protected-0-RTT-STREAM/in-flight-STREAM/cross-space probe hook + socket-backed UDP lifecycle loss/PTO recovery、lifecycle congestion-recovery 与 lifecycle STREAM-retransmission loopback | 实现 socket-owned protected-packet loss/PTO timer lifecycle 集成和剩余 NewReno 边界。 | 现有测试覆盖 ACK、recovery 副作用前的 invalid ACK range rejection、只新确认较低 range 且不更新 RTT sample 的 ACK、跨 packet number space 的 connection-level RTT 估计共享、shared RTT update 后 invalid-payload rollback、connection-level PTO backoff after one space expires、跨 space ACK reset、client Initial ACK PTO-backoff reset suppression、client no-in-flight anti-deadlock Initial/Handshake PTO、anti-amplification-limited server PTO disarm/rearm 和新 datagram 解除发送阻塞时的 expired-PTO service、discard reset、invalid-payload rollback、Initial/Handshake RTT ACK-delay suppression、ACK delay exponent scaling、handshake confirmed 后 max_ack_delay 截断、max_udp_payload_size-driven recovery max_datagram_size/initial-cwnd resync、packet-threshold loss、ACK 驱动和 timeout 驱动的 time-threshold loss、aggregate timer deadline/service 的 loss-time 优先于 PTO、deadline 前无副作用、due loss-time service 不额外排 PTO probe、最早 PTO space service、closing/draining recovery-timer disarm，以及 endpoint-owned 多连接 timer scheduling/re-arm/disarm、跨 packet number space bytes-in-flight 拥塞发送准入、protected short PTO service/disarm、protected short loss-time retransmission、protected short CRYPTO loss-time 到期/retransmission、ACK 驱动 lost STREAM、frame-payload/protected CRYPTO requeue、protected 0-RTT STREAM requeue、protected 0-RTT RESET_STREAM/STOP_SENDING requeue 和已 ACK 的 RESET_STREAM 过期重传抑制、retransmission requeue 后 invalid-payload rollback、NewReno underutilized-cwnd suppression 与 slow-start/congestion-avoidance 字节计数/batched-ACK 增长、NewReno recovery-period 抑制 loss 和 ECN-CE、新拥塞事件后一次性 recovery probe、minimum-window ssthresh clamp、不受 PTO backoff 放大的 persistent congestion duration/response、min-RTT refresh、recovery-period 清理/重新进入与非连续 loss 抑制、packet-number-space PTO PING 排队与 connection-level backoff、一次性 PTO probe congestion-window bypass、cross-space PTO peer probes、Initial/Handshake PTO deadline 不计 max_ack_delay、handshake confirmation 前 Application PTO no-op、queued STREAM data probe selection、PTO 驱动 in-flight CRYPTO/STREAM/protected-0-RTT-STREAM/protected-0-RTT-control retransmission 和拥塞窗口算术；`run-loss-recovery` 覆盖 invalid ACK range rejection、old-largest ACK RTT preservation、跨 packet number space bytes-in-flight 拥塞发送准入、aggregate loss-time timer service、NewReno underutilized-cwnd suppression 与字节计数/batched-ACK congestion-window 增长、新拥塞事件 STREAM recovery probe、minimum-window ssthresh clamp、不会被 PTO backoff 放宽的 persistent congestion duration、persistent-congestion min-RTT refresh、persistent-congestion recovery-period 清理/重新进入，以及非连续 persistent-congestion 抑制；`run-transport-parameters` 覆盖 peer max_udp_payload_size-driven recovery resync；`run-endpoint-recovery-timers` 覆盖多个 caller-owned connection handle 之间的 endpoint-owned selection/servicing 与 closing-state recovery timer disarm；`run-crypto-stream` 覆盖 frame-payload Handshake CRYPTO loss requeue/retransmission 和 protected 1-RTT CRYPTO ACK-loss requeue/retransmission；`run-pto-recovery` 覆盖 aggregate PTO timer service、handshake confirmation 前 Application PTO gating、client Initial ACK PTO-backoff reset suppression、client no-in-flight anti-deadlock Initial PTO、anti-amplification-limited server PTO disarm/rearm 和 unblock-time expired PTO service、跨 packet number space 的 connection-level RTT 估计共享与 PTO backoff、Initial/Handshake RTT ACK-delay suppression、已 armed 的单个 PTO probe 绕过 congestion window、已 ACK 的 RESET_STREAM 过期重传抑制、protected 1-RTT CRYPTO PTO probe selection 和 cross-space PTO peer probes；`run-udp-loss-recovery-loopback` 覆盖 UDP 上的 protected short PING delivery、protected ACK 驱动的 packet-threshold loss removal、lifecycle timer 驱动的 time-threshold cleanup 和最终 timer disarm；`run-udp-congestion-recovery-loopback` 覆盖 UDP 上 lifecycle-owned protected short PING/ACK routing、NewReno recovery-period 内重复 loss reduction 抑制，以及 persistent congestion 降到 minimum window；`run-udp-ecn-validation-loopback` 覆盖 protected ACK_ECN CE response 在 UDP 上降低 congestion window；`run-udp-pto-recovery-loopback` 覆盖 lifecycle timer 驱动的 protected UDP packet ACK-loss PTO、PING fallback probe delivery、queued STREAM data 作为 PTO probe、in-flight STREAM 和 CRYPTO data 作为 PTO probe、重复 receive range/CRYPTO range 丢弃、ACK cleanup 和最终 timer disarm；`run-udp-stream-retransmission-loopback` 覆盖 protected UDP packet 上 lifecycle-owned route selection 下 ACK 驱动的 1-RTT STREAM retransmission 和 final ACK cleanup；`packet_spaces` 覆盖 protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING 的 ACK-loss requeue 和新 packet number 重传。剩余可控时钟测试覆盖完整 socket-owned protected-packet loss/PTO timer lifecycle 集成。 |
| UDP endpoint routing | 部分内存态 DCID/IPv4 四元组 router + 带 client-side VN selection/follow-up route replacement、connection handoff 和 protected follow-up Initial emission 的 socket-backed UDP endpoint routing loopback + socket-backed zero-length CID tuple-routing loopback + socket-backed preferred-address route-migration loopback + socket-backed replacement-CID route-retirement loopback + socket-backed lifecycle connection-ID NEW/RETIRE loopback + socket-backed lifecycle flow-control credit-refresh loopback + socket-backed ECN ACK_ECN validation/CE response loopback + socket-backed lifecycle loss-recovery loopback + socket-backed lifecycle congestion-recovery loopback + socket-backed lifecycle PTO recovery loopback + socket-backed lifecycle STREAM retransmission loopback + socket-backed lifecycle installed-key key-update loopback + socket-backed path-validation route-update loopback + socket-backed lifecycle Retry route-switch/address-validation loopback + socket-backed close-triggered route retirement/reset loopback + socket-backed stateless reset emission loopback + unsupported-version VN response helper + client-side VN selection/follow-up lifecycle helper + client Initial Source CID route registration + supported-version unknown-DCID Initial accept classification + accepted Initial Original DCID/server Initial SCID route registration + zero-length CID tuple routing + Retry DCID switch helper + caller-validated preferred-address migration commit + sequence/retire-prior-to/connection-handle route retirement + endpoint reset-token uniqueness checks + caller-validated path update + retired-CID stateless reset token lookup/datagram construction + route/version-negotiation/reset/drop/accept receive classification | 按 DCID、本地/远端地址四元组、版本支持和连接状态路由 UDP datagram。 | 现有确定性 endpoint 测试覆盖 long-header DCID routing、unsupported-version Version Negotiation response generation 和 CID echo、client Initial Source CID route 注册以接收 server Initial/VN response、supported-version unknown-DCID Initial accept metadata、accepted Initial route 注册与回滚、client-side VN selection/ignore/reject state、lifecycle-owned VN follow-up route/timer retirement 与 follow-up route registration、endpoint-owned follow-up connection handoff、lifecycle-owned protected follow-up Initial emission、重用 client Initial Source CID 的 follow-up registration、short-header registered-CID matching、zero-length CID tuple routing、duplicate route 拒绝、duplicate sequence 拒绝、stateless reset token reuse rejection、Retry Source CID route switching、调用方验证后的 preferred-address route migration、unknown CID 拒绝、ambiguous short-header CID 拒绝、path-specific zero-CID retirement、面向 RETIRE_CONNECTION_ID wiring 的 sequence-number route retirement、retire_prior_to threshold retirement、connection-handle route retirement、caller-validated route path update、stale path-update rejection、route retirement、active-migration-disabled path 拒绝、inactive route 的 stateless reset token lookup、inactive route 的 reset datagram construction，以及 route/version-negotiation/reset/drop/accept receive action classification；`run-udp-endpoint-loopback` 覆盖真实 loopback UDP socket 上的路由决策、client-side VN selection、follow-up config derivation、old-attempt route retirement、follow-up Initial route registration、endpoint-owned follow-up connection handoff、protected follow-up Initial emission/server processing 和 follow-up Initial routing；`run-udp-zero-cid-loopback` 覆盖真实 loopback UDP socket 上的 zero-length CID tuple routing、long-header zero-DCID routing、path-specific retirement 和 route path update；`run-udp-preferred-address-loopback` 覆盖真实 loopback UDP socket 上调用方提交的 preferred-address route migration、preferred CID 路由、当前 route 退役、active-migration-disabled stray-path 拒绝，以及 retained reset-token lookup；`run-udp-replacement-cid-loopback` 覆盖真实 loopback UDP socket 上的 replacement-CID route registration、retire_prior_to sequence retirement、inactive reset-token lookup、active replacement routing、invalid replacement sequence rejection 和 active-migration-disabled stray-path rejection；`run-udp-connection-ids-loopback` 覆盖真实 loopback UDP socket 上 protected NEW_CONNECTION_ID 和 RETIRE_CONNECTION_ID 经 lifecycle-owned endpoint route 的交换、replacement CID routing、inactive reset-token lookup 与 active replacement token suppression；`run-udp-flow-control-loopback` 覆盖真实 loopback UDP socket 上 protected STREAM_DATA_BLOCKED、MAX_DATA/MAX_STREAM_DATA、resumed STREAM data 和 final ACK cleanup 经 lifecycle-owned endpoint route 传递；`run-udp-ecn-validation-loopback` 覆盖 loopback UDP socket 上 modeled ECT(0) protected PING routing、protected ACK_ECN validation、ACK_ECN CE response、endpoint ECN state update 和迁移路径 ECN isolation；`run-udp-loss-recovery-loopback` 覆盖 loopback UDP socket 上 protected short PING routing，以及 ACK 驱动 packet-threshold 和 lifecycle timer 驱动 time-threshold loss 和最终 timer disarm；`run-udp-congestion-recovery-loopback` 覆盖 loopback UDP socket 上 lifecycle-owned protected short PING/ACK routing、NewReno recovery-period 抑制和 persistent congestion 窗口降低；`run-udp-pto-recovery-loopback` 覆盖 loopback UDP socket 上 lifecycle timer service 加 protected short probe polling 驱动 ACK-loss PTO、protected PING fallback probe delivery、queued STREAM 与 in-flight STREAM/CRYPTO PTO probe delivery、重复 receive/CRYPTO range 丢弃、ACK cleanup 和最终 timer disarm；`run-udp-stream-retransmission-loopback` 覆盖 loopback UDP socket 上 lifecycle-owned route selection 下 sparse ACK 驱动的 1-RTT STREAM retransmission 和 final ACK cleanup；`run-udp-key-update-loopback` 覆盖真实 loopback UDP socket 上 lifecycle-owned installed-key key phase routing、peer key-phase advancement 和 ACK-gated second-update re-enable；`run-udp-path-validation-loopback` 覆盖新对端端口上的 path_changed routing，随后由 validation-driven lifecycle helper 提交 path update，并在新路径上确认 route；`run-udp-retry-loopback` 覆盖 loopback UDP socket 上 lifecycle-owned Retry response routing、Retry Source CID route switching、follow-up Initial routing 和 accepted server Initial response routing；`run-udp-close-lifecycle-loopback` 覆盖 loopback UDP socket 上 close-triggered connection-handle route retirement 和后续 inactive-CID reset emission；`run-udp-stateless-reset-loopback` 覆盖 inactive CID 的 socket-backed stateless reset 发出；后续测试覆盖 protected client/server 集成。 |
| 互通 | 部分完成 | 证书校验后的 Zig client 已对本机独立 `quic-go` v0.59.0 server 完成带 FIN 的受保护 STREAM echo；独立 Go/Rust client 也完成了反向的 Zig server echo。 | 记录可重复的 peer-version 证据，并补 Retry、loss/recovery、version-negotiation、更广泛 server 与应用层协议场景。 |

### 1-RTT 包号乱序证据

受保护的 1-RTT short-packet 接收路径现维护有界的已接收包号区间历史：可接受已认证的前向间隙和延迟到达的包，在 frame 副作用前拒绝重复包，并为非连续接收生成 ACK range。`received packet ranges merge reordered packets and encode ACK gaps` 与 `processProtectedShortDatagram acknowledges reordered packets with ACK ranges` 覆盖区间合并、重复包拒绝和 ACK 编码。`zig build run-interop-event-loopback -- loss` 会真实丢弃首个 client 1-RTT 带 FIN 的 STREAM datagram，随后验证 PTO 驱动重传和成功的双向 FIN 传输（`pto_recovered=true`）。

以上仅是有界的 1-RTT short-packet 证据。Initial 和 Handshake 接收路径仍保持当前的有序规则，尚未记录外部 server 互通结果。

## 进展记录

- 2026-06-24：caller-keyed long-header backend-drive poll/drain helper 现在会
  在 backend 确认握手并已丢弃待 poll/drain 的 Handshake packet number space
  时返回 no-output 结果。这样 socket loop 不会把 TLS backend 合法确认并清理
  Handshake 状态后的输出轮询误报为 packet-processing 错误。

- 2026-06-18：新增 recovery 和连接层 congestion-window 剩余发送预算查询。
  `recovery.Recovery.availableCongestionWindow()` 返回单个 recovery state 的
  ack-eliciting 可发送字节预算，`Connection.availableCongestionWindow()` 使用
  与 protected packet 发送准入相同的跨 packet number space aggregate
  bytes-in-flight 模型，向 socket/event-loop 调用方暴露连接级发送预算。
  `Connection.congestionWindowFull()` 让 socket/event-loop owner 不必尝试并回滚
  ack-eliciting send，也能判断当前是否因 congestion window 阻塞。
  `Connection.canSendAckEliciting()` 会按一个候选 ack-eliciting payload
  复用真实发送准入口径，包含 congestion/probe 规则和 peer-address
  anti-amplification 限制。
  `Connection.availableAckElicitingSendBudget()` 暴露同一规则下的有效剩余
  send-admission budget，并在当前没有 send-admission 上限时返回 `null`。
  `Connection.ackElicitingSendAdmission()` 会报告第一个阻塞原因是
  congestion-window 还是 peer-address anti-amplification，低层 packet send
  记录路径也已复用这个共享准入结果。caller-keyed protected short packet
  poll 路径也会先使用共享 admission 结果，再消费排队的 ack-eliciting
  STREAM payload。

- 2026-06-18：新增 direct installed-key 1-RTT short receive-to-compatible-backend
  no-output 形态：
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline()`
  和
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`。
  单元测试证明 Application-space CRYPTO 会先完成 installed-key short packet
  认证和接收，再由 compatible-version backend 应用 peer Version Information、报告
  selected compatible version、保留 backend output 给后续 installed-key output path；
  OrClose 变体在 peer Version Information 无法匹配 configured compatibility 时会排队
  CONNECTION_CLOSE，并停在 deadline selection 和 backend output pull 之前。
- 2026-06-18：新增 routed installed-key 1-RTT short
  receive-to-compatible-backend no-output 形态：
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline()`
  和
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`。
  单元测试证明 route selection 和 connection-id mismatch 检查发生在 packet processing
  与 backend callback 之前；成功路径会使用 routed DCID 长度处理 short packet，再通过
  compatible-version backend 应用 peer Version Information 并选择下一次 deadline。
- 2026-06-18：新增 direct installed-key 1-RTT short
  receive-to-compatible-backend-to-output poll 形态：
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`
  和
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`。
  单元测试证明 Application-space CRYPTO 经 installed-key short receive 后，compatible
  backend 会应用 peer Version Information 并立即进入 installed-key output poll；
  OrClose 变体在 compatible-version 校验失败时会排队 close，并停在 backend output pull
  与 installed-key output poll 之前。
- 2026-06-18：新增 routed installed-key 1-RTT short
  receive-to-compatible-backend-to-output poll 形态：
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`
  和
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`。
  单元测试证明 route selection 与 connection-id mismatch 检查发生在 packet processing
  与 backend callback 之前；成功路径会使用 routed DCID 长度处理 short packet，再通过
  compatible-version backend 应用 peer Version Information 并立即进入 installed-key
  output poll。
- 2026-06-18：新增 direct installed-key 1-RTT short
  receive-to-compatible-backend-to-output bounded-drain 形态：
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`
  和
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`。
  单元测试证明 Application-space CRYPTO 经 installed-key short receive 后，compatible
  backend 会应用 peer Version Information，并在同一步进入 caller-bounded installed-key
  output drain；OrClose 变体在 compatible-version 校验失败时会排队 close，并停在
  backend output pull 与 bounded drain 之前。
- 2026-06-18：新增 routed installed-key 1-RTT short
  receive-to-compatible-backend-to-output bounded-drain 形态：
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`
  和
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`。
  单元测试证明 route selection 与 connection-id mismatch 检查发生在 packet processing
  与 backend callback 之前；成功路径会使用 routed DCID 长度处理 short packet，再通过
  compatible-version backend 应用 peer Version Information，并把 installed-key output
  写入 caller-bounded drain 切片。
- 2026-06-18：新增 `EndpointFeedCryptoBackendDriveNextDeadlineResult`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline()`
  和
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline()`，
  让 installed-key socket loop 可以在处理入站 datagram 后驱动 Handshake/1-RTT backend
  progress，并只更新下一次 endpoint-visible deadline，而不立即 poll output。单元测试证明
  backend 产出的 Handshake CRYPTO 会留给已有 protected output path，single-connection
  wrapper 复用 cross-connection 行为，dropped datagram 不会触发 backend callback，且
  OrClose peer-parameter 错误会在排队 close state 后停在 backend output 之前。
- 2026-06-18：新增 RFC 9368-compatible no-output 形态：
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`
  和
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`。
  这些 helper 让 socket loop 可以在处理 installed-key datagram 后，经 TLS backend
  应用 peer Version Information，并只重算下一次 wakeup，不立即 poll output。单元测试证明
  cross-connection 与 single-connection 形态都会应用 compatible peer information，
  backend CRYPTO output 会保留给已有 protected output path，且 OrClose 变体在 peer
  Version Information 非法时会停在 backend output 之前。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialWithCryptoBackendOrCloseAndDrainDatagrams()`，
  作为 close-propagating accepted Initial backend-to-bounded-drain step。单元测试证明
  backend peer transport-parameter 错误会先消费已接收的 client Initial CRYPTO，在 backend
  output pull 或 protected Initial output drain 前停止，保留已安装 route，并通过已有
  long-packet output path 留下可发送的 protected Initial close。
- 2026-06-18：新增 installed-key Handshake receive-to-output poll 和 drain
  step：
  `EndpointConnectionLifecycle.processProtectedHandshakeDatagramWithInstalledKeysAndPollDatagram()`、
  `processProtectedHandshakeDatagramWithInstalledKeysOrCloseAndPollDatagram()`、
  `processRoutedProtectedHandshakeDatagramWithInstalledKeysAndPollDatagram()`、
  `processRoutedProtectedHandshakeDatagramWithInstalledKeysOrCloseAndPollDatagram()`、
  `processProtectedHandshakeDatagramWithInstalledKeysAndDrainDatagrams()`、
  `processProtectedHandshakeDatagramWithInstalledKeysOrCloseAndDrainDatagrams()`、
  `processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDrainDatagrams()` 和
  `processRoutedProtectedHandshakeDatagramWithInstalledKeysOrCloseAndDrainDatagrams()`。
  单元测试证明 installed-key Handshake receive-to-poll、routed receive-to-drain
  会在 packet processing 前拦截 route mismatch，以及 close-propagating frame 错误会在普通
  installed-key output 前停止。
- 2026-06-18：新增 caller-keyed Initial/Handshake long-packet
  receive-to-output poll 和 drain step：
  `EndpointConnectionLifecycle.processProtectedLongDatagramInSpaceAndPollDatagram()`、
  `processProtectedLongDatagramInSpaceOrCloseAndPollDatagram()`、
  `processRoutedProtectedLongDatagramInSpaceAndPollDatagram()`、
  `processRoutedProtectedLongDatagramInSpaceOrCloseAndPollDatagram()`、
  `processProtectedLongDatagramInSpaceAndDrainDatagrams()`、
  `processProtectedLongDatagramInSpaceOrCloseAndDrainDatagrams()`、
  `processRoutedProtectedLongDatagramInSpaceAndDrainDatagrams()` 和
  `processRoutedProtectedLongDatagramInSpaceOrCloseAndDrainDatagrams()`。
  单元测试证明 protected Handshake receive 后可直接输出 ACK、routed drain 会在 packet
  processing 前拦截 route mismatch，以及 close-propagating Initial frame 错误会在普通输出前停止。
- 2026-06-18：把 version-list matching 和本地 RFC 9368 version-information
  validation policy 迁移到 `src/quic/connection_version.zig`。`src/lib.zig`
  现在在 Version Negotiation follow-up 和 backend peer-version selection 中调用该聚焦模块，
  同时保持公开 `quicz` facade 不变。拆出模块的单元测试覆盖 reserved-version skip、
  authenticated extra-version selection，以及不一致 client follow-up config rejection。
- 2026-06-18：把公开连接配置和固定存储 preferred-address transport-parameter
  建模迁移到 `src/quic/connection_config.zig`，同时保持 `src/lib.zig`
  作为稳定的 `quicz` module facade。这是 transport core 文件继续收窄的第一步模块边界整理；
  `zig build test` 仍是验证门槛，因为拆出的文件仍必须被 root test build 发现。
- 2026-06-18：新增 caller-owned key-phase-state 1-RTT short
  receive-to-output poll 和 drain step：
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithKeyPhaseStateAndPollDatagram()`、
  `processProtectedShortDatagramWithKeyPhaseStateOrCloseAndPollDatagram()`、
  `processRoutedProtectedShortDatagramWithKeyPhaseStateAndPollDatagram()`、
  `processRoutedProtectedShortDatagramWithKeyPhaseStateOrCloseAndPollDatagram()`、
  `processProtectedShortDatagramWithKeyPhaseStateAndDrainDatagrams()`、
  `processProtectedShortDatagramWithKeyPhaseStateOrCloseAndDrainDatagrams()`、
  `processRoutedProtectedShortDatagramWithKeyPhaseStateAndDrainDatagrams()` 和
  `processRoutedProtectedShortDatagramWithKeyPhaseStateOrCloseAndDrainDatagrams()`。
  单元测试证明 route selection 会在 packet processing 或 key-phase advancement
  前拦截 connection handle mismatch，成功 routed next-key-phase PING receive
  会推进 caller-owned receive state，并 poll 或 drain Application-space ACK
  output；close-propagating 的认证后 Application frame 错误会在普通 stateful
  output polling 或 draining 前保留 caller-owned receive state。
- 2026-06-18：新增 caller-owned key-phase-state 1-RTT short
  receive-to-next-deadline no-output step：
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithKeyPhaseStateAndSelectNextDeadline()`、
  其 `OrClose` 变体，以及 routed
  `processRoutedProtectedShortDatagramWithKeyPhaseStateAndSelectNextDeadline()`。
  单元测试证明 successful next-key-phase PING receive 会推进 caller-owned receive
  state、刷新 idle deadline，并保留 ACK 输出供后续 stateful short-packet poll；
  routed 变体会在 packet processing 或 key-phase advancement 前拦截 connection
  handle mismatch。
- 2026-06-18：新增 explicit key-update 1-RTT short
  receive-to-output poll 和 drain step：
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithKeyUpdateAndPollDatagram()`、
  `processProtectedShortDatagramWithKeyUpdateOrCloseAndPollDatagram()`、
  `processRoutedProtectedShortDatagramWithKeyUpdateAndPollDatagram()`、
  `processRoutedProtectedShortDatagramWithKeyUpdateOrCloseAndPollDatagram()`、
  `processProtectedShortDatagramWithKeyUpdateAndDrainDatagrams()`、
  `processProtectedShortDatagramWithKeyUpdateOrCloseAndDrainDatagrams()`、
  `processRoutedProtectedShortDatagramWithKeyUpdateAndDrainDatagrams()` 和
  `processRoutedProtectedShortDatagramWithKeyUpdateOrCloseAndDrainDatagrams()`。
  单元测试证明 route selection 会在 packet processing 前拦截 connection handle
  mismatch，成功 routed next-key-phase PING receive 会 poll 和 drain
  Application-space ACK output，close-propagating 的认证后 Application frame 错误
  会在普通 explicit-phase output polling 或 draining 前停止。
- 2026-06-18：新增 explicit key-update 1-RTT short
  receive-to-next-deadline no-output step：
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithKeyUpdateAndSelectNextDeadline()`、
  其 `OrClose` 变体，以及 routed
  `processRoutedProtectedShortDatagramWithKeyUpdateAndSelectNextDeadline()`。
  单元测试证明 successful next-key-phase PING receive 会刷新 idle deadline、保留
  ACK 输出供后续 explicit-phase short-packet poll；routed 变体会在 packet
  processing 前拦截 connection handle mismatch。
- 2026-06-18：新增 caller-keyed 1-RTT short
  receive-to-output poll 和 drain step：
  `EndpointConnectionLifecycle.processProtectedShortDatagramAndPollDatagram()`、
  `processProtectedShortDatagramOrCloseAndPollDatagram()`、
  `processRoutedProtectedShortDatagramAndPollDatagram()`、
  `processRoutedProtectedShortDatagramOrCloseAndPollDatagram()`、
  `processProtectedShortDatagramAndDrainDatagrams()`、
  `processProtectedShortDatagramOrCloseAndDrainDatagrams()`、
  `processRoutedProtectedShortDatagramAndDrainDatagrams()` 和
  `processRoutedProtectedShortDatagramOrCloseAndDrainDatagrams()`。
  单元测试证明 route selection 会在 packet processing 前拦截 connection handle
  mismatch，成功 routed caller-keyed PING receive 会 poll 和 drain
  Application-space ACK output，close-propagating 的认证后 Application frame 错误
  会在普通 output polling 或 draining 前停止。
- 2026-06-18：新增 caller-keyed 1-RTT short
  receive-to-next-deadline no-output step：
  `EndpointConnectionLifecycle.processProtectedShortDatagramAndSelectNextDeadline()`、
  其 `OrClose` 变体，以及 routed
  `processRoutedProtectedShortDatagramAndSelectNextDeadline()`。
  单元测试证明 successful caller-keyed PING receive 会刷新 idle deadline、保留 ACK
  输出供后续 caller-keyed short-packet poll；routed 变体会在 packet processing
  前拦截 connection handle mismatch。
- 2026-06-18：新增 caller-keyed 和 installed-key 0-RTT
  receive-to-short-output drain step：
  `EndpointConnectionLifecycle.processProtectedZeroRttDatagramAndDrainShortDatagrams()`、
  `processProtectedZeroRttDatagramOrCloseAndDrainShortDatagrams()`、
  `processRoutedProtectedZeroRttDatagramAndDrainShortDatagrams()`、
  `processRoutedProtectedZeroRttDatagramOrCloseAndDrainShortDatagrams()`、
  `processProtectedZeroRttDatagramWithInstalledKeysAndDrainShortDatagrams()`、
  `processProtectedZeroRttDatagramWithInstalledKeysOrCloseAndDrainShortDatagrams()`、
  `processRoutedProtectedZeroRttDatagramWithInstalledKeysAndDrainShortDatagrams()` 和
  `processRoutedProtectedZeroRttDatagramWithInstalledKeysOrCloseAndDrainShortDatagrams()`。
  单元测试证明 route selection 会在 0-RTT processing 前拦截 connection handle
  mismatch，成功 routed 0-RTT STREAM receive 会在 caller-keyed 与 installed-key
  路径中 drain 一个 Application-space short ACK，close-propagating 的认证后
  0-RTT frame 错误会在普通 short-output draining 前停止。
- 2026-06-18：新增 caller-keyed 和 installed-key 0-RTT
  receive-to-short-output poll step：
  `EndpointConnectionLifecycle.processProtectedZeroRttDatagramAndPollShortDatagram()`、
  `processProtectedZeroRttDatagramOrCloseAndPollShortDatagram()`、
  `processRoutedProtectedZeroRttDatagramAndPollShortDatagram()`、
  `processRoutedProtectedZeroRttDatagramOrCloseAndPollShortDatagram()`、
  `processProtectedZeroRttDatagramWithInstalledKeysAndPollShortDatagram()`、
  `processProtectedZeroRttDatagramWithInstalledKeysOrCloseAndPollShortDatagram()`、
  `processRoutedProtectedZeroRttDatagramWithInstalledKeysAndPollShortDatagram()` 和
  `processRoutedProtectedZeroRttDatagramWithInstalledKeysOrCloseAndPollShortDatagram()`。
  单元测试证明 route selection 会在 0-RTT processing 前拦截 connection handle
  mismatch，成功 routed 0-RTT STREAM receive 会在 caller-keyed 与 installed-key
  路径中 poll 一个 Application-space short ACK，close-propagating 的认证后 0-RTT
  frame 错误会在普通 short-output polling 前停止。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndPollProtectedLongCryptoDatagram()`、
  其 `OrClose` 变体、
  `processProtectedLongDatagramInSpaceAndDriveCryptoBackendAndPollDatagram()`、
  其 `OrClose` 变体，以及 routed
  `processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendAndPollDatagram()`
  这一组 API，作为 caller-keyed Initial/Handshake
  receive-to-backend-to-output loop step。单元测试证明非 routed 处理会驱动
  backend progress 并 poll 一个 caller-keyed protected long response，route
  selection 会在 backend delivery 前拦截 connection handle mismatch，成功 routed
  Handshake CRYPTO receive 会 poll 一个 response，close-propagating backend
  peer-parameter 错误会在 output polling 前停止。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedLongDatagramInSpaceAndDriveCryptoBackendInSpaceAndSelectNextDeadline()`、
  其 `OrClose` 变体，以及 routed
  `processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendInSpaceAndSelectNextDeadline()`
  这一组 API，作为 caller-keyed Initial/Handshake
  receive-to-backend-to-next-deadline no-output loop step。单元测试证明 successful receive
  会把 Handshake CRYPTO 交给 backend、保留 backend 输出供后续 caller-keyed long-packet
  poll，并返回 idle deadline；routed 变体会在 backend drive 前拦截 connection handle mismatch。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndPollDatagram()`、
  其 `OrClose` 变体，以及 routed
  `processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndPollDatagram()`
  这一组 API，作为 installed-key Handshake receive-to-backend-to-output loop step。
  单元测试证明 route selection 会在 backend delivery 前拦截 connection handle mismatch，
  成功 routed Handshake CRYPTO receive 会驱动 backend progress 并 poll 一个 protected
  Handshake response，close-propagating backend peer-parameter 错误会在 output
  polling 前停止。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndSelectNextDeadline()`、
  其 `OrClose` 变体，以及 routed
  `processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndSelectNextDeadline()`
  这一组 API，作为 installed-key Handshake receive-to-backend-to-next-deadline
  no-output loop step。单元测试证明 successful receive 会把 Handshake CRYPTO
  交给 backend、保留 backend 输出供后续 poll，并返回 idle deadline；routed 变体会在 backend
  drive 前拦截 connection handle mismatch。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndPollDatagram()`、
  `processProtectedShortDatagramWithInstalledKeysOrCloseAndPollDatagram()`、
  `processProtectedShortDatagramWithInstalledKeysAndDrainDatagrams()` 和
  `processProtectedShortDatagramWithInstalledKeysOrCloseAndDrainDatagrams()`，
  作为 single-connection installed-key 1-RTT receive-to-output 和
  receive-to-bounded-drain loop step。单元测试证明 successful installed-key PING
  receive 不需要 endpoint routing 也能 poll 和 drain Application-space ACK output，
  close-propagating 的认证后 Application frame 错误会在普通 output polling 或
  draining 前排队 close。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDrainDatagramsWithInstalledKeyOptions()`
  和
  `processProtectedShortDatagramWithInstalledKeysOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个 single-connection bounded-drain 入口保留和 poll 入口一致的显式 installed-key
  output options；旧的 Application-only drain 入口继续作为兼容 wrapper。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndPollDatagram()`
  及其 `OrClose` 变体，作为 routed installed-key 1-RTT
  receive-to-output loop step。单元测试证明 endpoint route selection
  发生在 packet processing 前，connection-id mismatch 会在 ACK generation 前停止，
  成功 routed installed-key PING receive 会 poll 一个 ACK datagram 给 peer，认证后的
  frame 错误会排队 close 并在 output polling 前停止。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndSelectNextDeadline()`、
  其 `OrClose` 变体，以及 routed
  `processRoutedProtectedShortDatagramWithInstalledKeysAndSelectNextDeadline()`
  这一组 API，作为 installed-key 1-RTT receive-to-next-deadline no-output
  loop step。单元测试证明 successful installed-key PING receive 会刷新 idle
  deadline、保留 ACK 输出供后续 installed-key short-packet poll；routed 变体会在
  packet processing 前拦截 connection handle mismatch。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndSelectNextDeadline()`
  和
  `processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndSelectNextDeadline()`，
  作为 installed-key 1-RTT receive-to-Application-backend-to-next-deadline
  no-output loop step。单元测试证明 successful Application CRYPTO receive 会交给
  backend、保留 ACK/CRYPTO output 供后续 installed-key short-packet poll，并返回
  idle deadline；routed 变体会在 packet processing 和 backend callback 前拦截
  connection handle mismatch。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline()`
  和
  `processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline()`，
  作为 close-propagating installed-key 1-RTT
  receive-to-Application-backend-to-next-deadline no-output loop step。单元测试证明
  backend peer transport-parameter 错误会在 backend output pull 和 deadline
  selection 前排队 close；routed 变体会在 packet processing 和 backend callback
  前拦截 connection handle mismatch。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagram()`
  和
  `processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagram()`，
  作为 installed-key 1-RTT receive-to-Application-backend-to-output
  loop step。单元测试证明 successful Application CRYPTO receive 会驱动 backend，
  backend 产出的 Application CRYPTO 与 ACK 可在同一步 installed-key short-packet
  poll 中输出；routed 变体会在 packet processing 和 backend callback 前拦截
  connection handle mismatch。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram()`
  和
  `processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram()`，
  作为 close-propagating installed-key 1-RTT
  receive-to-Application-backend-to-output loop step。单元测试证明 backend peer
  transport-parameter 错误会在 ordinary installed-key output poll 前排队 close，
  backend output 不会被拉取；routed 变体会在 packet processing 和 backend callback
  前拦截 connection handle mismatch。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagrams()`
  和
  `processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagrams()`，
  作为 installed-key 1-RTT receive-to-Application-backend-to-bounded-drain
  loop step。单元测试证明 successful Application CRYPTO receive 会驱动 backend，
  backend 产出的 Application CRYPTO 与 ACK 可被同一步 bounded installed-key
  drain 写入 caller-owned output slot；routed 变体会在 packet processing 和 backend
  callback 前拦截 connection handle mismatch。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`
  和
  `processRoutedProtectedShortDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`，
  作为 close-propagating installed-key 1-RTT
  receive-to-Application-backend-to-bounded-drain loop step。单元测试证明 backend
  peer transport-parameter 错误会在 bounded installed-key drain 前排队 close，
  backend output 不会被拉取；routed 变体会在 packet processing 和 backend callback
  前拦截 connection handle mismatch。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndPollDatagram()`
  和 cross-connection
  `feedDatagramWithInstalledKeysAcrossConnectionsAndPollDatagram()`，作为
  socket-facing installed-key receive-to-output 核心 step。单元测试证明 feed
  classification 会先完成 route selection，选中的 caller-owned connection 会 poll 一个
  1-RTT ACK datagram，decoy connection 不被触碰，single-connection wrapper 也保持
  peer ACK cleanup。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDrainDatagrams()`
  和 cross-connection
  `feedDatagramWithInstalledKeysAcrossConnectionsAndDrainDatagrams()`，作为
  socket-facing installed-key receive-to-bounded-drain 核心 step。单元测试证明 feed
  classification 会先完成 route selection，选中的 caller-owned connection 会把 1-RTT
  ACK drain 到 bounded output slots，decoy connection 不被触碰，single-connection
  wrapper 也保持 peer ACK cleanup。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndDrainDatagrams()`
  及其 `OrClose` 变体，作为 routed installed-key 1-RTT
  receive-to-bounded-drain 核心 step。单元测试证明 route selection 发生在 packet
  processing 前，connection-id mismatch 会在 ACK generation 前停止，成功 routed
  installed-key PING receive 会把 ACK drain 到 caller-owned output slots，认证后的
  frame 错误会排队 close 并在 output drain 前停止。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndDrainDatagramsWithInstalledKeyOptions()`
  和
  `processRoutedProtectedShortDatagramWithInstalledKeysOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个 routed bounded-drain 入口会在 route selection 后保留调用方选择的 installed-key
  output options。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams()`
  及其 `OrClose` 变体，作为 routed installed-key Handshake
  receive-to-backend-to-bounded-drain 核心 step。单元测试证明 route selection
  发生在 packet processing 前，connection-id mismatch 会在 backend delivery 前停止，
  成功 routed installed-key Handshake CRYPTO 会产出 protected response，backend peer
  transport-parameter 错误会在 output drain 前停止并留下 protected Handshake close 给 peer。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndDrainProtectedLongCryptoDatagrams()`，
  作为 close-propagating caller-keyed Initial/Handshake backend-drive 到 bounded-drain
  的核心 step。单元测试证明 backend peer transport-parameter 错误会消费已收到的
  Handshake CRYPTO，但在 backend output pull 或 caller-keyed long-header CRYPTO drain
  前停止，刷新 endpoint recovery state，并留下 protected Handshake
  `TRANSPORT_PARAMETER_ERROR` close 给 peer。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.processProtectedLongDatagramInSpaceAndDriveCryptoBackendOrCloseAndDrainDatagrams()`，
  作为 close-propagating caller-keyed long-header
  receive-to-backend-to-bounded-drain 核心 step。单元测试证明 authenticated Handshake
  CRYPTO datagram 会先完成处理再交付 backend，backend peer transport-parameter 错误会在
  output pull 或 drain 前停止，并让 peer 收到 protected Handshake
  `TRANSPORT_PARAMETER_ERROR` close。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams()`
  及其 `OrClose` 变体，作为 routed caller-keyed long-header
  receive-to-backend-to-bounded-drain 核心 step。单元测试证明 route selection
  发生在 packet processing 前，connection-id mismatch 会在 backend delivery 前停止，
  成功 routed Handshake CRYPTO 会产出 protected response，backend peer
  transport-parameter 错误会在 output drain 前停止并留下 protected Handshake close 给 peer。
- 2026-06-24：收紧 endpoint lifecycle backend-drive installed-key Handshake
  输出边界。backend-drive-to-poll 和 backend-drive-to-bounded-drain helper
  现在会在 backend 确认 Handshake 且连接可丢弃 Handshake space 时，把 Handshake
  输出视为空结果，同时清理已安装 Handshake key 并刷新 lifecycle recovery timer。
  该行为同样覆盖 close-propagating 与 compatible-version backend-drive 变体；
  直接 installed-key polling 仍保留调用方负责的既有语义。单元测试证明普通和
  compatible backend poll/drain 路径会报告 backend progress 与 Handshake discard，
  但不再产出 datagram 或 drain error。
- 2026-06-05：把当前 C TLS 示例边界迁移到 Zig 0.16 的 `addTranslateC`
  构建路径。C ABI 声明现在放在小 header 中，Zig 示例通过 `@import("c")`
  引入；当前示例中的手写 `extern fn` / `extern struct` 已移除。
  OpenSSL-backed `TlsBackend` wrapper 也通过 translate-c header 暴露
  `handshake_confirmed` callback，在 peer transport parameters、Handshake/1-RTT
  secrets 和 OpenSSL recv/release 对入站 Handshake CRYPTO 的消费证据均可用后报告确认，因此
  `run-tls-openssl-backend-adapter` 现在会打印 `backend_confirmed=true`。同一
  translate-c header 也暴露 OpenSSL server-role backend 构造入口。backend C harness
  现在配置 TLS 1.3 + 固定示例 PSK，并验证服务端上下文可设置本端 transport
  parameters、消费真实 client Initial CRYPTO、产出 server Initial CRYPTO，且不会在
  完整握手前误报 confirmed；同一示例还会用 quicz protected Initial datagram 把
  client Initial CRYPTO 送入 server connection，通过
  `driveCryptoBackendInSpace(.initial)` 驱动 OpenSSL server backend 产出 server
  Initial CRYPTO，再由 quicz server 组包给 client 解包，并验证 peer transport
  parameters 与 Handshake keys 回到连接层。OpenSSL backend adapter 现在也按
  packet space 分离 CRYPTO buffer，server 连接层可以继续通过
  `driveCryptoBackendInSpace(.handshake)` 拉取 pending Handshake CRYPTO，并用
  installed Handshake keys 组 protected Handshake datagram；验证用 client 也会用同一
  backend 会话的 Handshake keys 回送 protected Handshake CRYPTO，server connection
  再把该 CRYPTO 投递给 OpenSSL recv/release callback 消费。完整 server-side
  `SSL_do_handshake()` Handshake/Application 推进与 confirmed 仍待接入。
- 2026-06-05：新增 `examples/tls_openssl_pair_transcript.zig` 和一个小 C
  harness，使用固定示例 PSK 完成 OpenSSL client/server callback-mode TLS
  transcript。该 harness 按 OpenSSL protection level 路由 CRYPTO bytes，验证双端无
  alert 完成 transcript，并记录双端 peer transport-parameter callback 与
  Handshake/1-RTT traffic-secret callback；Zig 侧现在会复制并解析按角色区分的 peer
  transport-parameter bytes，也会记录 keylog callback 次数和字节数，但不打印 key
  material，并会复制这些生成的 CRYPTO bytes，以 frame-payload 形式投递到 quicz Initial/Handshake/Application CRYPTO 队列，并按
  packet number space 读回；同时会把 client Initial CRYPTO bytes 经 quicz protected
  Initial long-packet helper 组包并验证 server 侧投递，也会通过 quicz endpoint lifecycle
  在 loopback UDP 上投递双向 Initial flight；随后会把 OpenSSL 产出的 Handshake secrets
  安装进 quicz，验证双向 protected Handshake CRYPTO 投递，包括通过同一个 lifecycle 的
  loopback UDP 投递；同一个手动 OpenSSL context 还会安装 OpenSSL 产出的 1-RTT
  secrets，并通过同一 socket/lifecycle 路径驱动 STREAM request/echo/final-ACK；
  随后还会在该路径验证 Handshake key discard 和 protected close/route cleanup；
  完整 pair transcript 也会验证 short packet 上的 installed-key protected STREAM
  request/response，并用同一组 1-RTT secrets 通过同一个 lifecycle 驱动 loopback UDP
  STREAM echo。完整 endpoint-owned live TLS handshake/socket
  loop 仍待实现。
- 2026-06-10：新增 `EndpointAcceptedInitialCryptoBackendDatagramResult` 和
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialWithCryptoBackendAndPollDatagram()`，
  作为 server Initial accept-to-TLS-backend response step。该 helper 会认证已接受的
  protected client Initial、安装 endpoint routes、驱动 Initial-space `CryptoBackend`，
  并把 backend 产出的 server Initial CRYPTO 组包成一个 protected server Initial
  datagram，同时不接管 connection/backend/socket storage。单元测试证明 backend 会消费
  client Initial CRYPTO、排队 server Initial CRYPTO、刷新 endpoint recovery scheduling，
  且 client 能解开 backend 产出的 response。
- 2026-06-10：新增
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialWithCryptoBackendOrCloseAndPollDatagram()`，
  覆盖 close-propagating accepted-Initial backend path。Initial-space backend 返回 peer
  transport-parameter 错误时，helper 会在 route 安装后排队 transport
  `CONNECTION_CLOSE`，并在 backend output polling 前停止；close 仍由已有 protected
  long-packet poll path 发出。单元测试证明 backend 会消费 client Initial CRYPTO，peer
  parameter 错误后不会拉取 output，lifecycle 会暴露 close-timeout deadline，且 client
  能解开 protected Initial close。
- 2026-06-18：新增 `EndpointAcceptedInitialCryptoBackendNextDeadlineResult`、
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialWithCryptoBackendAndSelectNextDeadline()`
  和
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialWithCryptoBackendOrCloseAndSelectNextDeadline()`，
  让 accepted Initial socket loop 可以在认证并路由 client Initial、驱动 Initial-space
  TLS backend 后，只更新下一次 endpoint-visible deadline，而不立即 poll protected
  output。单元测试证明 backend 产出的 Initial CRYPTO 会继续留给已有 protected
  long-packet poll path，并且 OrClose 变体在 peer transport-parameter validation 排队
  close 后会停在 backend output 之前。
- 2026-06-10：新增 `EndpointAcceptedInitialCryptoBackendDatagramDrainResult`、
  `EndpointConnectionLifecycle.drainProtectedLongCryptoDatagramsInSpace()` 和
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialWithCryptoBackendAndDrainDatagrams()`，
  让 socket loop 可以用 caller-owned result slots 限制 protected Initial/Handshake
  CRYPTO output 工作量。单元测试证明 accepted Initial 可以驱动 backend 排队多段 Initial
  CRYPTO output，一格 batch 只 drain 第一段 protected server Initial datagram，后续
  batch 继续 drain 剩余 Initial datagram，client 最终能重组 backend 产出的完整 CRYPTO
  bytes。
- 2026-06-10：新增
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndArmConnection()`，让
  endpoint-owned loop 可以通过一个核心 API 驱动连接的 `CryptoBackend` 并刷新聚合
  recovery timer snapshot。单元测试证明 backend-confirmed no-output Handshake drive
  会确认连接、丢弃 Handshake packet-number-space 状态并清空 endpoint timer；OpenSSL-backed
  adapter 现在也在 client 和 paired server backend 路径使用这个 lifecycle helper。新增
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndArmConnection()`
  覆盖 close-propagating peer transport-parameter 路径；单元测试证明无效 backend
  peer-parameter bytes 会通过 endpoint lifecycle 排队 protected Handshake
  `TRANSPORT_PARAMETER_ERROR` close，并且不会继续拉取 backend output。新增
  `driveCryptoBackendInSpaceWithCompatibleVersion*()` 的 endpoint lifecycle wrapper，
  作为 RFC 9368 compatible Version Information backend 路径；测试覆盖 selected-version
  progress、Handshake discard/timer refresh，以及拉取 backend output 前发出 protected
  `VERSION_NEGOTIATION_ERROR` close。新增
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndDrainProtectedLongCryptoDatagrams()`，
  面向已经持有 Initial 或 Handshake packet-protection keys 的 socket loop。单元测试证明
  caller-keyed Handshake datagram 可以喂入 backend input，backend drive 可以排队两段
  Handshake CRYPTO output，一格 bounded drain 只发出第一段 protected long-header
  datagram，后续 drain 可以完成 peer 侧交付。新增
  `EndpointConnectionLifecycle.processProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams()`，
  作为 caller-keyed Initial/Handshake 路径的单连接 receive-to-backend-to-bounded-drain
  step；测试证明 authenticated Handshake datagram 会先完成处理，再交付 backend input
  并执行 bounded response draining。新增
  `EndpointConnectionLifecycle.processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams()`，
  用于 traffic secrets 已安装后的 TLS-owned Handshake 阶段；测试证明 installed-key
  Handshake receive、backend input delivery、多段 backend CRYPTO、一格 bounded drain
  和后续 installed-key Handshake packet protection peer delivery。新增
  `EndpointConnectionLifecycle.processProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendOrCloseAndDrainDatagrams()`，
  覆盖 close-propagating installed-key Handshake backend path；测试证明 backend peer
  transport-parameter 错误会在 backend output pull 和 output drain 前停止，并留下
  protected Handshake close 给 peer。新增
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagrams()`，
  作为单连接 no-new-datagram tick；测试证明 pending-work sweep 计数、backend drive、
  一格 installed-key Handshake drain 和后续 peer delivery，不要求调用方构造单元素 view
  slices。新增
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`，
  覆盖单连接 close-propagating no-new-datagram tick；测试证明 backend 错误会在 output
  pull 和 drain 前停止。installed-key Handshake receive `OrClose`
  lifecycle wrapper 现在也会在 authenticated frame error 排队 protected
  `CONNECTION_CLOSE` 后刷新 endpoint 状态；测试证明已 armed 的 Handshake recovery
  timer 会在 poll protected close 前被清理。其他 endpoint protected receive
  `OrClose` wrapper 现在也采用同一条错误路径刷新规则，覆盖 caller-keyed、
  installed-key、key-update 和 key-phase 的 long/0-RTT/1-RTT 路径；short-packet
  和 installed-key 1-RTT 测试证明已 armed 的 Application recovery timer 会在 poll
  protected close 前被清理。对于已经失败的连接路径，endpoint timer 刷新只做
  best-effort，调用者会保留原始连接错误，而不是被二次 timer mirroring 失败遮蔽。
- 2026-06-10：在 `EndpointConnectionLifecycle` 上新增第一组核心 socket-loop 入口：
  `feedDatagram()` 封装 version-independent routing、Version Negotiation、
  stateless reset 和 Initial accept classification；`nextDeadline()` 返回单个
  connection handle 上最早的 active idle、close/drain 或 recovery deadline；
  `processPendingWork()` 固定 endpoint-owned pending-work 顺序：先 idle retirement，
  再 close/drain retirement，最后 loss/PTO service；`pollDatagram()` 通过现有
  protected packet helper 发出 installed-key Handshake、0-RTT 或 1-RTT datagram。
  单元测试证明 routed feed classification、idle-before-recovery 的 pending-work
  retirement、closed connection 不再报告 stale idle deadline、installed-key 1-RTT
  packet output、recovery timer refresh 和对端 ACK scheduling。这里落地的是可嵌入
  socket loop API surface；生产级 TLS-owned event loop 仍待实现。
- 2026-06-10：扩展 socket-facing lifecycle surface，新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeys()`。该 helper 会把
  version-independent feed classification 和 routed installed-key Handshake、0-RTT
  或 1-RTT protected receive 合在一起，并对 authenticated plaintext frame error 使用
  close-propagating receive path。单元测试现在证明 client lifecycle 可以通过
  `pollDatagram()` 发出 installed-key 1-RTT packet，server lifecycle 可以通过
  `feedDatagramWithInstalledKeys()` 路由并处理同一 packet，保留 route 证据、排队 peer
  ACK，并且 ACK-only receive state 不会 armed recovery timer。
- 2026-06-10：新增
  `EndpointConnectionLifecycle.processPendingWorkAndPollDatagram()`，作为
  socket loop 的 installed-key recovery wakeup bridge。它保留
  `processPendingWork()` 的处理顺序，idle/close retirement 会直接返回且不轮询输出；
  只有请求的 packet-number space 上确实有到期 loss/PTO timer 被服务后，才调用
  `pollDatagram()`。单元测试证明 deadline 前调用无副作用；Application PTO 到期路径会发出
  installed-key 1-RTT PING probe，并为该 probe 继续保持 endpoint recovery timer。
- 2026-06-10：新增 `EndpointPendingWorkDatagramDrainResult` 和
  `EndpointConnectionLifecycle.processPendingWorkAndDrainDatagrams()`，作为
  installed-key recovery wakeup bridge 的 bounded-output 形态。它保留与
  `processPendingWorkAndPollDatagram()` 相同的 `processPendingWork()` gating：
  loss/PTO timer 未被服务前返回空 drain result；匹配的 recovery wakeup 到期后，
  把 installed-key output drain 到 caller-owned result slots。单元测试证明
  deadline 前 no-op 和 Application PTO 到期后 1-RTT PING probe 路径。
- 2026-06-10：新增 `EndpointConnectionDeadline.installedKeyPollOptions()` 和
  `EndpointPollInstalledKeyDatagramOptions.fromRecoveryDeadline()`，让 socket loop 可以直接从
  `nextDeadline()` 返回的 recovery wakeup 推导 installed-key Handshake 或 1-RTT
  poll options。Initial recovery 会明确返回 null，因为 Initial packetization 不使用已安装的
  TLS traffic secrets；accepted early data 的 0-RTT 仍保持显式 poll choice。单元测试覆盖
  idle/Initial no-op 映射、Handshake DCID/SCID 保留和 Application 到 1-RTT 的映射；
  PTO wakeup 测试现在也使用从 deadline 推导出的 options。
- 2026-06-10：新增
  `EndpointConnectionLifecycle.processDueDeadlineAndPollDatagram()`，作为把
  `nextDeadline()` 和 pending-work processing 合在一起的 socket-loop wakeup 入口。deadline
  前调用会返回 null，且不修改 connection 或 endpoint 状态；到期的 idle/close deadline
  只执行 retirement，不输出 datagram；到期的 installed-key recovery deadline 复用
  `processPendingWorkAndPollDatagram()`，并可能返回 probe datagram。单元测试证明 idle
  retirement 会经过 due-deadline 入口完成，也证明 Application PTO wakeup 在 deadline 前无副作用，
  到期时会发出 installed-key 1-RTT PING probe。
- 2026-06-10：新增 `EndpointDueWorkDatagramDrainResult`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDrainDatagrams()` 和
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDrainDatagrams()`，
  作为 due-deadline wakeup path 的 bounded-output 形态。deadline 前调用仍返回 null；
  到期的 idle/close deadline 返回空 drain result；到期的 installed-key recovery
  deadline 复用 `processPendingWorkAndDrainDatagrams()`。单元测试证明单连接和跨连接
  Application PTO wakeup 都会 drain 1-RTT PING probe，并保留 earliest-deadline selection。
- 2026-06-11：新增
  `EndpointConnectionLifecycle.processDueDeadlineAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.processDueDeadlineAndDrainDatagramsWithInstalledKeyOptions()`，
  供 socket loop 在 recovery deadline 到期后显式选择 installed-key 输出空间。默认
  `installedKeyPollOptions()` 仍用于 Handshake 和 1-RTT 映射；accepted 0-RTT 的 PTO
  wakeup 可以显式 poll 或 drain `.zero_rtt` 输出。单元测试证明 deadline 前路径仍无副作用，
  packet-space 选项不匹配时会在 recovery state 变化前拒绝，到期 Application PTO 可以发出或
  drain protected 0-RTT `RESET_STREAM` probe。
- 2026-06-11：新增 `EndpointConnectionInstalledKeyPollView`、
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDrainDatagramsWithInstalledKeyOptions()`。
  这些是调用方持有 connection map 时的显式 installed-key due-deadline wakeup 形态。单元测试证明
  两个 accepted 0-RTT connection 之间会保持 earliest-deadline selection，deadline 前无副作用，
  到期后可以 poll 或 drain protected 0-RTT `RESET_STREAM` 输出，且较晚 deadline 的连接不被修改。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.pollDatagramAcrossConnectionsWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.drainDatagramsAcrossConnectionsWithInstalledKeyOptions()`。
  这两个入口是调用方持有 connection map 时的可复用显式 installed-key 输出 helper。
  单元测试证明跨连接选择和 bounded drain 会保留调用方选择的 0-RTT packetization，
  且不改变默认 `pollDatagramAcrossConnections()` 和
  `drainDatagramsAcrossConnections()` 行为。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口让跨连接 timer tick 可以先服务 pending recovery work，再按调用方选择的
  installed-key 输出选项发包。单元测试证明未到期 tick 仍无输出，到期 accepted 0-RTT
  recovery work 会在 poll 和 bounded-drain 形态中发出 protected 0-RTT `RESET_STREAM` probe。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.processPendingWorkAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.processPendingWorkAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口是单连接 pending-work 的显式输出命名，和跨连接 pending-work API 对齐。
  `EndpointPollInstalledKeyDatagramOptions` 现在在 `endpoint_types.zig` 中暴露 recovery
  packet-number-space 映射，使 pending-work 与 due-deadline 的校验复用同一条 options 规则。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口让普通 backend sweep 在 TLS progress 之后保留每个调用方持有 connection 的
  installed-key 输出选项。单元测试证明 backend sweep 可以 poll 和 bounded-drain 调用方选择的
  0-RTT `RESET_STREAM` 输出，且不改变默认统一 output space 的 backend 输出 helper。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把显式 installed-key 输出贯通到 no-new-datagram 的 pending-work/backend tick。
  单元测试证明到期 accepted 0-RTT recovery work 会先被 service，再经过 backend progress，
  最后按调用方选择的 0-RTT poll 或 bounded-drain 输出路径发出。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把显式 installed-key 输出贯通到 close-propagating backend sweep，同时保留现有的
  出错时停止在输出前的语义。单元测试证明成功的 OrClose sweep 可以 poll 和 bounded-drain
  调用方选择的 0-RTT `RESET_STREAM` 输出。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把显式 installed-key 输出贯通到 pending-work 加 close-propagating backend tick。
  单元测试证明到期 accepted 0-RTT recovery work 会被 service，OrClose backend progress 成功运行，
  并通过 poll 和 bounded-drain 形态发出调用方选择的 0-RTT 输出。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口在 RFC 9368-compatible backend progress 之后保留调用方选择的 installed-key
  输出。单元测试证明 compatible Version Information 会被应用，并且调用方选择的 0-RTT
  `RESET_STREAM` 输出可通过 poll 和 bounded-drain 形态发出。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把显式 installed-key 输出贯通到 pending-work 加 RFC 9368-compatible backend tick。
  单元测试证明到期 accepted 0-RTT recovery work 会被 service、compatible Version Information
  会被应用，并通过 poll 和 bounded-drain 形态发出调用方选择的 0-RTT 输出。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口在成功的 close-propagating RFC 9368-compatible backend sweep 中保留显式
  installed-key 输出，同时维持现有出错时停止在输出前的语义。单元测试证明 compatible
  Version Information 会被应用，并通过 poll 和 bounded-drain 形态发出调用方选择的 0-RTT 输出。
- 2026-06-24：新增 single-backend explicit-output drive wrapper：
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndDrainDatagramsWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions()`，
  以及对应 compatible-version 形态。这些入口用单个 backend drive view 复用跨连接显式
  output 实现，让简单 socket loop 可以 drive 一个 backend，同时 poll 或 drain 调用方选择的
  output views。单元测试证明分离的 backend/output connection 会发出 protected 0-RTT
  `RESET_STREAM` 输出，并覆盖 close/compatible 变体在空 output views 下的类型检查。
- 2026-06-24：新增 single-connection feed/backend explicit-output
  wrapper：
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagramsWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions()`，
  以及对应 compatible-version 形态。它们让简单 socket loop 可以 feed 一个已路由的
  installed-key datagram、drive 一个 backend，同时继续 poll 或 drain 调用方选择的
  installed-key output views。单元测试证明已路由 Handshake 输入会 drive backend，
  显式 0-RTT `RESET_STREAM` 输出可来自独立 output views，并覆盖 dropped datagram
  不会 drive close/compatible 变体。
- 2026-06-24：新增 single-connection pending-work/backend explicit-output
  wrapper：
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagramsWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions()`，
  以及对应 compatible-version 形态。它们让简单 socket loop 可以先 service 单个
  connection 的 pending timer，再 drive 一个 TLS backend，同时继续使用调用方选择的
  installed-key output views。单元测试证明 accepted 0-RTT PTO wakeup 在 poll 和
  bounded-drain 形态下都保留显式 `RESET_STREAM` 输出，并覆盖 close/compatible
  变体在空 output views 下的可调用性。
- 2026-07-02：新增 single-connection cross-space pending-work backend output
  wrapper：
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendAcrossSpacesAndPollDatagram()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendAcrossSpacesAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendAcrossSpacesAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendAcrossSpacesAndDrainDatagramsWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendAcrossSpacesOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendAcrossSpacesOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendAcrossSpacesOrCloseAndPollDatagramWithInstalledKeyOptions()`，
  以及
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendAcrossSpacesOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  它们复用 single-connection pending-work gate 和现有 cross-space backend/output helper，
  让简单 no-new-datagram socket-loop tick 可以 service 一个 connection、按有序 space
  drive backend，并 poll 或 drain 调用方选择的输出，而不需要构造 multi-connection view
  数组。单元测试证明 cross-space 显式 0-RTT poll/drain output，并保持新的 OrClose
  explicit-output 形态在空 output views 下可调用。
- 2026-06-11：更新 single-connection due-deadline-to-backend poll 和 bounded-drain
  wrapper，让它们保留显式 installed-key recovery output 选择。Initial recovery 仍只服务
  pending work、不发 installed-key datagram，并可继续进入 backend drive；Handshake 和
  Application recovery 会先校验调用方传入的输出空间再 poll。单元测试证明 accepted 0-RTT PTO
  wakeup 在 poll 和 drain wrapper 中都会返回 protected 0-RTT `RESET_STREAM` recovery datagram，
  并在 backend drive 前停止。
- 2026-06-11：新增
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把显式 installed-key recovery output 选择贯通到调用方持有 connection map 的 backend
  sweep 前。单元测试证明 accepted 0-RTT PTO wakeup 会按最早 deadline 被选中，发出 protected
  0-RTT `RESET_STREAM` datagram，跳过 backend drive/drain，并且不修改较晚 deadline 的连接。
- 2026-06-18：新增 close-propagating explicit-output 变体：
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions()`
  和
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口会在 OrClose backend sweep 前保留调用方选择的 installed-key output space。
  单元测试证明到期 accepted 0-RTT PTO wakeup 会保留 protected 0-RTT `RESET_STREAM`
  recovery output，并在 poll 和 bounded-drain 形态中都停在 backend drive 前。
- 2026-06-18：新增 RFC 9368-compatible explicit-output due-deadline backend
  变体：
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions()`
  和
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这些入口会在 compatible backend sweep 前保留显式 installed-key recovery output
  选择。单元测试证明到期 accepted 0-RTT PTO wakeup 会保留 protected 0-RTT
  `RESET_STREAM` output，并在 poll、drain 和 close-propagating 形态中都停在
  backend work 前。
- 2026-06-18：修正 cross-connection due-deadline backend
  `WithInstalledKeyOptions` 变体，让显式 installed-key 输出不仅用于 due recovery wakeup，
  也继续用于 backend poll/drain。普通变体仍使用 `EndpointConnectionPollView` 加共享
  `EndpointInstalledKeyDatagramSpace`；显式变体则端到端使用
  `EndpointConnectionInstalledKeyPollView`。单元测试证明 Application loss-time deadline
  在 due 阶段没有 datagram 时，可以继续进入 backend work，并通过 poll 和 bounded-drain
  形态发出调用方选择的 0-RTT `RESET_STREAM` 输出。
- 2026-06-24：新增 single-connection due-deadline backend explicit-output
  变体：
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceAndDrainDatagramsWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions()`，
  以及对应 compatible-version 形态。这些入口把 due recovery options 与 backend output
  views 分开，让 live Application loss-time deadline 可以先运行 backend work，再 poll 或
  drain 调用方选择的 0-RTT output。单元测试证明 poll 和 bounded-drain 的输出选择、deadline
  前不会 drive backend、以及 deadline 前 endpoint state 不变。
- 2026-07-02：新增 single-connection cross-space due-deadline backend output
  变体：
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendAcrossSpacesAndPollDatagram()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendAcrossSpacesAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendAcrossSpacesAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendAcrossSpacesAndDrainDatagramsWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendAcrossSpacesOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendAcrossSpacesOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendAcrossSpacesOrCloseAndPollDatagramWithInstalledKeyOptions()`，
  以及
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendAcrossSpacesOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这些入口复用 single-connection due-deadline ownership gate 和现有 cross-space
  backend/output helper，让没有 due datagram 的 live deadline 可以按有序 space drive backend，
  再 poll 或 drain 调用方选择的输出，而不引入另一套 backend 路径。单元测试证明 cross-space
  poll 和 bounded-drain 的显式 0-RTT output 选择，以及 deadline 前不会 drive backend。
- 2026-06-18：把内部 connection bookkeeping 记录拆到
  `src/quic/connection_state.zig`，同时保持 `src/lib.zig` 作为稳定 public module root。
  新模块负责 pending STREAM/CRYPTO frame、sent-packet metadata、pending close/control
  frame、path-challenge 记录、RTT/PTO snapshot 和 connection-ID rollback snapshot。
  验证保持同一组 856 个 transport 测试通过，证明该拆分不改变行为。
- 2026-06-18：把 packet-number-space 存储拆到
  `src/quic/packet_number_space.zig`，同时保持 `src/lib.zig` 作为稳定 public module root
  和内部兼容别名。新模块负责每个 space 的 packet-number、ACK、recovery、CRYPTO
  buffer、sent-packet、PTO probe、congestion probe 和 ECN validation state，以及借用字段
  view。验证保持 899 个测试通过，并保留现有公开 `@import("quicz")` 表面。
- 2026-06-18：把 stream ID 方向、发起方、stream count，以及 QUIC varint stream
  offset/range helper 拆到 `src/quic/stream_id.zig`，同时保持 `src/lib.zig` 内部兼容
  别名。聚焦单元测试固定低位 stream ID 编码、offset 溢出拒绝和非法 range 视为 overlap 的
  行为，后续再迁移有状态 stream send/receive state machine。
- 2026-06-18：收紧 `driveCryptoBackendInSpace()` 在已 discarded packet number space
  上的失败语义。现在 drive 会先拒绝已 discarded 的 space，再调用 backend callback，例如本端
  transport-parameter setup、入站 CRYPTO 投递或出站 CRYPTO 拉取。单元测试证明被拒绝路径不会
  触发 backend callback 计数。
- 2026-06-18：收紧 `driveCryptoBackendInSpace()` 在 closing/closed 连接上的失败语义。
  现在 drive 会在本端 transport-parameter setup、入站 CRYPTO 投递或出站 CRYPTO 拉取前返回
  `ConnectionClosed`。单元测试证明该路径不会触发 backend callback 计数。
- 2026-06-18：把 QUIC wire-length 预算 helper 拆到 `src/quic/wire_len.zig`，
  同时保持 `src/lib.zig` 的内部兼容别名。新模块负责 varint 长度、protected
  long/short datagram 长度、ACK/CRYPTO/STREAM/control frame 长度和 bounded frame data
  切片预算。新增单元测试覆盖 varint 边界和 Initial/short datagram 最小长度扩展，证明该拆分
  不改变发送路径的长度预算语义。
- 2026-06-18：把 ACK/frame packet-type 规则 helper 拆到
  `src/quic/frame_rules.zig`，同时保持 `src/lib.zig` 的公开
  `framePacketTypeErrorCode()` 包装和内部兼容别名。新模块负责 ACK range 校验、ACK
  membership 判断、ack-eliciting 分类、packet-number-space 到 frame packet type 映射，以及
  RFC 9000 frame/packet-type 许可表。新增单元测试覆盖 ACK range membership 和 Initial、
  Handshake、0-RTT、1-RTT frame 许可规则。
- 2026-06-10：新增 `EndpointConnectionView` 和
  `EndpointConnectionLifecycle.nextDeadlineAcrossConnections()`，服务于调用方持有
  connection map 的可嵌入 socket loop。lifecycle 现在可以在不接管 connection storage
  的前提下，基于调用方提供的 view slice，把 connection-owned idle/close deadline 和
  endpoint-owned recovery snapshot 合并选出最早 wakeup。单元测试证明 close timeout、idle
  timeout、recovery PTO 和没有 endpoint-visible deadline 的连接之间的选择顺序。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndSelectNextDeadline()`，
  作为 no-output pending-work-to-next-deadline socket-loop planning step。单元测试证明
  pending work 会在 wakeup selection 前退休 idle connection，较晚 recovery timer 保持
  armed，并为剩余 caller-owned connection map 返回 recovery deadline。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processPendingWorkAndSelectNextDeadline()`，
  作为 single-connection no-output pending-work-to-next-deadline planning step。
  单元测试证明未到期 recovery deadline 会保持不变，到期 recovery deadline 会先被服务，
  然后选出下一次 recovery wakeup。
- 2026-06-17：新增 `EndpointPendingWorkCryptoBackendNextDeadlineResult` 和
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndSelectNextDeadline()`，
  作为 no-output pending-work-to-backend-drive-to-next-deadline socket-loop
  step。单元测试证明 pending idle retirement 会先于 backend drive 执行，backend progress
  会刷新 endpoint recovery scheduling，并在不 poll output 的情况下选出对应 recovery deadline。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceAndSelectNextDeadline()`，
  作为 single-connection no-output pending-work/backend/deadline step。单元测试证明
  due recovery work 会先被服务再进入 backend drive，且同一 connection idle retirement
  会在 backend progress 前停止。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline()`，
  作为 close-propagating no-output pending-work-to-backend-drive-to-next-deadline
  socket-loop step。单元测试证明 pending idle retirement 会先于 close-propagating
  backend drive 执行，endpoint recovery scheduling 会被刷新，并在不 poll output
  的情况下选出对应 recovery deadline。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline()`，
  作为 single-connection close-propagating no-output pending-work/backend/deadline
  step。单元测试证明成功的 OrClose backend progress 会选出下一次 recovery deadline，
  peer transport-parameter error 会在 output pull 或 deadline result delivery 前停止。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline()`，
  作为 RFC 9368 compatible-version no-output pending-work-to-backend-drive-to-next-deadline
  socket-loop step。单元测试证明 pending idle retirement 会先于 compatible Version
  Information application 执行，endpoint recovery scheduling 会被刷新，并在不 poll output
  的情况下选出对应 recovery deadline。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline()`，
  作为 single-connection RFC 9368 compatible-version no-output pending-work/backend/deadline
  step。单元测试证明 due recovery work 后会应用 compatible Version Information，
  且同一 connection idle retirement 会在 backend progress 前停止。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`，
  作为 close-propagating RFC 9368 compatible-version no-output
  pending-work-to-backend-drive-to-next-deadline socket-loop step。单元测试证明
  pending idle retirement 会先于 compatible close-propagating backend drive 执行，
  Version Information 会被应用，endpoint recovery scheduling 会被刷新，并在不 poll output
  的情况下选出对应 recovery deadline。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`，
  作为 single-connection close-propagating RFC 9368 compatible-version no-output
  pending-work/backend/deadline step。单元测试证明成功的 compatible OrClose backend
  progress 会选出下一次 recovery deadline，idle retirement 会在 backend progress 前停止，
  且 incompatible Version Information 会在 output pull 或 deadline result delivery 前停止。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.processDueDeadlineAndSelectNextDeadline()` 和
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndSelectNextDeadline()`，
  作为 no-output due-deadline-to-next-deadline socket-loop planning step。单元测试证明
  deadline 前调用无副作用，单连接到期 recovery deadline 会被服务并重新调度，到期 idle
  deadline 会退休 endpoint route state，并为剩余 caller-owned connection map 返回下一条
  recovery deadline。
- 2026-06-10：新增 `EndpointConnectionPollView` 和
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndPollDatagram()`，
  让可嵌入 socket loop 在不把 connection storage 交给 lifecycle 的前提下，跨调用方持有的
  connection 集合分发最早且已经到期的 deadline。单元测试证明最早 deadline 前调用无副作用，
  到期时只有被选中的连接会发出 installed-key 1-RTT PTO probe，较晚 deadline 的连接不被触碰。
- 2026-06-10：新增 `EndpointConnectionReceiveView` 和
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnections()`，
  让 socket loop 可以在调用方持有的 connection 集合上路由并处理 installed-key datagram，
  不需要重复实现 endpoint route lookup 和 close-propagating protected receive 逻辑。
  单元测试证明 routed 1-RTT packet 会投递到匹配 connection ID 的连接，另一条 live
  caller-owned connection 不被触碰。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndSelectNextDeadline()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndSelectNextDeadline()`，
  作为 no-output receive-to-next-deadline socket-loop step。单元测试证明 routed installed-key
  1-RTT receive 会刷新被选中 connection 的 idle deadline，不触碰无关 caller-owned
  connection，并在不 poll output 的情况下返回下一条 deadline。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndSelectNextDeadline()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndSelectNextDeadline()`，
  作为 receive-to-pending-work-to-next-deadline socket-loop step。单元测试证明
  active-route stateless reset receive 会把 close timeout 作为下一次 wakeup 返回，
  收包步骤也可以在选择下一条 deadline 前退休到期的 closing endpoint state。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDrainDatagrams()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDrainDatagrams()`，
  作为 receive-to-pending-work-to-bounded-drain socket-loop step。单元测试证明 dropped
  input 在 pending work 后仍能 drain 已排队的 installed-key output，单连接入口会在任何
  output drain 前先退休到期的 closing state。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDrainDatagramsWithInstalledKeyOptions()`，
  以及
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDrainDatagramsWithInstalledKeyOptions()`，
  让调用方持有 connection map 的 socket loop 和简单单连接 socket loop 都可以在
  receive processing 和 pending work 后继续保留显式 installed-key output 选择。单元测试证明
  dropped input 后仍能 drain 调用方选择的 0-RTT output，且 single-connection
  explicit 形态在 due close cleanup 退休连接后仍会停止在 output 前。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndPollDatagram()`，
  以及
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndPollDatagramWithInstalledKeyOptions()`，
  作为 receive-to-pending-work-to-output socket-loop step。单元测试证明 dropped input
  在 pending work 后仍能 poll 已排队的 installed-key output，单连接入口会在 due closing
  state retire 后停止 output polling，显式 installed-key options 会保留调用方选择的 0-RTT
  output，并覆盖 cross-connection 和 single-connection 两种形态。结果契约放在
  `src/quic/endpoint_types.zig`，并从 `src/lib.zig` re-export。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`，
  作为 RFC 9368-compatible receive-to-pending-work-to-backend-to-next-deadline
  socket-loop step。单元测试证明 routed Handshake input 会先处理 pending work，再通过
  backend 应用对端 Version Information、选择 compatible version、应用对端 transport
  parameters，并返回下一条 endpoint deadline。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline()`，
  作为 close-propagating receive-to-pending-work-to-backend-to-next-deadline
  socket-loop step。单元测试证明 routed Handshake input 可以在对端 transport parameter
  无效时排队 CONNECTION_CLOSE，并在生成 deadline result 前返回 backend 错误。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`，
  作为 close-propagating receive-to-pending-work-to-backend-to-output socket-loop
  step。单元测试证明 backend 对端 transport parameter 错误会先排队 CONNECTION_CLOSE
  并停止 output polling；成功路径仍能保留显式 output options 并 poll/drain protected
  Handshake response。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndSelectNextDeadline()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndSelectNextDeadline()`，
  作为 receive-to-pending-work-to-backend-to-next-deadline socket-loop step。单元测试证明
  routed Handshake input 可以先处理 pending work，再驱动调用方持有的 backend、排队
  protected output，并在不 poll output 的情况下返回下一条 endpoint deadline。结果契约放在
  `src/quic/endpoint_types.zig`，并从 `src/lib.zig` re-export。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndPollDatagram()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagram()`，
  作为 receive-to-pending-work-to-backend-to-output socket-loop step。单元测试证明 routed
  Handshake input 可以驱动调用方持有的 backend，并在同一个 lifecycle call 中返回 protected
  Handshake response datagram。结果契约放在 `src/quic/endpoint_types.zig`，并从
  `src/lib.zig` re-export。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndDrainDatagrams()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagrams()`，
  作为 bounded receive-to-pending-work-to-backend-to-output socket-loop step。单元测试证明
  routed Handshake input 可以驱动调用方持有的 backend，把一个 protected Handshake response
  drain 到调用方持有的 output slice，并在同一个 lifecycle call 中保持 endpoint pending-work
  顺序。结果契约放在 `src/quic/endpoint_types.zig`，并从 `src/lib.zig` re-export。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions()`，
  让调用方持有 connection map 的 socket loop 可以在 receive processing、pending work 和
  backend progress 后继续保留每条连接自己的 installed-key output 选择。单元测试证明 explicit
  Handshake output options 可以在同一个 lifecycle call 中返回和 drain protected backend response。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions()`
  和 `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`，
  作为 RFC 9368-compatible receive-to-pending-work-to-backend-to-output
  socket-loop step。单元测试证明 routed Handshake input 会运行 pending work，通过 backend
  应用对端 Version Information，保留显式 installed-key output options，并 poll/drain
  protected 0-RTT output；OrClose drain 路径保持相同成功路径契约。
- 2026-06-24：新增单连接 explicit-output 入口
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceAndDrainDatagramsWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions()`，
  以及匹配的 compatible-version 形式。调用方可以在简单 socket loop 中 feed 一条
  routed installed-key datagram、处理 pending work、驱动一个调用方持有的 backend，同时仍按
  调用方指定的 installed-key output view poll/drain 输出。单元测试证明 routed Handshake
  input 会驱动 backend，显式 0-RTT `RESET_STREAM` output 来自调用方选择的 output view，
  dropped datagram 不会驱动任何变体。
- 2026-06-24：将连接级纯规则拆到 `src/quic/connection_rules.zig`，同时保持
  `src/lib.zig` 作为公开 re-export surface。迁出的规则覆盖 ACK-eliciting send-admission
  分类、Initial DCID 长度校验、stateless reset token 比较，以及 transport-parameter
  validation error 映射。
- 2026-06-24：将纯 Version Negotiation endpoint result 契约
  `EndpointVersionNegotiationResult` 和 `EndpointVersionNegotiationFollowupResult`
  迁到 `src/quic/endpoint_types.zig`，同时保持 `src/lib.zig` 作为公开 re-export surface。
  持有 `Connection` 的 Version Negotiation handoff result 会等 `Connection` 拆出独立模块后再迁。
- 2026-06-24：将 `src/lib.zig` 中的 frame packet-type error wrapper 改成从
  `src/quic/frame_rules.zig` 直接公开 re-export。公开 `framePacketTypeErrorCode()` API
  保持稳定，RFC 9000 frame 许可和错误分类继续归属 frame-rule 模块。
- 2026-06-10：新增
  `EndpointConnectionLifecycle.pollDatagramAcrossConnections()` 和
  `EndpointPolledDatagramResult`，服务于调用方持有 connection map 的输出轮询。socket
  loop 现在可以让 lifecycle owner 按调用方给定顺序跨 connection slice 轮询 installed-key
  output，而不需要在每条连接周围重复实现 timer mirroring。单元测试证明会选择第一条有排队输出的
  connection 并产出 protected 1-RTT PING，排在前面的 idle connection 不会发送。
- 2026-06-10：新增 `EndpointDatagramDrainResult` 和
  `EndpointConnectionLifecycle.drainDatagramsAcrossConnections()`，让可嵌入 socket
  loop 可以把 installed-key output drain 到调用方持有的 result slot，并用输出 slice
  明确限制单轮工作量。结果会在后续 poll 失败时保留已初始化条目数量，确保调用方仍能释放已
  drain 的 datagram。单元测试证明一格 batch 只产出第一条有排队输出的连接，后续 drain
  会继续取出剩余连接的输出。
- 2026-06-10：新增 `EndpointPendingWorkSweepResult` 和
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnections()`，让 socket loop
  可以在不接管 connection storage 的前提下，跨调用方持有的连接集合执行 idle timeout、
  close/drain timeout 和 recovery timer work。单元测试证明同一轮 sweep 可以退休一条 idle
  connection，并 service 另一条连接的到期 recovery timer，同时保留后者为 active。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把显式 installed-key 输出贯通到 pending-work 加 close-propagating
  RFC 9368-compatible backend tick。单元测试证明到期 accepted 0-RTT recovery work
  会被 service、compatible Version Information 会被应用，并通过 poll 和 bounded-drain
  形态发出调用方选择的 0-RTT 输出，同时保留出错时停止在输出前的语义。
- 2026-06-10：新增 `EndpointPendingWorkCryptoBackendDatagramResult` 和
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram()`，
  服务于没有新入站 datagram 的 loop tick。该 helper 会先处理 idle/close/recovery
  pending work，再驱动调用方持有的 TLS backend，最后跨 caller-owned connection poll
  installed-key output。单元测试证明到期 Application PTO 可以在同一个 lifecycle-owned
  API step 中被 service，并作为 protected 1-RTT PING probe 发出，同时不接管 backend storage。
- 2026-06-10：新增 pending-work backend loop 的 close-propagating 与 RFC 9368
  compatible-version 变体：
  `processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram()`、
  `processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram()`、
  以及
  `processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`。
  单元测试证明 timer/flush tick 可在 peer transport-parameter 错误时先排队 close
  并停止 output poll，也可通过同一个 lifecycle-owned API 边界应用已认证的 compatible
  Version Information，并排队 compatible-version close 状态。
- 2026-06-10：新增 `EndpointDueWorkCryptoBackendDatagramResult` 和 due-deadline
  backend loop 变体：
  `processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram()`、
  `processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram()`、
  `processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram()`、
  以及
  `processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`。
  这些 helper 会先处理 caller-owned connection 集合中最早到期的 deadline；如果 due
  recovery 已经产出 datagram，则直接把 datagram 交还调用方，不继续驱动 TLS backend；
  live no-output due work 才继续进入 backend drive 和 output polling，terminal idle/close
  cleanup 会在 backend progress 之前停止。单元测试证明
  one-output ownership、close-propagating backend error、compatible Version Information
  应用，以及 compatible-version close propagation 都经过同一个 lifecycle-owned wakeup API。
- 2026-06-18：新增 `EndpointDueWorkCryptoBackendNextDeadlineResult` 和
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndSelectNextDeadline()`，
  作为 no-output due-deadline-to-backend-drive-to-next-deadline socket-loop step。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline()`，
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline()`，
  和
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline()`，
  作为 close-propagating 与 compatible-version no-output due-deadline/backend/deadline
  step。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`，
  和
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`，
  作为 single/cross compatible-version close-propagating no-output due-deadline/backend/deadline
  step。next-deadline due 路径的单元测试证明最早到期的 recovery deadline 会先被服务，
  backend progress 会刷新另一条 connection 的 recovery scheduling，compatible Version
  Information 会被应用，并在不 poll output 的情况下选出对应 recovery deadline。
- 2026-06-10：新增 `EndpointCryptoBackendDriveView`、
  `EndpointCryptoBackendDriveSweepResult` 和
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceAndArmConnections()`，
  让 TLS-backed socket loop 可以在一轮 lifecycle-owned sweep 中驱动调用方持有的
  connection/backend pair。该 helper 复用单连接 backend drive 路径，并为每条连接刷新
  endpoint recovery scheduling。单元测试证明两条 caller-owned backend 都会被驱动，
  outbound Handshake CRYPTO bytes 会聚合到 progress 计数，且每条连接各自收到排队的
  CRYPTO output。
- 2026-06-17：新增 `EndpointCryptoBackendDriveNextDeadlineResult`、
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceAndSelectNextDeadline()` 和
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndSelectNextDeadline()`，
  作为 no-output backend-drive-to-next-deadline socket-loop step。单元测试证明 backend
  drive 会为已有 application in-flight data 的连接刷新 endpoint recovery scheduling，并在
  不 poll output 的情况下返回对应 recovery deadline。
- 2026-06-10：新增
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceOrCloseAndArmConnections()`，
  服务于 TLS-backed socket loop 中需要 close-propagating peer transport-parameter
  处理的 connection/backend 批量驱动。该 sweep 在第一条 backend 错误处停止，避免用后续
  backend work 遮蔽原始连接错误。单元测试证明前一条 backend 可以排队 CRYPTO output，
  失败 backend 进入 closing 且不会拉取 output，后续 backend 不会被驱动。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceOrCloseAndSelectNextDeadline()`
  和
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndSelectNextDeadline()`，
  作为 close-propagating no-output backend-drive-to-next-deadline socket-loop
  step。单元测试证明成功 backend drive 会刷新 endpoint recovery scheduling，并在
  不 poll output 的情况下返回对应 recovery deadline；backend 错误继续沿用既有
  close-propagating sweep 语义。
- 2026-06-10：新增
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionAndArmConnections()`
  和
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndArmConnections()`，
  服务于 RFC 9368 compatible-version TLS backend 在 caller-owned
  connection/backend pair 上的批量 sweep。成功路径会跨多条连接聚合 peer
  transport-parameter bytes、compatible-version selection、handshake confirmation
  和 recovery-timer refresh；close-propagating 路径会在第一处 peer Version
  Information 错误处停止，并保持后续 backend 未驱动。单元测试覆盖两条连接的
  compatible-version 成功路径和 first-error close 路径。
- 2026-06-17：新增
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`
  和
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndSelectNextDeadline()`，
  作为 RFC 9368 compatible-version no-output backend-drive-to-next-deadline
  socket-loop step。单元测试证明 compatible Version Information application、
  endpoint recovery scheduling refresh 和 recovery deadline selection 可以在
  不 poll output 的情况下完成。
- 2026-06-10：新增 `EndpointCryptoBackendDriveDatagramResult`，以及
  backend-drive-to-datagram loop step：
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceAndPollDatagram()`、
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndPollDatagram()`、
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram()`、
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`、
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`、
  以及
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`。
  这些 helper 会把一次 lifecycle-owned TLS backend sweep 和跨 caller-owned
  connection 的 installed-key datagram polling 合在同一层 API 中，但不接管
  connection/backend storage。单元测试证明 backend 产出的 Handshake CRYPTO 可以在同一个
  面向 loop 的 API step 中被驱动、组包为 protected installed-key Handshake datagram，
  并由对端作为 CRYPTO bytes 消费。单连接形态复用同一 sweep path，只接收一个
  connection/backend pair，并证明 one-datagram polling、close-before-poll
  suppression 和 compatible-version peer information 处理。
- 2026-06-10：新增 `EndpointCryptoBackendDriveDatagramDrainResult`，以及
  backend-drive-to-bounded-drain loop step：
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.driveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams()`
  和
  `EndpointConnectionLifecycle.driveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`。
  这些 helper 会把 backend progress 与 caller-owned output queue 的 bounded drain
  合在同一个 lifecycle-owned API step。单元测试证明 backend sweep 后可以 drain 多个已排队
  installed-key datagram；close-propagating backend error 会在初始化任何输出槽之前停止；
  compatible-version 变体会在 drain 前应用或拒绝 peer Version Information。单连接形态复用
  同一 sweep path，只传入一个 connection/backend pair，并证明一格 bounded drain、
  close-before-drain suppression 和 compatible-version peer information 处理。
- 2026-06-10：新增 `EndpointFeedCryptoBackendDriveDatagramResult` 和
  receive-to-backend-to-output loop step：
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagram()`，
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`、
  以及
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`。
  这些 helper 服务于 caller-owned connection/backend map。被 route 的 installed-key datagram
  会先处理到连接，再由选定 backend sweep 消费收到的 CRYPTO，并在同一个
  lifecycle-owned API step 中 poll installed-key output。非 routed 的 Version
  Negotiation、stateless reset、supported Initial acceptance 和 drop 结果会直接返回，
  不会驱动 backend。单元测试证明 protected Handshake CRYPTO datagram 会被路由到
  server connection，经 backend 消费后产出 protected Handshake response datagram，
  并由对端作为 CRYPTO bytes 消费；也证明 dropped datagram 不会驱动
  OrClose/compatible backend，且 close-propagating backend peer-parameter 错误会在
  output polling 前停止。单连接形态复用同一 lifecycle path，只接收一个
  connection/backend pair，并证明 routed receive-to-backend-to-poll response
  delivery、close-before-poll suppression、compatible peer Version Information
  application，以及 compatible-version close-before-poll suppression。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把 per-connection installed-key output options 贯通到直接
  routed receive-to-output socket-loop step。单元测试证明 routed protected
  1-RTT datagram 可以被处理，并通过调用方选择的 poll 和 bounded-drain options
  发出 ACK output，同时 decoy connection 不被影响。
- 2026-06-24：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDrainDatagramsWithInstalledKeyOptions()`，
  作为直接 receive-to-output explicit output step 的单连接形态。单元测试证明简单
  socket loop 可以 feed 一条 routed protected 1-RTT datagram，并继续通过调用方选择的
  installed-key output view poll 或 drain 输出，同时保持既有 cross-connection route 和
  output 行为。
- 2026-06-18：新增
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把 per-connection installed-key output options 贯通到 routed
  receive-to-backend loop step。单元测试证明 routed Handshake CRYPTO datagram
  仍会驱动 backend input，同时调用方选择的 0-RTT output 会通过 poll 和 bounded-drain
  形态从 caller-owned connection 发出。
- 2026-06-18：新增 close-propagating explicit-output 变体：
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把 per-connection installed-key output options 贯通到 routed
  receive-to-backend loop step，同时保留 OrClose backend 行为。单元测试证明 routed
  Handshake CRYPTO input 仍会驱动 backend，并在 close-propagating backend 成功推进后
  通过 poll 和 bounded-drain 形态发出调用方选择的 0-RTT output。
- 2026-06-18：新增 RFC 9368-compatible explicit-output 变体：
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把 per-connection installed-key output options 贯通到 routed
  receive-to-compatible-backend loop step。单元测试证明 routed Handshake CRYPTO
  input 仍会驱动 compatible backend progress、compatible Version Information 会被应用，
  并通过 poll 和 bounded-drain 形态发出调用方选择的 0-RTT output。
- 2026-06-18：新增 RFC 9368-compatible close-propagating explicit-output
  变体：
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndPollDatagramWithInstalledKeyOptions()` 和
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagramsWithInstalledKeyOptions()`。
  这两个入口把 per-connection installed-key output options 贯通到 routed
  receive-to-compatible-backend loop step，同时保留 OrClose 语义。单元测试证明
  compatible Version Information 成功应用后 connection 保持 open，并通过 poll 和
  bounded-drain 形态发出调用方选择的 0-RTT output；dropped datagram 仍会在 backend
  drive 前返回。
- 2026-06-10：新增 `EndpointFeedCryptoBackendDriveDatagramDrainResult`，以及
  receive-to-backend-to-bounded-drain loop step：
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams()`
  和
  `EndpointConnectionLifecycle.feedDatagramWithInstalledKeysAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`。
  这些 helper 会把 routed installed-key receive、选定 TLS backend sweep 和
  caller-owned output queue 的 bounded drain 合在同一个 lifecycle-owned API step，
  但不接管 connection/backend storage。单元测试证明 routed Handshake CRYPTO
  datagram 可以驱动 backend output，并在同一 loop step 中 drain 多个 protected
  response datagram；单连接形态复用同一 lifecycle path，只接收一个 connection/backend
  pair，并证明一格 bounded drain 和后续 peer delivery；单连接 compatible-version
  形态还证明 peer Version Information 会先应用再执行 bounded drain，其 OrClose 形态在
  未选出 compatible version 时会排队 CONNECTION_CLOSE 并在 output draining 前停止。
  dropped datagram 不会驱动 backend，close-propagating peer-parameter 错误会在
  output draining 前停止。
- 2026-06-11：新增 cross-connection pending-work-to-output 和
  pending-work-to-bounded-drain loop step：
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndPollDatagram()`
  和
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDrainDatagrams()`。
  这些 no-backend helper 会先对 caller-owned connection sweep idle/close/recovery
  work，再执行 installed-key output poll 或 bounded drain。单元测试证明无 recovery
  timer 被 service 时不会偷跑普通 queued output；PTO wakeup 被 service 后可以返回一个
  protected output datagram；bounded drain 可在一个 loop step 中返回两个
  caller-owned connection 的 PTO output。
- 2026-06-10：新增 pending-work-to-backend-to-output 和
  pending-work-to-backend-to-bounded-drain loop step：
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceAndPollDatagram()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams()`
  和
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`。
  这些 helper 会先执行 endpoint pending work，再推进 TLS backend progress，并执行
  caller-owned output queue 的 bounded drain。单元测试证明 no-new-datagram loop tick
  可以驱动 backend 并 drain 多个已排队 installed-key datagram；单连接
  compatible-version 形态证明 peer Version Information 会先应用再执行 bounded drain，
  其 OrClose 形态在未选出 compatible version 时会排队 CONNECTION_CLOSE 并在 output
  draining 前停止；close-propagating backend error 现在会在调用方提供同连接 output view
  时返回该连接的 close output，缺少匹配 view 时仍先返回错误且不消费无关连接输出。单连接 output-polling 形态证明
  one-datagram polling、close-before-poll suppression、compatible peer Version
  Information 处理，以及 compatible-version close-before-poll suppression。
- 2026-07-02：新增 cross-space RFC 9368-compatible backend-drive primitive：
  `Connection.driveCryptoBackendAcrossSpacesWithCompatibleVersion()`、
  `Connection.driveCryptoBackendAcrossSpacesWithCompatibleVersionOrClose()`、
  `EndpointConnectionLifecycle.driveCryptoBackendAcrossSpacesWithCompatibleVersionAndArmConnection()`、
  `EndpointConnectionLifecycle.driveCryptoBackendsAcrossSpacesWithCompatibleVersionAndArmConnections()`、
  `EndpointConnectionLifecycle.driveCryptoBackendAcrossSpacesWithCompatibleVersionAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.driveCryptoBackendsAcrossSpacesWithCompatibleVersionAndSelectNextDeadline()`，
  以及对应 OrClose 形态。它们复用现有 ordered-space backend drive 和 compatible
  peer-parameter policy，让 socket loop 可以在一个 lifecycle step 中处理 Initial/Handshake
  backend work 与 compatible Version Information。单元测试证明跨 space 的 compatible
  Version Information application、deadline selection、close-before-output 行为和首错停止 sweep。
- 2026-07-02：新增 cross-space RFC 9368-compatible backend-drive output 变体，覆盖
  poll、显式 poll、bounded drain、显式 bounded drain 和对应 OrClose 形态。这些 helper
  复用 cross-space compatible backend-drive primitive 与现有 installed-key output poll/drain
  路径。单元测试证明 compatible cross-space backend progress 后可以发出显式 0-RTT output，
  并确认 OrClose 错误会在拉取 output 前返回。
- 2026-07-03：新增 cross-space RFC 9368-compatible lifecycle no-output wrapper，
  覆盖 pending-work 和 due-deadline deadline selection：
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendAcrossSpacesWithCompatibleVersionAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.processPendingWorkAndDriveCryptoBackendAcrossSpacesWithCompatibleVersionOrCloseAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesWithCompatibleVersionAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.processPendingWorkAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesWithCompatibleVersionOrCloseAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendAcrossSpacesWithCompatibleVersionAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendAcrossSpacesWithCompatibleVersionOrCloseAndSelectNextDeadline()`、
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesWithCompatibleVersionAndSelectNextDeadline()`，
  以及
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsAcrossSpacesWithCompatibleVersionOrCloseAndSelectNextDeadline()`。
  它们把现有 pending-work 和 due-deadline ownership gate 与 cross-space compatible
  backend-drive primitive 组合。单元测试证明单连接和跨连接在 compatible cross-space
  backend progress 后的 deadline selection，以及 deadline 前 no-op。
- 2026-06-10：新增 due-deadline-to-backend-to-output 和
  due-deadline-to-backend-to-bounded-drain loop step：
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceAndPollDatagram()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndPollDatagram()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndPollDatagram()`、
  `EndpointConnectionLifecycle.processDueDeadlineAndDriveCryptoBackendInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceOrCloseAndDrainDatagrams()`、
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionAndDrainDatagrams()`
  和
  `EndpointConnectionLifecycle.processDueDeadlineAcrossConnectionsAndDriveCryptoBackendsInSpaceWithCompatibleVersionOrCloseAndDrainDatagrams()`。
  这些 helper 保留 due recovery datagram 的所有权规则：deadline 已产出 protected
  probe 时不会驱动 backend；deadline 没有 datagram 时，backend progress 和
  bounded output draining 会在同一个 lifecycle-owned step 中执行；单连接形态在
  idle/close 这类终止清理后会停止，不再驱动 backend；它的 OrClose 形态会在 backend
  peer-parameter 错误时排队 CONNECTION_CLOSE，并在存在同连接 output view 时返回 close output；单连接
  compatible-version 形态证明无 installed-key datagram 的 Initial recovery wakeup 后会
  先应用 peer Version Information 再执行 bounded drain，其 OrClose 形态在未选出
  compatible version 时会排队 CONNECTION_CLOSE 并在 output draining 前停止。单元测试覆盖
  recovery datagram 所有权、无输出 deadline 后的 backend drive、close-propagating
  drain suppression，以及 Initial recovery wakeup 不产出 installed-key datagram
  时继续进入 Handshake backend output；一格预算只发出第一段 protected datagram，
  剩余 backend CRYPTO 可由后续 drain 交付给 peer。单连接 output-polling 形态证明同样的
  no-output deadline backend progression：one-datagram polling、close-before-poll
  suppression、compatible peer Version Information 处理，以及 compatible-version
  close-before-poll suppression。跨连接 output-polling 和 bounded-drain 形态现在也会在
  terminal idle/close cleanup 后停止，不再驱动 backend；close-propagating 和
  compatible-version 变体同样覆盖该边界。
- 2026-06-05：扩展 `examples/tls_openssl_backend_adapter.zig`，让 server
  connection probe 通过 OpenSSL-backed backend 拉取真实 pair-transcript 1-RTT
  secrets，报告 handshake confirmation，并通过同一条 `driveCryptoBackendInSpace()`
  路径丢弃 server Handshake packet-number-space keys。同一个 probe 现在也会证明已应用
  peer transport parameters 后的 server-side bidirectional stream-count limit。示例现在会打印
  `server_connection_initial=1511/1184/1223/1184/43/true/3/8/true`，依次证明 server
  Initial CRYPTO bytes、server output bytes、protected Initial datagram bytes、
  client-read Initial CRYPTO bytes、peer transport-parameter bytes、Handshake
  key 安装、OpenSSL secret callback 次数、允许的 8 条 peer-limited bidirectional
  streams，以及第 9 次 open 被阻塞。示例也会打印
  `server_connection_application=true/true/true/false`，依次证明 server 1-RTT key
  安装、server 已确认、server Handshake space 已丢弃和 server Handshake keys 已清理。
  paired loopback server 现在也会通过 backend 消费 loopback UDP 上的 client
  Handshake CRYPTO，拉取 peer transport parameters 与 Handshake/1-RTT secrets，
  确认并清理 Handshake keys；`peer_backend=36/72/43/36/36/true/true/true/true/false`
  依次记录 CRYPTO bytes、datagram bytes、peer transport-parameter bytes、backend
  inbound/released bytes、key 安装、确认、discard 和 Handshake keys 清理。direct
  OpenSSL server probe 现在也会消费 Handshake CRYPTO，并打印
  `server_probe_initial=1547/1184/36` 与 `server_probe_confirmed=true`，依次证明
  total received CRYPTO bytes、server Initial output bytes、Handshake released
  bytes 和确认。完整
  endpoint-owned live TLS handshake/socket loop 仍待实现。
- 2026-06-04：扩展 `examples/tls_openssl_backend_adapter.zig`，让
  OpenSSL-backed `TlsBackend` wrapper 调用 `SSL_do_handshake()`，并在把 quicz 本端
  transport parameters 传入 `SSL_set_quic_tls_transport_params()` 后，通过现有 quicz
  CRYPTO output 路径产出第一段 TLS CRYPTO flight。该示例仍记录 OpenSSL callback mode
  与 OpenSSL full QUIC mode 不同，也能消费 pair-transcript server transport
  parameters，并让 Handshake secrets、1-RTT secrets 和 Handshake CRYPTO bytes 经 OpenSSL callback 边界进入
  连接层；同时会把 adapter 产出的 Initial CRYPTO flight 作为 protected Initial
  datagram 通过 loopback UDP 投递，并把真实 pair-transcript Handshake CRYPTO 作为
  protected Handshake datagram 通过 loopback UDP 投递。当前这些 Handshake/1-RTT
  secrets 与 Handshake CRYPTO bytes 已复用真实 pair transcript，并会用 adapter 安装的
  client keys 和匹配 peer transcript secrets 驱动 loopback UDP 1-RTT STREAM echo；
  同一个 lifecycle owner 现在也会服务 client Application PTO，并把 protected probe 路由到
  server，且不会重复交付重复 STREAM data；OpenSSL recv/release 消费入站
  Handshake CRYPTO 后，OpenSSL-backed `handshake_confirmed` callback 确认
  client，并通过 no-output Handshake drive 丢弃 client Handshake packet-number
  space 和 keys；配对 loopback server 侧 backend confirmation 留到下一步 adapter
  证据；Initial、Handshake、Application echo、
  Application PTO、protected close 和 close/drain timeout cleanup 现在共用同一个
  socket/lifecycle loop owner；示例会打印匹配的 `peer_tp_bytes` 和 `transcript_tp`
  证明连接层应用的 peer bytes 来自 quicz 编码后配置给 OpenSSL 的 pair transcript，也会打印 `transcript_keylog=5/5/773/773`
  证明完整 OpenSSL pair transcript 的 keylog callback/bytes，并打印 `adapter_keylog=0/0`
  记录当前 callback-mode wrapper 边界；示例还会打印 `adapter_pto=62/53/511/1`，依次证明 PTO
  deadline、PTO datagram bytes、server route 和 server ACK largest，也会打印
  `adapter_key_discard=true/true/true/true/false/false`，依次证明 client/server 已确认、
  client/server Handshake space 已丢弃、client/server Handshake keys 已清理，然后在退役全部
  client/server route 后打印 `adapter_endpoint_routes=3/4/0/0`。
  完整 endpoint-owned live TLS handshake/socket loop 仍待实现。
- 2026-06-04：新增 `examples/tls_openssl_probe.zig` 和通过 `pkg-config` 链接
  OpenSSL 的小 C probe。该 probe 验证 OpenSSL 暴露可用 QUIC method，且普通 TLS
  object 可以设置 QUIC TLS callbacks 和本端 transport-parameter bytes；同时记录
  OpenSSL callback mode 与 OpenSSL 完整 QUIC connection mode 不同，因为设置
  callbacks 后 `SSL_is_quic()` 仍为 false。完整 endpoint-owned live TLS
  handshake/socket loop 仍待实现。
- 2026-06-04：新增 `examples/tls_c_abi_adapter.zig` 和 C 编译 demo callback
  object，证明 `TlsBackend` 不只可以由 Zig 的 C calling convention 函数驱动，也可以由
  真实 C object 驱动。这仍不等于绑定具体 TLS 库，但验证了下一步接入成熟 C TLS
  backend 所需的 FFI 边界。
- 2026-06-04：新增 `examples/tls_backend_adapter.zig` 和
  `zig build run-tls-backend-adapter`，用可运行示例验证 C-ABI `TlsBackend`
  adapter 契约。这个示例尚不绑定具体 TLS 库；它先验证真实 C TLS 绑定前需要稳定的窄
  adapter 边界：本端/对端 transport-parameter bytes、入站/出站 CRYPTO bytes、
  Handshake traffic secret 安装和 handshake confirmation。
- 2026-06-04：新增很小的 C-ABI `TlsBackend` adapter，把 C TLS callback 的
  status-code/output-buffer 形式转换为现有 `CryptoBackend` drive 路径。单元测试证明
  通过该 adapter 可以完成本端/对端 transport-parameter handoff、入站与出站 CRYPTO
  bytes、Handshake traffic-secret 安装和 handshake confirmation。该单元测试本身不绑定具体
  TLS 库；后续 OpenSSL 示例覆盖真实库 callback-mode 绑定证据。
- 2026-06-18：收紧 C-ABI `TlsBackend` adapter 的 status 边界。pull-style callback
  仍使用 `pending` 表示当前没有可拉取的 bytes 或 secrets；必须在当前 drive step 消费输入的
  callback 现在会把 `pending` 视为 adapter 协议错误。单元测试证明 `receive` 和本端
  transport-parameter 设置不会再把 `pending` 静默当作成功，同时 CRYPTO output pull
  保持无输出行为。
- 2026-06-18：补齐 C-ABI `TlsBackend` adapter 的 output-buffer status guard。
  pull-style callback 返回 `pending` 时必须报告 0 个已写字节；`pending` 同时携带 bytes
  会被视为 adapter 协议错误，避免 CRYPTO output 或对端 transport-parameter bytes
  在 C 边界被静默丢弃。
- 2026-06-18：在 `driveCryptoBackendInSpace()` 中保留 backend receive 失败时的入站
  CRYPTO bytes。drive loop 现在会在 `backend.receive()` 返回错误时恢复对应 packet number
  space 的 CRYPTO read offset，避免失败的 TLS backend step 在调用方选择重试、close
  propagation 或 teardown 前消耗输入 bytes。
- 2026-06-04：记录实现策略：成熟非核心能力优先适配，不在仓库内重复自研。`quicz`
  自己负责 QUIC transport state、packet processing、recovery、endpoint lifecycle 和
  Zig API；TLS 等配套能力应放在窄 adapter 后面接入维护良好的库。
- 2026-06-04：把实用目标重新收敛为成熟 QUIC transport 的共同能力基线，不再把所有
  QUIC 可选扩展都当作第一轮里程碑内容。新增基线表逐项记录第一轮必需功能、延后扩展
  和 `quicz` 当前状态。
- 2026-06-04：新增当前 mock/installed-key 加 endpoint lifecycle 可验证覆盖阶段的
  明确边界。任务计划现在说明，现有 socket-backed loopback 能证明实验性骨架的
  protected routing、recovery-timer service 和 endpoint lifecycle 行为，但不能证明完整
  TLS-owned QUIC。下一里程碑是通过很小的 Zig `TlsBackend` adapter 接入 C TLS 库后实现
  endpoint-owned live TLS handshake/socket loop，需要 transport-parameter transcript
  handoff、traffic-secret ownership、lifecycle cleanup，以及外部互通证据或明确互通
  blocker。
- 2026-06-02：把 UDP Version Negotiation follow-up server
  transport-parameter validation 切到 TLS extension bytes。server 现在编码本端
  transport parameters，follow-up client 解析并应用这些 bytes，继续验证
  Original DCID、Initial SCID 和 Version Information；示例也会证明 malformed
  transport-parameter bytes 会排队 `TRANSPORT_PARAMETER_ERROR`；
  `run-udp-endpoint-loopback` 现在打印 `server_tp_bytes` 和
  `malformed_tp_close`，以及 `followup_timers`。
- 2026-06-02：在 UDP Version Negotiation follow-up loopback 中新增 server
  transport-parameter validation。protected server Initial 路由到 follow-up
  client 后，示例会应用 server authenticated transport parameters 并校验
  selected Version Information；`run-udp-endpoint-loopback` 现在打印
  `server_tp_version=0x6b3343cf`。
- 2026-06-02：新增 Version Negotiation follow-up Original DCID 证据。
  lifecycle protected follow-up Initial 测试现在会断言返回的 follow-up
  connection 记录旧 Initial Destination CID，供后续 transport-parameter 校验；
  `run-udp-endpoint-loopback` 现在打印 `followup_odcid_len=8`。
- 2026-06-02：在 `CryptoBackendProgress` 中新增 selected compatible-version
  reporting。Compatible backend peer-parameter drive 现在会直接在 drive
  结果中返回选中的 QUIC version，strict drive 保持该字段为 null；
  `run-crypto-stream` 会从 backend progress 打印 selected version。
- 2026-06-02：新增通过 `CryptoBackend` peer transport-parameter bytes 的
  compatible Version Information handoff。
  `driveCryptoBackendInSpaceWithCompatibleVersion()` 及其 close-propagating
  变体会在拉取 backend output 前，用显式 RFC 9368 compatibility 应用 backend
  提供的对端参数；`run-crypto-stream` 现在打印
  `backend_compatible_version selected=0x6b3343cf peer_versions=2`。
- 2026-06-02：新增 server-side compatible Version Information application。
  `Connection` 现在保存 peer Version Information snapshot，暴露
  `peerVersionInformation()` / `selectPeerCompatibleVersion()`，并提供 byte
  和 close-propagating compatible apply 路径，要求 selected version 必须等于
  server connection 配置的 `chosen_version`；`run-transport-parameters` 现在打印
  `compatible_selected=0x6b3343cf` 和 `compatible_peer_versions=2`。
- 2026-06-02：新增显式 RFC 9368 compatible-version selection helper。
  `VersionCompatibility` 记录 directional first-flight compatibility，
  `selectCompatibleVersion()` 只会选择 client 已声明、非 reserved、且调用方提供的
  compatibility 规则允许转换 first flight 的版本；`run-codec` 现在打印
  `compatible_selected=0x6b3343cf`。
- 2026-06-02：新增 RFC 9368 已解析 `version_information` 语义失败的
  close-code 分类。`applyPeerTransportParameterBytesOrClose()` 继续保留旧
  apply API 的 rollback-only 表面行为，但对 downgrade/version-negotiation
  失败排队 `VERSION_NEGOTIATION_ERROR`，对畸形 transport parameter 排队
  `TRANSPORT_PARAMETER_ERROR`；`run-codec` 现在打印 `downgrade_close=0x11`。
- 2026-06-03：新增 UDP close lifecycle close/deadline 证据，并加入 close/drain
  timeout 到期后的 endpoint lifecycle route 清理。
  `udp_close_lifecycle_loopback` 现在会断言并打印 lifecycle-routed protected
  receive auto-close 和显式 CONNECTION_CLOSE 路径的 close/drain deadline，并在
  connection-handle retirement 后输出剩余 route/reset-token count。
- 2026-06-03：新增 controlled-clock persistent-congestion recovery-period
  reset 证据。Persistent congestion 现在有直接 `Recovery` 断言和
  `run-loss-recovery` 输出，证明它会清理当前 NewReno recovery period、重置
  congestion-avoidance credit，并允许后续 congestion event 建立新的 recovery
  start；示例现在打印 `recovery_cleared=true` 和 `reentry_start=1900`。
- 2026-06-02：新增 controlled-clock NewReno recovery-period ACK accounting
  覆盖。`Recovery` 测试现在验证 recovery-start 边界上的 packet 被 ACK 时，会清理
  PTO backoff、更新 RTT、移除 bytes in flight，但不会增长
  `congestion_window`，也不会累计 congestion-avoidance credit；`loss_recovery`
  现在打印
  `recovery ACK accounting cwnd=6000 latest_rtt=80 inflight=10800 credit=0`。
- 2026-06-02：新增 socket-backed UDP installed-key 0-RTT PTO recovery
  覆盖。`udp_pto_recovery_loopback` 现在会在 loopback UDP 上发出 installed-key
  0-RTT RESET_STREAM，通过
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedZeroRttDatagramWithInstalledKeys()`
  service Application PTO，验证 packet number 1 的 protected 0-RTT
  retransmission，把它路由到已 accept 0-RTT 的 server，并通过 1-RTT ACK 清理
  client recovery state。示例现在打印 `zero_rtt_probe_bytes=37` 和
  `zero_rtt_ack_bytes=27`。
- 2026-06-02：新增
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedZeroRttDatagramWithInstalledKeys()`。
  endpoint lifecycle 现在可以在 `Connection` 持有已安装本端 0-RTT key 的情况下
  service 到期的 Application recovery timer，并发出 protected 0-RTT
  long-header PTO/loss probe。测试覆盖 deadline 前 no-op、RESET_STREAM
  retransmission 先于 PING fallback、installed-key 0-RTT packet opening 和
  timer re-arm；`endpoint_recovery_timers` 现在打印
  `installed_zero_rtt_pto_bytes=37`。
- 2026-06-02：新增
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedHandshakeDatagramWithInstalledKeys()`。
  endpoint lifecycle 现在可以在 `Connection` 持有已安装 Handshake key 的情况下
  service 到期的 Handshake recovery timer，并发出 protected long-header
  PTO/loss probe。测试覆盖 deadline 前 no-op、Handshake PTO probe emission、
  installed-key long-packet opening、Initial-space discard 和 timer re-arm；
  `endpoint_recovery_timers` 现在打印 `installed_handshake_pto_bytes=36`。
- 2026-06-02：新增
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys()`。
  endpoint lifecycle 现在可以在 `Connection` 持有已安装 1-RTT key 的情况下
  service 到期的 Application recovery timer，并发出 protected 1-RTT PTO/loss
  probe。测试覆盖 deadline 前 no-op、PTO probe emission、installed-key packet
  opening 和 ACK disarm；`endpoint_recovery_timers` 现在打印
  `installed_pto_bytes=25`。
- 2026-06-02：把 long-header Handshake PTO service 接入 socket-backed UDP
  PTO loopback。`udp_pto_recovery_loopback` 现在会先通过 loopback UDP 完成
  Initial CRYPTO/ACK 交换，再通过 `EndpointConnectionLifecycle` service 由此产生的
  Handshake anti-deadlock PTO，把 protected long-header PING 投递到 server，
  返回 Handshake ACK，并打印 `long_pto_bytes=36` 与 `long_ack_bytes=38`。
- 2026-06-02：新增
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedLongDatagram()`。
  endpoint lifecycle 现在可以在同一个 route/timer owner 中 service 到期的
  Initial/Handshake recovery timer，并发出调用方 key 的 protected long-header
  PTO/loss probe。测试覆盖 deadline 前 no-op、Handshake PTO probe emission、
  发送 Handshake 后 Initial-space discard，以及 timer re-arm；
  `endpoint_recovery_timers` 现在打印 `long_pto_bytes=36` 作为确定性证据。
- 2026-06-02：新增
  `EndpointConnectionLifecycle.serviceRecoveryTimerAndPollProtectedShortDatagram()`。
  endpoint lifecycle 现在可以在同一个 route/timer owner 中 service 到期的
  Application recovery timer，并发出调用方 key 的 protected short PTO/loss
  probe。测试覆盖 deadline 前 no-op、PTO probe emission 和 ACK disarm；
  `udp_pto_recovery_loopback` 现在通过该 helper 在 loopback UDP 上发出 PING、
  STREAM 和 CRYPTO PTO probe。
- 2026-06-02：新增 TLS backend confirmed 且仍有最后一段 outbound
  Handshake CRYPTO 时的延迟 Handshake-space discard。连接会在 backend 输出仍排队
  时保留已安装 Handshake key，并在 frame-payload 或 protected long-packet
  发送提交后清理 Handshake packet-number space 和 key。测试覆盖两条发送路径；
  `crypto_stream` 会打印发送后的 discard 证据。
- 2026-06-02：刷新 RFC 9002 persistent-congestion 后的 RTT 状态。当建立
  persistent congestion 的 ACK 同时产生最新 RTT sample 时，recovery 路径现在会把
  `min_rtt` 重置为该 sample，并把共享 RTT 估计重新同步到所有 packet number
  space。测试覆盖直接 recovery state 和连接层 ACK 处理，`loss_recovery` 会打印
  刷新后的 `min_rtt` 证据。
- 2026-06-02：新增客户端 no-in-flight anti-deadlock PTO。客户端在握手确认前
  经过 Initial/Handshake ACK 或 loss 事件后没有任何 ack-eliciting packet in
  flight 时，会从该事件启动 recovery timer 并排队 Initial probe；安装
  Handshake keys 后会切换为 Handshake probe。测试覆盖 Initial 和 Handshake
  选择，`pto_recovery` 会打印 Initial anti-deadlock probe 证据。
- 2026-06-02：新增 anti-amplification unblock 时的 expired PTO service。server
  之前处于 anti-amplification limit 时，现在会先记录新收到的 datagram bytes，
  重新 arm aggregate PTO timer；如果原始 PTO deadline 已在被阻塞期间过期，则会
  立即 service 该 timer。测试覆盖 re-arm 但不 service，以及已过期 deadline 的
  service；`pto_recovery` 会打印 unblock service 证据。
- 2026-06-02：新增 socket-backed UDP installed-key echo loopback 覆盖。
  `udp_echo_loopback` 使用 connection-owned 1-RTT key、真实 loopback UDP socket
  和 `EndpointConnectionLifecycle` route ownership 投递 client STREAM，再由
  server 在同一 bidirectional stream echo 相同数据，路由 final ACK，并输出
  request/echo payload equality、bytes-in-flight cleanup 和 timer-state 证据。
- 2026-06-02：扩展 socket-backed UDP CryptoBackend 1-RTT loopback echo 覆盖。
  `udp_crypto_backend_loopback` 现在把 mock `CryptoBackend` 1-RTT
  traffic-secret handoff 和建模 handshake confirmation，与真实 loopback UDP 上
  lifecycle-routed client STREAM delivery、server bidirectional STREAM echo、
  final ACK routing，以及 bytes-in-flight/timer-state 证据组合到同一闭环。
- 2026-06-02：暴露 installed-key 1-RTT key-update ACK-gate 状态。
  `Connection.pendingOneRttKeyUpdateAckThreshold()` 返回再次发起本端 key
  update 前必须被 ACK 的 packet-number threshold；`udp_key_update_loopback`
  现在通过 lifecycle-routed UDP 输出 first/second threshold 与 ACK gate clearing
  证据。
- 2026-06-02：新增 installed 1-RTT key update 的 key-phase generation
  可观测性。`Aes128KeyPhaseState.keyUpdateCount()` 与 connection local/peer
  count accessor 暴露发送侧和接收侧 key-phase advance，不会修改状态；
  `udp_key_update_loopback` 现在在 ACK-gated update 流程中输出 client local
  和 server peer update-count 证据。
- 2026-06-02：暴露 installed 1-RTT key update 的 retained key-generation
  window。`Aes128KeyPhaseState.retainsKeyGeneration()` 与 connection local/peer
  accessor 让 endpoint loop 可证明 key update 后旧 generation 不再保留，而
  current/next generation 仍可用；`udp_key_update_loopback` 现在输出 old-generation
  discard 证据。
- 2026-06-02：把 UDP installed-key key-update loopback 扩展到第二次 update
  packet。第一次 ACK 清理 key-update gate 后，client 会发送第二个 key-phase
  PING，server 推进到 generation 2 并从 retained window 丢弃 generation 1，
  第二个 ACK 会清理 client 的第二次 update gate。
- 2026-06-02：新增第二次 installed-key update 后 stale old-generation packet
  rejection 证据。测试和 `udp_key_update_loopback` 现在会在 server 推进到
  generation 2 后构造 next expected packet number 上的 generation-1 packet，
  证明认证失败，并验证 peer packet number、pending ACK 与 key-update count
  保持不变。
- 2026-06-01：通过 `Connection.streamState()` 新增公开 `StreamState`
  快照。该只读 API 会报告当前建模的发送侧 FIN/reset 关闭、接收侧 final-size/reset
  状态、接收缓冲字节数和 read offset，不会创建 stream 或修改状态。测试覆盖
  unknown/invalid stream ID、FIN delivery、接收 final-size 快照，以及
  RESET_STREAM 发送/接收快照；`stream_reset` 会打印 reset 快照证据。
- 2026-06-01：扩展 `StreamState`，补充接收侧 STOP_SENDING 可观测性。
  快照现在会暴露本端是否已经为某个 stream receive side 排队或发送
  STOP_SENDING，同时保留既有 receive lifecycle state 和后续 RESET_STREAM
  final-size/error 快照。测试覆盖 stop 请求和对端 reset 响应，`stop_sending`
  会打印快照证据。
- 2026-06-01：细化 `StreamState` 接收侧快照，新增 Data Read 与 Reset Read
  状态。`recvOnStream()` 只在应用消费或观察到所有 final bytes 后把 FIN stream
  标记为 read，只在应用观察到 `StreamClosed` 后把 reset stream 标记为 read。
  测试覆盖数据、零长度 FIN 和 reset 观测路径；`stream_reset` 会打印 reset-read
  快照证据。
- 2026-06-01：新增 `StreamState` 发送侧 Data Acked 与 Reset Acked 快照。
  ACK 处理现在只会在 FIN 前所有 STREAM frame 都离开 queued 和 in-flight
  recovery 状态后，把 FIN stream 标记为 acked；RESET_STREAM 被确认后会标记为
  reset-acked。测试覆盖拆分 FIN ACK 顺序和 RESET_STREAM ACK 观测路径；
  `stream_reset` 会打印 reset-acked 证据。
- 2026-06-01：RESET_STREAM 被确认后抑制过期重传。ACK-driven loss 与 PTO
  control-frame probe selection 现在会跳过发送侧已是 `reset_acked` 的
  RESET_STREAM，因此 retransmission 已被 ACK 后，旧 in-flight reset packet
  即使随后进入 loss 清理，也不会再次排队 reset。测试覆盖 PTO retransmission/ACK/loss
  竞态，`pto_recovery` 会打印抑制证据。
- 2026-06-01：新增受控时钟证据，证明 ACK 驱动的 lost packet 必须保持
  packet number 连续，才会建立 RFC 9002 persistent congestion。跨越
  persistent-congestion duration 但 packet number 不连续的 lost packet 会保留在
  普通 NewReno recovery 路径，`loss_recovery` 会打印被抑制的
  persistent-congestion 场景。
- 2026-06-01：新增 `STREAMS_BLOCKED_BIDI` 和 `STREAMS_BLOCKED_UNI`
  超过 RFC 9000 stream-count limit 的 close-on-error 显式证据。
  rollback-only receive 现在有 connection-level 覆盖证明对端 blocked
  状态保持不变，`processDatagramOrClose()` 会为两个 frame type 排队
  `FRAME_ENCODING_ERROR` CONNECTION_CLOSE；`graceful_close` 会打印两条非法
  STREAMS_BLOCKED close 路径。
- 2026-06-01：新增 ACK_ECN packet-type close 显式证据。0-RTT
  `ACK_ECN` 现在有 rollback-only forbidden-frame 覆盖，
  `processDatagramForPacketTypeOrClose()` 也会为同一 packet-type violation
  排队 `PROTOCOL_VIOLATION` CONNECTION_CLOSE；`graceful_close` 会打印非法
  0-RTT ACK_ECN close 路径。
- 2026-06-01：新增 ACK_ECN close-on-error 显式证据。非法 ACK_ECN
  range 现在有直接 `FRAME_ENCODING_ERROR` close 覆盖，ACK_ECN 确认未发送
  packet number 也有直接 `PROTOCOL_VIOLATION` close 覆盖；`graceful_close`
  会打印两条 ACK_ECN close 路径。
- 2026-06-01：新增 stream-control frame stream 校验的 close-on-error
  显式证据。非法 `STOP_SENDING` 与 `MAX_STREAM_DATA` receive-only stream
  现在有直接 `STREAM_STATE_ERROR` close 覆盖，超过接收 stream-count limit
  的 `STREAM_DATA_BLOCKED` 也有直接 `STREAM_LIMIT_ERROR` close 覆盖；
  `graceful_close` 会打印三条 stream-control close 路径。
- 2026-06-01：新增非法 ACK range 的 close-on-error 显式证据。
  frame codec 仍会拒绝导致 packet number 下溢或 first range 超过 largest
  acknowledged packet 的 ACK range；`processDatagramOrClose()` 现在有直接
  覆盖证明这类 decode failure 会排队 `FRAME_ENCODING_ERROR`；
  `graceful_close` 会打印非法 ACK range close 证据。
- 2026-06-01：新增 ACK 确认未发送 packet number 的语义 close
  传播。rollback-only receive path 仍会在 recovery 副作用前拒绝该
  ACK，close-on-error receive path 现在会排队 `PROTOCOL_VIOLATION`
  CONNECTION_CLOSE；`graceful_close` 会打印 ACK close 证据。
- 2026-06-01：新增冲突 STREAM 字节的语义 close 传播。rollback-only
  receive path 仍会拒绝 repeated offset 上变化的数据且不提交状态，
  close-on-error receive path 现在会把已确认的字节冲突映射为
  `PROTOCOL_VIOLATION`，而相同重复重传继续走既有非关闭路径；
  `graceful_close` 会打印 stream-conflict close 证据。
- 2026-06-01：新增按 packet number space 生效的 CRYPTO 接收缓冲上限。
  `Connection.Config.max_crypto_buffer_size` 现在约束可接受的最大 CRYPTO
  end offset；rollback-only receive API 会在不改变已缓冲字节的前提下拒绝
  超限 CRYPTO，close-on-error receive API 会排队 `CRYPTO_BUFFER_EXCEEDED`
  CONNECTION_CLOSE。`crypto_stream` 会打印 buffer-limit close 证据。
- 2026-05-30：新增 `pollProtectedLongDatagram()` 的 caller-keyed protected
  Initial/Handshake `CONNECTION_CLOSE` emission。pending transport close frame
  现在会绕过 closing-state guard，优先使用调用方提供的 Handshake key，缺少时回退到
  Initial key，close packet 不进入 bytes-in-flight，并保留到 close deadline
  以支持重发；`graceful_close` 会打印两条 protected long close 路径。
- 2026-05-30：新增 installed Handshake keys 下的 protected Handshake
  CONNECTION_CLOSE emission。`pollProtectedHandshakeDatagramWithInstalledKeys()`
  现在会在 closing-state guard 前优先处理 pending transport close frame，
  发出 protected Handshake `CONNECTION_CLOSE`，发送后进入 closing，并让对端收到
  draining close diagnostics；`crypto_stream` 演示 backend transport-parameter
  错误进入 protected Handshake close。
- 2026-05-30：新增 close-propagating CryptoBackend transport-parameter drive
  覆盖。`driveCryptoBackendInSpaceOrClose()` 保留既有 backend drive 成功语义，
  但会把无效 peer transport-parameter extension byte 交给
  `applyPeerTransportParameterBytesOrClose()`，因此下一次发送会变成
  `TRANSPORT_PARAMETER_ERROR` CONNECTION_CLOSE，并且错误后不会再拉取 backend
  output。
- 2026-05-30：新增 socket-backed UDP CryptoBackend Handshake CRYPTO stream
  覆盖。`udp_crypto_stream_loopback` 驱动 mock `CryptoBackend` 安装 Handshake
  traffic secret、交接本端/对端 transport-parameter byte、生产/消费 CRYPTO
  flight，并通过真实 loopback UDP 上的 lifecycle-routed protected Handshake
  datagram 完成 ACK cleanup。
- 2026-05-30：新增 socket-backed UDP CryptoBackend 1-RTT handoff 覆盖。
  `udp_crypto_backend_loopback` 驱动 mock `CryptoBackend` 安装
  connection-owned 1-RTT traffic secret 并标记建模 handshake confirmed，然后
  使用真实 loopback UDP 上的 `EndpointConnectionLifecycle` 路由 protected
  STREAM 和 ACK cleanup。
- 2026-05-30：新增 socket-backed UDP installed-key HANDSHAKE_DONE loopback
  覆盖。`udp_handshake_done_loopback` 使用 connection-owned 1-RTT key 通过真实
  loopback UDP socket 和 `EndpointConnectionLifecycle` 投递 server
  HANDSHAKE_DONE frame，验证 server/client-side handshake confirmation 与
  Handshake key discard，并输出 ACK pending/cleared 证据，再把 ACK 路由回
  server 清理 Application-space bytes in flight。
- 2026-06-02：在 `udp_handshake_done_loopback` 中暴露公开 connection-state
  证据。该 loopback 现在会在 lifecycle-routed HANDSHAKE_DONE delivery 后断言并
  输出 server/client `handshakeState=confirmed` 与 `connectionState=active`，
  把已有 key-discard 与 ACK-cleanup 证据绑定到建模 connection state machine。
- 2026-05-29：新增 socket-backed UDP installed-key 1-RTT STREAM loopback 覆盖。
  `udp_one_rtt_loopback` 安装 connection-owned 1-RTT traffic secret，确认建模
  handshake，通过真实 loopback UDP socket 和 `EndpointConnectionLifecycle`
  投递 protected STREAM frame，并验证 Application packet number space 的 routed
  ACK cleanup。
- 2026-06-04：扩展 `udp_one_rtt_loopback` 的 serviced installed-key 1-RTT
  PTO 证据。该示例现在记录 client Application PTO deadline，通过
  `serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys()` 服务该
  timer，把 protected 1-RTT STREAM PTO probe 经 loopback UDP 路由到 server，并验证
  重复 STREAM data 不会再次交付，同时 server ACK PTO packet number。
- 2026-05-29：新增 socket-backed UDP installed-key Handshake loopback 覆盖。
  `udp_handshake_keys_loopback` 使用 connection-installed Handshake traffic
  secret 通过真实 loopback UDP socket 和 `EndpointConnectionLifecycle` 路由，
  双向投递 Handshake CRYPTO，并验证 routed Handshake ACK cleanup。
- 2026-06-04：扩展 `udp_handshake_keys_loopback` 的 serviced installed-key
  Handshake PTO 证据。该示例现在通过
  `serviceRecoveryTimerAndPollProtectedHandshakeDatagramWithInstalledKeys()`
  服务 server Handshake PTO，把 protected Handshake CRYPTO PTO probe 经
  loopback UDP 路由到 client，验证重复 CRYPTO data 不会再次交付，然后 ACK 两个
  server Handshake packet 并把 bytes in flight 清到 0。
- 2026-05-29：新增 socket-backed UDP 0-RTT loopback 覆盖。
  `udp_zero_rtt_loopback` 使用 installed 0-RTT key 通过真实 loopback UDP
  socket 和 `EndpointConnectionLifecycle` 路由，验证显式接受 0-RTT 前拒绝
  receive processing、接受后投递 early STREAM data 并输出 ACK 证据、通过 routed
  1-RTT ACK 清理 client bytes in flight，并证明 1-RTT 边界上的 client/server
  0-RTT key discard。
- 2026-06-02：给 `udp_zero_rtt_loopback` 新增 rejection-driven installed-key
  0-RTT discard 证据。该 loopback 现在会在 accept 前拒绝 early-data processing，
  显式调用 `rejectZeroRtt()`，证明 peer 0-RTT receive key 和 accepted flag 已清理，
  并验证后续再次 accept 会失败。
- 2026-06-04：扩展 `udp_zero_rtt_loopback` 的 serviced installed-key
  0-RTT PTO 证据。该示例现在会在建模 handshake confirmation 后 arm endpoint
  recovery timer，通过
  `serviceRecoveryTimerAndPollProtectedZeroRttDatagramWithInstalledKeys()`
  服务 client Application PTO，把 protected 0-RTT STREAM PTO probe 经 loopback
  UDP 路由到 server，并验证重复 STREAM data 不会再次交付，同时 ACK largest 前进到
  PTO packet number。
- 2026-06-03：新增 lifecycle-owned address-token validation unblocking。
  `EndpointConnectionLifecycle.validateAddressTokenForPathAndArmConnection()`
  现在会在一个步骤里校验 path-bound endpoint token、记录 replay state、把 server
  peer address 标记为 validated，并刷新 endpoint recovery scheduling。测试证明
  wrong-path token 不会解除发送限制，也不会记录 replay；合法 NEW_TOKEN 会解除
  server 的 anti-amplification 限制，并 arm 既有 recovery timer；
  `run-address-validation` 和 `run-udp-address-validation-loopback` 现在通过该
  lifecycle helper 输出 future-server unblock 证据。
- 2026-06-04：新增 lifecycle-owned Retry token validation 和 consumption。
  `EndpointConnectionLifecycle.validateRetryTokenForPathAndArmConnection()`
  会先检查连接仍等待该一次性 Retry token，再记录 endpoint replay state、校验
  path-bound Retry token、消费连接侧 Retry token、解除 anti-amplification，并刷新
  endpoint recovery scheduling。测试证明 wrong-path 和缺失 pending token 的失败
  不会记录 replay，也不会解除 server 发送限制；已 replay 的合法 Retry token 不会
  消费 pending connection state；`run-retry-token` 和 `run-udp-retry-loopback`
  现在通过该 lifecycle helper 接受 Retry token。
- 2026-06-04：新增 lifecycle-owned Retry follow-up Initial acceptance。
  `EndpointConnectionLifecycle.processRetryValidatedProtectedInitialDatagram()`
  把 Retry 后 server receive path 保持在 endpoint lifecycle owner 上：route
  selection、Initial accept metadata 提取、path-bound Retry token
  validation/consumption 和 protected Initial processing 现在由一个 helper 完成。
  测试证明缺失 pending Retry state 时不会记录 replay，也不会处理 packet；
  `run-udp-retry-loopback` 现在通过该 helper 处理 Retry-derived client Initial。
- 2026-06-04：把 address-validation 的 protected HANDSHAKE_DONE/NEW_TOKEN
  emission 接入 endpoint lifecycle polling。`address_validation` 和
  `udp_address_validation_loopback` 现在通过
  `EndpointConnectionLifecycle.pollProtectedShortDatagram()` 生成 server 侧
  HANDSHAKE_DONE 与 NEW_TOKEN packet，再交给 lifecycle-routed client delivery，
  因而同一个 lifecycle owner 会刷新 protected short-packet send timer。两个
  示例现在都会输出 `emit_timers=1`。
- 2026-06-04：收紧 socket-backed UDP echo timer-state 证据。
  `udp_echo_loopback` 和 `udp_crypto_backend_loopback` 现在会在 final ACK 完成
  routed delivery 后断言并输出两端 endpoint lifecycle timer count：client
  final-ACK 侧仍暴露 1 个 endpoint timer，server 侧 bytes in flight 与 timer
  均已清零。
- 2026-06-04：扩展 `udp_echo_loopback` 的 serviced server-side 1-RTT PTO
  证据。该 echo loopback 现在会在 client 收到 echoed STREAM data 后重新 arm
  server Application recovery timer，通过
  `serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys()` 服务该
  timer，把 protected echo STREAM PTO probe 经 loopback UDP 路由到 client，验证
  重复 STREAM data 不会再次交付且 client ACK largest 前进，然后用 final ACK
  清空 server bytes in flight 并 disarm server timer。
- 2026-06-04：扩展 `udp_crypto_backend_loopback` 的 installed-key recovery
  timer 证据。mock `CryptoBackend` 1-RTT loopback 现在会断言并打印 client
  STREAM 发送侧 PTO deadline，通过
  `serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys()` 服务
  这个到期 Application timer，把生成的 protected STREAM PTO probe 经 loopback UDP
  路由到 server，验证重复 STREAM 不会再次交付；随后通过同一个 installed-key
  endpoint helper 服务 server echo 发送侧 PTO，把 protected echo STREAM PTO probe
  路由回 client，验证重复 echo data 不会再次交付且 client ACK largest 前进，再验证
  最终 routed ACK 会 disarm server lifecycle timer 并清空 server bytes in flight。
- 2026-05-29：新增 socket-backed UDP address-validation loopback 覆盖。
  `udp_address_validation_loopback` 会通过真实 loopback UDP socket 投递
  protected HANDSHAKE_DONE 和 NEW_TOKEN，并经
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` 处理，
  随后验证 NEW_TOKEN path binding 并输出 changed-path rejection 证据、
  originating-version binding、secret rotation、replay snapshot restore
  rejection，以及 lifecycle-owned address-validation block/unblock 输出。
- 2026-05-29：把 address-validation 的 protected HANDSHAKE_DONE 和 NEW_TOKEN
  receive path 接入 endpoint lifecycle routed helper。`address_validation`
  现在会把 client receive CID 注册到 `EndpointConnectionLifecycle`，并用
  `processRoutedProtectedShortDatagram()` 处理这两个 protected short packet，
  然后继续验证 NEW_TOKEN path/version binding 与 replay rejection。
- 2026-05-29：把 UDP Retry follow-up protected Initial receive path 接入
  endpoint lifecycle routed helper。`udp_retry_loopback` 现在使用
  `EndpointConnectionLifecycle.processRoutedProtectedInitialDatagram()` 处理
  server 收到的 Retry-derived client Initial，以及 client 收到的 protected
  server Initial；未加密 Retry packet 本身继续走 route-only Retry processing
  path。
- 2026-05-29：把 `endpoint_recovery_timers` 中剩余 caller-keyed short-packet
  receive path 接入 endpoint lifecycle routed helper。caller-keyed 0-RTT ACK
  cleanup、caller-keyed 1-RTT PING delivery 和 caller-keyed 1-RTT ACK cleanup
  现在都使用 `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()`，
  不再拆成 `routeDatagram()` 与 `processProtectedShortDatagram()` 两步。
- 2026-05-29：把 UDP path-validation protected receive path 接入 endpoint
  lifecycle routed helper。`udp_path_validation_loopback` 现在会把客户端新端口
  的 receive CID 注册到 client lifecycle owner，然后使用
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` 处理
  protected PATH_CHALLENGE delivery，以及带 `path_changed` 的 protected
  PATH_RESPONSE receive。该示例还会在 PATH_RESPONSE validation 前从新 path
  发送 protected PING，并验证 lifecycle helper 只报告 `path_changed`，不会提交
  route update。
- 2026-05-29：把 UDP close lifecycle protected receive path 接入 endpoint
  lifecycle routed helper。`udp_close_lifecycle_loopback` 现在使用
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` 处理
  protected CONNECTION_CLOSE receive path，使 route selection、connection-handle
  validation、routed DCID length selection、packet processing 和 recovery-timer
  refresh 都保留在同一个 lifecycle owner 上；后续 route retirement 和
  stateless reset emission 也继续由该 owner 执行。
- 2026-05-30：为 `udp_close_lifecycle_loopback` 增加 socket-backed protected
  receive auto-close 路径。该示例现在通过 loopback UDP 发送一个认证后畸形的
  protected short packet，用
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramOrClose()` 处理，
  再把排队的 CONNECTION_CLOSE 发回客户端，同时保持既有 close-triggered route
  retirement/stateless reset 场景不变。
- 2026-05-30：为 close-on-error receive wrapper 增加语义 frame-processing
  close 传播。`processDatagramForPacketTypeOrClose()` 继续保留基础 receive
  path 的 rollback-only 行为，同时会为已分类的 STREAM/RESET_STREAM
  flow-control、stream-limit 和 final-size 错误排队 CONNECTION_CLOSE。测试覆盖
  三类映射，`examples/graceful_close.zig` 会打印 semantic auto-close 证据。
- 2026-05-30：为未匹配 PATH_RESPONSE 增加语义 close 传播。close-on-error
  receive wrapper 现在会把没有匹配 outstanding PATH_CHALLENGE 的 PATH_RESPONSE
  映射为 `PROTOCOL_VIOLATION`，而匹配的 PATH_RESPONSE 仍只清理 challenge、不关闭连接；
  测试覆盖两条路径，`examples/graceful_close.zig` 会打印 auto-close 证据。
- 2026-05-30：为 role-specific NEW_TOKEN/HANDSHAKE_DONE 违规增加语义 close
  传播。server 侧 close-on-error receive 现在会把 peer NEW_TOKEN 和 HANDSHAKE_DONE
  frame 映射为 `PROTOCOL_VIOLATION`，已有 client 侧接收/存储路径和 rollback-only
  receive API 保持不变；测试覆盖两条 close 路径，`examples/graceful_close.zig` 会打印
  auto-close 证据。
- 2026-05-30：为 active connection-ID limit overflow 增加语义 close 传播。
  close-on-error receive 现在会先按 `retire_prior_to` 计算退役后的 active CID
  数量，再把仍会超过 `active_connection_id_limit` 的 NEW_CONNECTION_ID 映射为
  `CONNECTION_ID_LIMIT_ERROR`；测试覆盖 overflow close 和先退役旧 CID 的合法
  replacement，`examples/graceful_close.zig` 会打印 auto-close 证据。
- 2026-05-30：为非法 NEW_CONNECTION_ID reuse 增加语义 close 传播。close-on-error
  receive 现在会把 sequence/CID mismatch 和 stateless reset token reuse 映射为
  `PROTOCOL_VIOLATION`，完全重复的 NEW_CONNECTION_ID 仍保持幂等；测试覆盖三条路径，
  `examples/graceful_close.zig` 会打印 reset-token-reuse auto-close 证据。
- 2026-05-30：收紧 rollback-only NEW_CONNECTION_ID receive path，拒绝把已存在的
  peer-issued CID 值用在另一个 sequence number 上。基础 `processDatagram()`
  路径现在与 close-on-error classifier 的 CID reuse 校验一致，并在非法 payload
  回滚时保留 ACK 与 active-CID 状态。
- 2026-05-30：本端 NEW_CONNECTION_ID 签发现在会先应用 replacement frame 的
  `retire_prior_to` 再检查 peer active CID limit。server 在达到对端 CID limit 时，
  只要同一帧会退役旧 sequence，就能签发合法 replacement CID；非 replacement
  overflow 仍会被拒绝。
- 2026-05-30：为非法 RETIRE_CONNECTION_ID 增加语义 close 传播。close-on-error
  receive 现在会把 unknown 或尚未发送的本端 CID sequence number 映射为
  `PROTOCOL_VIOLATION`，已发送本端 CID 仍可正常 retire 而不关闭；测试覆盖两条
  close 路径和一条 accept 路径，`examples/graceful_close.zig` 会打印 retire-CID
  auto-close 证据。
- 2026-05-29：把 UDP ECN validation loopback protected receive path 接入
  endpoint lifecycle routed helper。`udp_ecn_validation_loopback` 现在使用
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` 处理
  modeled ECT(0) PING、ACK_ECN validation、ECN-CE ACK_ECN congestion response
  和第二个 PING receive path；已有 lifecycle ECN path-state refresh 继续作为
  endpoint-owned post-validation mirror step。
- 2026-05-29：把 UDP spin-bit loopback protected receive path 接入 endpoint
  lifecycle routed helper。`udp_spin_bit_loopback` 现在使用
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` 处理第一轮
  false-spin PING/ACK、迁移端口 true-spin PING 和 reset-spin ACK receive path，
  同时继续由 lifecycle owner 负责 server/client route-update spin reset。
- 2026-05-29：把 UDP connection-ID loopback protected receive path 接入
  endpoint lifecycle routed helper。`udp_connection_ids_loopback` 现在使用
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` 处理
  protected NEW_CONNECTION_ID、ACK、RETIRE_CONNECTION_ID 和 final ACK receive
  path，同时保留未加密 route probe 与 retired-token lookup 的 route-only
  endpoint 检查。
- 2026-06-02：新增
  `EndpointConnectionLifecycle.issueConnectionIdRoute()`，把
  `Connection.issueConnectionId()` 与 lifecycle-owned endpoint route
  registration 串到同一个调用里。该 helper 使用 NEW_CONNECTION_ID 携带的同一个
  stateless reset token 注册 active route，应用 `retire_prior_to`，并在 route
  registration 失败时回滚刚签发的本端 CID。测试覆盖成功 replacement route
  retirement 和 duplicate route-sequence rollback；`connection_ids` 与
  `udp_connection_ids_loopback` 现在使用该 lifecycle helper，不再手动同步
  connection 与 route 状态。
- 2026-05-29：把 UDP flow-control loopback receive path 接入 endpoint
  lifecycle routed helper。`udp_flow_control_loopback` 现在使用
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` 处理
  protected STREAM、STREAM_DATA_BLOCKED、MAX_DATA/MAX_STREAM_DATA、resumed
  STREAM 的 FIN final-size 证据和 final ACK receive path，让 route selection、connection-handle
  validation、routed DCID length selection、packet processing 和
  recovery-timer refresh 继续归 endpoint lifecycle owner 管理。
- 2026-05-29：把 UDP recovery loopback receive path 接入 endpoint lifecycle
  routed helper。`udp_loss_recovery_loopback`、
  `udp_congestion_recovery_loopback`、`udp_pto_recovery_loopback` 和
  `udp_stream_retransmission_loopback` 现在使用
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` 处理
  socket receive path，让 route selection、connection-handle validation、
  routed DCID length selection、protected packet processing 和
  recovery-timer refresh 共享 endpoint lifecycle-owned 边界。
- 2026-05-29：新增 lifecycle-owned routed protected long-datagram processing。
  `EndpointConnectionLifecycle.processRoutedProtectedLongDatagram()` 现在会返回
  selected route 和 processed long-packet count，同时合并 endpoint route
  selection、connection-handle validation、coalesced long-packet processing 和
  recovery-timer refresh。测试覆盖 mismatch rejection、routed DCID validation、
  processed-count preservation、Initial ACK cleanup 和 timer disarm；
  `endpoint_recovery_timers` 现在用它完成 generic protected Initial receive path。
- 2026-05-29：新增 lifecycle-owned routed explicit key-update 和
  caller-owned key-phase short-packet processing。
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithKeyUpdate()`
  与 `processRoutedProtectedShortDatagramWithKeyPhaseState()` 现在会把
  endpoint route selection、connection-handle validation、routed DCID length
  selection、caller-owned key-phase/key-update processing 和 recovery-timer
  refresh 合并在一个 endpoint lifecycle 步骤里。测试覆盖 mismatch rejection、
  routed DCID validation、route validation 前 key-phase preservation、ACK
  cleanup 和 timer disarm；`endpoint_recovery_timers` 现在用这些 helper 完成
  explicit key-phase receive path。
- 2026-05-29：新增 lifecycle-owned routed caller-keyed long-packet
  processing。`EndpointConnectionLifecycle.processRoutedProtectedLongDatagramInSpace()`
  与 `processRoutedProtectedZeroRttDatagram()` 现在会为 direct Handshake 和
  0-RTT receive path 合并 endpoint route selection、connection-handle
  validation、caller-supplied key processing 和 recovery-timer refresh。测试覆盖
  mismatch rejection、routed DCID validation、Handshake ACK cleanup 和 0-RTT
  STREAM delivery；`endpoint_recovery_timers` 现在用这些 helper 完成
  caller-keyed long-packet receive path。
- 2026-05-29：新增 lifecycle-owned routed installed-key Handshake 和 0-RTT
  long-packet processing。
  `EndpointConnectionLifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys()`
  与 `processRoutedProtectedZeroRttDatagramWithInstalledKeys()` 现在会把
  endpoint route selection、connection-handle validation、connection-owned TLS
  key processing 和 recovery-timer refresh 合并在一个步骤里。测试覆盖
  mismatch rejection、routed DCID validation、Handshake ACK cleanup 和 0-RTT
  STREAM delivery；`endpoint_recovery_timers` 现在用这些 helper 完成
  installed-key long-packet receive path。
- 2026-05-29：新增 lifecycle-owned routed installed-key protected short-packet
  processing。`EndpointConnectionLifecycle.processRoutedProtectedShortDatagramWithInstalledKeys()`
  现在会把 endpoint route selection、connection-handle validation、routed
  DCID length selection、connection-owned 1-RTT key processing 和 recovery-timer
  refresh 合并在一个 endpoint lifecycle 步骤里。测试覆盖 route mismatch
  rejection 和 ACK cleanup；`udp_key_update_loopback` 与
  `endpoint_recovery_timers` 现在用它完成 installed-key PING/ACK receive
  processing。
- 2026-05-29：新增 lifecycle-owned routed protected short-packet processing。
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagram()` 现在会把
  endpoint route selection、connection-handle validation、routed DCID length
  selection、caller-keyed 1-RTT packet processing 和 recovery-timer refresh
  合并在一个 endpoint lifecycle 步骤里。测试覆盖 route mismatch rejection 和
  ACK cleanup；`udp_protected_loopback` 现在用它完成 routed 1-RTT PING/ACK
  processing。
- 2026-05-29：新增 lifecycle-owned routed protected Initial processing。
  `EndpointConnectionLifecycle.processRoutedProtectedInitialDatagram()` 现在会把
  protected Initial datagram 路由到预期 connection handle，根据 packet version
  和 Original DCID 派生 client/server Initial keys，在 Initial space 中处理
  packet，并镜像 recovery timer。测试和 UDP endpoint/protected loopback 现在
  使用它完成 client-side protected server Initial response processing。
- 2026-05-29：新增 lifecycle-owned accepted Initial response emission。
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialResponseDatagram()`
  现在会把已认证的 client Initial 字节记入建模 server anti-amplification
  budget，排队调用方提供的 server Initial CRYPTO bytes，发出 protected
  server Initial response，并通过 endpoint lifecycle 镜像 recovery timer。
  测试覆盖 server/client CRYPTO delivery、client-side response routing 和
  anti-amplification accounting；`udp_protected_loopback` 与
  `udp_endpoint_loopback` 现在都通过该 helper 发送 protected server Initial
  response。
- 2026-05-29：新增 lifecycle-owned accepted protected Initial processing。
  `EndpointConnectionLifecycle.processAcceptedProtectedInitialDatagram()` 现在会先认证并处理
  accepted client Initial，再安装 Original DCID/server Initial SCID endpoint
  route，避免畸形 protected Initial 留下有效 route。测试覆盖成功 CRYPTO
  delivery 与 route/token 安装，也覆盖 tampered Initial rollback；
  `udp_protected_loopback` 和 `udp_endpoint_loopback` 现在都通过该 helper 在
  loopback UDP 上完成 server-side accepted Initial processing。
- 2026-05-29：新增 lifecycle-owned protected Version Negotiation follow-up
  Initial emission。`EndpointConnectionLifecycle.processVersionNegotiationProtectedInitialDatagram()`
  现在会验证 VN、退役旧 attempt、注册 follow-up route、初始化 follow-up client
  connection、排队调用方提供的 Initial CRYPTO bytes、用 selected-version Initial
  keys 发出 protected Initial，并把 recovery timer 镜像到 endpoint lifecycle。
  测试覆盖 v2 packetization 和 server CRYPTO receive；`udp_endpoint_loopback`
  现在会通过 loopback UDP 发送 protected follow-up Initial。
- 2026-05-29：新增 endpoint-owned Version Negotiation connection handoff。
  `EndpointConnectionLifecycle.processVersionNegotiationHandoffDatagram()` 现在会包装
  VN validation、follow-up config derivation、old-attempt route/timer retirement、
  follow-up Initial route registration 和 follow-up `Connection` 创建。测试覆盖
  accepted 与 ignored handoff 路径；`udp_endpoint_loopback` 现在直接使用返回的
  follow-up connection。
- 2026-05-29：新增 lifecycle-owned Version Negotiation follow-up route
  orchestration。`EndpointConnectionLifecycle.processVersionNegotiationFollowupDatagram()`
  现在会在一个 endpoint-owned 步骤中完成 client-side VN validation、follow-up
  config 派生、旧 attempt 退役，以及 follow-up client Initial Source CID route
  注册。测试覆盖 accepted、ignored 和 reused-SCID 路径；`udp_endpoint_loopback`
  现在使用该 helper 完成 follow-up Initial routing。
- 2026-05-29：新增 lifecycle-owned Version Negotiation follow-up handling。
  `EndpointConnectionLifecycle.processVersionNegotiationDatagram()` 现在会包装
  client-side VN validation，派生 follow-up client config，并且只在 VN packet
  被接受后退役旧 connection handle 的 routes/timer。测试覆盖 accepted 与
  ignored VN 路径；`udp_endpoint_loopback` 现在使用该 helper 退役旧 attempt
  并注册 follow-up Initial route。
- 2026-05-29：新增 client-side Version Negotiation follow-up config
  propagation。`Connection.versionNegotiationFollowupConfig()` 会把已验证的
  RFC 8999 Version Negotiation 选择转换为下一次 client connection config，
  保留 advertised available-version list，同时写入 selected chosen version
  和 RFC 9368 downgrade-check state。测试覆盖 follow-up config 生成、认证
  Version Information 成功、downgrade 拒绝和未选择时的错误路径；
  `codec_roundtrip` 现在使用该 helper 生成 Version Negotiation 证据。
- 2026-05-29：新增按配置使用 QUIC v2 protected long-packet 和 Retry
  wire-version。`Config.chosen_version = .v2` 现在会让 protected
  Initial/Handshake/0-RTT long-packet builder 发出 v2 version/type bits，
  并让 long-packet receive 和 Retry processing 拒绝跨版本 packet。测试覆盖
  v2 Initial packetization/receive、v1 对 v2 Initial 的拒绝，以及 v2 Retry
  issue/process 与后续 Initial token reuse；`initial_keys` 会打印 configured
  v2 Initial packetization 证据。
- 2026-05-29：新增 RFC 9002 max_datagram_size recovery resync from peer
  `max_udp_payload_size`。应用对端 transport parameter 现在会把所有
  packet-number-space recovery state 同步到有效发送 datagram size；如果 peer
  limit 缩小该 size，congestion window 会重置为较小 datagram size 下重新计算的
  initial congestion window，并清空 congestion-avoidance credit。测试覆盖
  recovery 直接 decrease/increase 行为和连接层 peer-parameter 应用；
  `transport_parameters` 现在打印 resynced recovery datagram size 与
  congestion window。
- 2026-05-29：新增 RFC 9002 server anti-amplification limit 下 PTO
  disarm/rearm。未验证 client 地址的 server 在建模 anti-amplification
  send credit 为 0 时不再暴露 PTO deadline，因此 direct PTO check 和
  aggregate loss-detection timer 不会排 probe；记录更多 peer bytes 后会重新
  暴露原 PTO deadline 并允许 service path 排 PING。测试覆盖 disarm、service
  no-op、credit rearm 和 PING probe 发出；`pto_recovery` 现在打印 rearm deadline
  证据。
- 2026-05-29：新增 RFC 9002 client Initial ACK 不重置 PTO backoff。
  客户端 ACK 处理在 Initial ACK 新确认 ack-eliciting packet 时会保留
  connection-level PTO backoff 快照；Handshake 和 Application ACK 仍沿用正常
  reset 行为。测试覆盖 client Initial backoff 保留、随后 Handshake ACK reset；
  `pto_recovery` 现在打印两条路径的证据。
- 2026-05-29：新增 RFC 9002 跨 packet number space 的 connection-level
  PTO backoff。PTO deadline helper 现在用同一个 connection backoff count 计算
  Initial、Handshake 与 Application deadline；service 最早到期的 PTO 会推进所有
  未 discard space 的 shared backoff；ack-eliciting packet 被 ACK 或
  Initial/Handshake space discard 会将其清零。无效 payload 回滚会恢复跨 space
  backoff 快照。测试覆盖 Initial PTO service 带动 Handshake backoff、ACK reset、
  discard reset、invalid-payload rollback；`pto_recovery` 现在打印 backed-off
  Handshake deadline 证据。
- 2026-05-29：新增 RFC 9002 跨 packet number space 的 connection-level
  RTT 估计共享。largest-acknowledged RTT sample 现在会更新所有未丢弃的
  Initial、Handshake 与 Application packet number space RTT estimator，同时
  继续把 sent-packet、loss、PTO backoff 和 congestion accounting 限定在被
  ACK 的 space 内。无效多帧 payload 会把 shared RTT 变更和其它 recovery state
  一起回滚；`pto_recovery` 现在打印 shared RTT 与 Handshake PTO deadline 证据。
- 2026-05-29：新增 RFC 9002 跨 packet number space bytes-in-flight
  拥塞发送准入。`Connection.totalBytesInFlight()` 现在暴露
  Initial/Handshake/Application 的聚合 in-flight byte count，ack-eliciting
  send 会先用该聚合值与当前 space 的 congestion window 做准入；PTO probe
  和 congestion probe 仍保留一次性绕过语义。测试覆盖 Initial 与 Handshake
  in-flight bytes 填满 congestion window 时 Application STREAM 留在队列中，
  以及 Initial ACK 释放聚合预算后 STREAM 可以发送；`loss_recovery` 现在打印
  `cross-space congestion gate`。
- 2026-05-29：新增 RFC 9002 largest-acknowledged RTT sampling。ACK frame
  的 largest acknowledged packet 已经处理过、但本次只新确认较低 range
  时，仍会清理 sent-packet state、bytes in flight 和 PTO backoff，但不再更新
  RTT estimate。测试覆盖 connection ACK path 和 recovery accounting helper；
  `loss_recovery` 现在打印 `old-largest ACK preserved RTT`。
- 2026-05-29：新增 connection-level ACK API path 的 RFC 9000 ACK range
  结构校验。调用方构造的 ACK/ACK_ECN frame 若 range 会计算出负 packet
  number，现在会在触碰 recovery state 前被拒绝，与现有 wire-codec
  validation 口径一致。测试覆盖 sent-packet、bytes-in-flight、
  largest-acknowledged 和 timer 均不变；`loss_recovery` 会打印被拒绝的
  invalid range。
- 2026-05-29：新增 RFC 9002 Application Data PTO handshake-confirmation
  gating。Application-space PTO deadline 在 `confirmHandshake()` 或建模
  TLS/backend path 标记 handshake confirmed 前保持 null，因此 aggregate
  endpoint timer 和 PTO service 不会在确认对端可用 key 前重传 0-RTT/1-RTT
  数据。测试覆盖 confirmation 前直接 timer/service no-op、cross-space
  peer-probe 抑制和 confirmed 后 Application PTO 行为；`pto_recovery`
  现在会在确认后打印 gated deadline。
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
  测试覆盖 full-cwnd STREAM 在 packet-threshold loss 后仍能重传，以及 CE 驱动
  congestion event 后 queued STREAM probe 仍可发送；`loss_recovery` 现在打印
  loss probe 和 CE probe 的字节数、cwnd 与 inflight 证据。
- 2026-06-04：新增 controlled-clock CE-driven NewReno congestion-probe 证据。
  新 ACK_ECN CE 测试先用 ECT packet 填满 congestion window，排队 STREAM data，
  证明 CE 前发送会被 full cwnd 阻塞，再验证 CE congestion event 在降窗后仍只授予
  一次 probe。`loss_recovery` 现在打印 `CE congestion probe`。
- 2026-06-04：扩展 `udp_congestion_recovery_loopback` 的 socket-backed
  CE-driven probe 阶段。该示例在真实 loopback UDP 上路由建模 ECT protected PING，
  接收 protected ACK_ECN CE 信号，并通过 `EndpointConnectionLifecycle` 投递一次性
  protected STREAM probe，同时打印 CE count、降窗后 cwnd、inflight bytes 和 route 证据。
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
  caller-owned `Connection` 模型，但 socket event loop 现在可以通过同一状态
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
  现在也可穿过 endpoint route/timer owner，同时 `Connection` 继续持有
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
  第二个 PING，并证明 lifecycle route update 会清除 server 和 client 的
  next-spin state。
- 2026-05-28：新增 lifecycle-owned replacement-CID route registration。
  `EndpointConnectionLifecycle.registerReplacementConnectionId()` 现在会提交
  NEW_CONNECTION_ID-style replacement route，应用 `retire_prior_to`，并通过
  `statelessResetTokenForDatagram()` 暴露保留的 inactive-CID reset-token
  lookup。测试覆盖旧 CID 退役后的 routing 拒绝、保留 reset-token lookup、
  active replacement routing，以及 active route 的 reset-token suppression；
  `udp_connection_ids_loopback` 现在通过 lifecycle owner 完成 protected
  NEW_CONNECTION_ID/RETIRE_CONNECTION_ID 的 route update。后续
  `issueConnectionIdRoute()` 已把本端 CID 签发接到同一个 lifecycle-owned
  route update。
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
  的 packet number space 排 probe。后续 connection-level PTO backoff 更新让最早
  到期 PTO service 推进 shared backoff，同时抑制重复 peer probe。测试覆盖
  Initial 触发的 Handshake peer-space probe、重复排队抑制和 backed-off
  Handshake deadline；`pto_recovery` 现在会打印 peer-space probe 证据。
- 2026-05-27：修正 RFC 9002 persistent congestion duration，避免 PTO
  exponential backoff 放大 persistent congestion 判定阈值。`Recovery` 现在把
  persistent congestion 使用的 base PTO 计算，与 probe timer 使用的 backed-off
  PTO 计算分开。测试覆盖 recovery state 的 PTO backoff、PTO backoff 后 ACK
  驱动的 persistent congestion；`loss_recovery` 会打印 persistent-congestion
  duration 证据。
- 2026-05-27：对齐 closing 和 draining 状态的入站 datagram 处理语义。
  frame-payload 与 protected receive 入口现在会在 close timer 仍有效时直接丢弃
  入站 datagram，不解析非法字节、不生成 ACK，也不推进 peer packet-number 状态；
  close deadline 到期后的 `.closed` 仍返回 `ConnectionClosed`。测试覆盖本端
  queued close、对端 draining close、invalid-payload discard、close 后的 protected
  short-packet receive；`graceful_close` 示例现在会打印丢弃包时保留的 packet-number
  证据。
- 2026-06-01：把 close-state discard 覆盖扩展到 protected long-header 与 0-RTT
  receive 入口。close-path 测试现在会在本端 `closing` 和对端 `draining` 下执行
  close-propagating long/0-RTT wrapper，证明非法 protected bytes 不会被解析、
  不会生成 ACK，也不会推进 Initial 或 Application peer packet number；
  `graceful_close` 会打印对应的 long/0-RTT discard 证据。
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
  recovery-period 行为的 protected ACK frame，并输出 recovery 内重复 loss 不会再次降低
  congestion window 的证据，同时输出 persistent congestion 会把 congestion window 降到
  minimum window 的证据。ACK 驱动和 PTO 驱动的 1-RTT STREAM retransmission 加上 ACK
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
  lifecycle-owned route update/reset 会清除下一次 server ACK 和 client outgoing
  spin bit。
- 2026-05-26：新增 `examples/udp_flow_control_loopback.zig` 和
  `run-udp-flow-control-loopback` build step。该示例通过 loopback UDP 发送
  protected STREAM data 直到 receive limit，经过 endpoint lifecycle owner 上报
  STREAM_DATA_BLOCKED，把接收侧 MAX_DATA 和 MAX_STREAM_DATA credit refresh
  投递回发送端，随后恢复 STREAM 并携带 FIN，最后证明 ACK cleanup。
- 2026-06-04：扩展 `udp_flow_control_loopback` 的 caller-keyed resumed
  STREAM PTO 证据。接收侧 MAX_DATA/MAX_STREAM_DATA refresh 允许发送端携带 FIN
  恢复 STREAM 后，该示例会把 client recovery timer mirror 到
  `EndpointConnectionLifecycle`，通过
  `serviceRecoveryTimerAndPollProtectedShortDatagram()` 服务 Application PTO，
  把 protected resumed STREAM PTO probe 经 loopback UDP 路由到 server，验证重复
  FIN data 不会再次交付且 server ACK largest 前进，再用 final ACK 清空
  client bytes in flight。
- 2026-05-26：新增 `examples/udp_key_update_loopback.zig` 和
  `run-udp-key-update-loopback` build step。该示例把建模的 1-RTT traffic secret
  安装进 client/server 连接，发起 installed-key update，通过 lifecycle-owned
  loopback UDP routing 发送 next key-phase PING，验证 server 在认证成功后推进
  peer key phase，再通过同一个 lifecycle owner 回 ACK，并证明 ACK gate 会重新允许
  下一次本端 key update。
- 2026-06-04：扩展 `udp_key_update_loopback` 的 installed-key key-phase PTO
  证据。第二次本端 key update 发送 next-phase PING 后，该示例通过
  `serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys()` 服务
  client Application recovery timer，把 PTO probe 经 loopback UDP 路由到 server，
  验证该 probe 保持当前 key phase 并推进 server ACK largest；随后证明 stale
  old-generation packet 仍会被拒绝且不会改变 peer key-update state，最终 ACK
  清除第二次 ACK gate。
- 2026-05-26：新增 `examples/udp_connection_ids_loopback.zig` 和
  `run-udp-connection-ids-loopback` build step。该示例通过 loopback UDP 投递
  protected NEW_CONNECTION_ID，更新 replacement CID 的 endpoint route，证明旧 CID
  只暴露 inactive reset token，并探测 active replacement CID routing，再经 active
  replacement CID 路由 protected RETIRE_CONNECTION_ID，并验证 server-side local CID
  retirement 与 ACK cleanup。
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
  route，通过 server transport-parameter bytes 学到 preferred-address
  CID/token，并通过同一个 lifecycle owner 在第二个 server 地址上提交调用方已验证的
  preferred-address CID，证明旧 route 已退役、preferred path 可路由、同一 CID
  在 stray path 下因 active-migration-disabled 被拒绝，并验证 preferred-address
  reset token 在退役后仍可查找。
- 2026-05-25：新增 `examples/udp_zero_cid_loopback.zig` 和
  `run-udp-zero-cid-loopback` build step。该示例通过
  `EndpointConnectionLifecycle` 在不同 UDP 四元组上注册两个 zero-length
  destination CID route，证明 short/long datagram 都能通过 loopback socket 按
  tuple identity 路由，并在更新前拒绝未注册 tuple，随后通过 lifecycle owner
  按 path 退役其中一个 zero-CID route，并把剩余 route 更新到这个先前未知的
  对端端口后再次验证路由。
- 2026-05-25：新增 `examples/udp_path_validation_loopback.zig` 和
  `run-udp-path-validation-loopback` build step。该示例通过 loopback UDP 把
  protected PATH_CHALLENGE 发送到新的 client 端口，先证明新 path 上验证前的
  protected PING 不会更新 endpoint route；server endpoint 收到 protected
  PATH_RESPONSE 时先报告 `path_changed = true`，连接层验证响应并消耗
  outstanding challenge 后，经 close-propagating route-update helper 提交
  endpoint route update，并证明后续同一路径路由不再报告 path change。
- 2026-05-25：新增 `examples/udp_retry_loopback.zig` 和
  `run-udp-retry-loopback` build step。该示例通过 loopback UDP 发送一个
  Initial-like datagram，server 签发带地址绑定 endpoint token 的 Retry，把
  Retry 经 lifecycle owner 路由回 client，将 server pending route 切换到
  Retry Source CID，校验后续 Initial 中的 token 并拒绝 replay，消费一次性
  Retry token，基于 Retry 派生的 Initial key 交换 protected Initial CRYPTO，
  并校验 Retry 相关 transport parameter。
- 2026-05-25：扩展 `examples/udp_endpoint_loopback.zig`，把真实 loopback
  UDP Version Negotiation response 交给
  `Connection.processVersionNegotiationDatagram()` 处理。示例现在能在同一个
  socket-backed flow 中证明 lifecycle-owned endpoint VN response delivery 与
  client-side mutual-version selection。
- 2026-05-25：新增 `examples/udp_close_lifecycle_loopback.zig` 和
  `run-udp-close-lifecycle-loopback` build step。该示例通过 loopback UDP 投递
  protected CONNECTION_CLOSE，client/server route state 均由
  `EndpointConnectionLifecycle` 持有，并经 active endpoint CID 路由到连接；
  同时演示认证后畸形 short packet 的 lifecycle-routed protected receive auto-close；
  还会应用 close/drain timeout-driven lifecycle route cleanup；server 进入
  draining 后按 connection handle 退役 routes，然后对同一 inactive CID 的后续
  packet 使用保留的 token 发出 stateless reset。
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
  `Connection.processVersionNegotiationDatagram()` 会校验 RFC 8999
  connection-ID echo，忽略包含 client Original Version 或 CID 不匹配的 packet，
  从本地 `available_versions` 中选择 mutual version，记录本次 connection attempt
  已经响应过 VN，并通过 `versionNegotiationSelectedVersion()` 暴露结果。后续
  helper 现在会从该状态派生 follow-up config、替换 endpoint route，并 hand off
  follow-up client connection；完整 socket-owned retry-loop integration 仍待实现。
- 2026-05-23：新增 client 响应 Version Negotiation 后的 RFC 9368 server Version
  Information downgrade checks。后续 client connection 可携带
  `Config.version_negotiation_selected_version`；对端 transport-parameter 校验会要求
  server Chosen Version 匹配该选择，拒绝空的 server Available Versions，校验
  client 基于 server Available Versions 加 negotiated version 仍会选择同一版本，并保留
  QUIC v1 缺失 `version_information` 的例外。后续 endpoint lifecycle helper 已能
  hand off follow-up connection object；完整 socket-owned incompatible-version
  retry-loop integration 仍待实现。
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
- 2026-05-29：扩展 `quicz.transport_error`，新增
  `frameDecodeErrorCode()`，把入站 frame codec 失败（例如未知 frame type、
  非法 frame value、非法 ACK range、截断 frame body）分类为
  `FRAME_ENCODING_ERROR`，同时不映射本地资源错误。测试覆盖所有映射的 frame
  decode error，`examples/codec_roundtrip.zig` 会打印映射后的 close code 名称。
- 2026-05-29：扩展 `quicz.transport_error`，新增
  `transportParameterErrorCode()`，把 transport parameter 解析和值校验失败
  （例如非法长度、非法值、重复参数、非法 varint、截断 extension）分类为
  `TRANSPORT_PARAMETER_ERROR`，同时不映射本地 encode-buffer 和分配失败。测试覆盖
  所有映射的 codec error，`examples/codec_roundtrip.zig` 会打印映射后的 close code
  名称。
- 2026-05-29：新增 `framePacketTypeErrorCode()`，用于 RFC 9000 packet-type
  frame 校验。语法合法的 frame 如果出现在禁止的 Initial、Handshake 或 0-RTT
  packet 上，会映射为 `PROTOCOL_VIOLATION`；允许的 packet/frame 组合返回 null。
  测试覆盖允许的 Initial/1-RTT frame，以及禁止的 Initial、Handshake 和 0-RTT
  frame；`examples/codec_roundtrip.zig` 会打印映射后的 packet-type close code。
- 2026-05-29：新增显式 close 传播 wrapper
  `processDatagramForPacketTypeOrClose()`。它保持原
  `processDatagramForPacketType()` 只回滚不关闭的行为不变，但可把畸形或未知
  frame payload 排队为 `FRAME_ENCODING_ERROR` transport CONNECTION_CLOSE，把语法合法但
  出现在禁止 packet type 中的 frame 排队为 `PROTOCOL_VIOLATION` transport
  CONNECTION_CLOSE。测试覆盖两条 close 路径，`examples/graceful_close.zig`
  会打印非法 0-RTT ACK 触发的 close。
- 2026-05-29：新增默认和 packet-number-space close 传播 receive wrapper：
  `processDatagramOrClose()` 与 `processDatagramInSpaceOrClose()`。它们委托同一套
  packet-type close classifier，并保持 `processDatagram()` 与
  `processDatagramInSpace()` 只回滚不关闭。测试覆盖 Application-space frame
  encoding close 与 Initial-space forbidden-frame protocol violation，
  `examples/graceful_close.zig` 会打印两条路径。
- 2026-05-30：新增 authenticated protected long/short receive 的 close 传播
  wrapper。`processProtectedLongDatagramOrClose()`、
  `processProtectedLongDatagramInSpaceOrClose()`、
  `processProtectedZeroRttDatagramOrClose()`、`processProtectedShortDatagramOrClose()`
  及 installed-key/key-update 变体保持旧成功路径不变，但会把已分类 protected
  plaintext frame 错误排队为 CONNECTION_CLOSE。测试覆盖 protected Initial packet-type
  violation 和 protected short frame-encoding close，`examples/graceful_close.zig`
  会打印两条路径。
- 2026-05-30：为 `EndpointConnectionLifecycle` 新增 direct/routed protected
  receive `*OrClose` wrapper，覆盖 Initial、long-header、0-RTT、short-header、
  显式 key-phase 和 installed-key 路径。旧 lifecycle receive API 继续只回滚不关闭；
  socket/lifecycle loop 可在 route selection 成功后显式选择 close propagation。
  测试覆盖 routed protected short frame-encoding close 和 routed protected Initial
  packet-type close，`examples/graceful_close.zig` 会打印 lifecycle-routed
  protected auto-close 路径。
- 2026-05-22：新增 `examples/codec_roundtrip.zig` 和 `zig build run-codec`。
  该示例演示 varint、short-packet envelope、coalesced long-packet envelope、
  short-header spin-bit 保留、header packet number 截断/重建、packet number
  编码、Version Negotiation、STREAM frame、transport parameter、连接层
  transport-parameter 暴露（含 TLS extension bytes、本端 ACK delay policy 和 server preferred_address）与
  transport error helper 的 roundtrip（含 transport-parameter、frame codec 和
  packet-type error 分类）。
- 2026-05-22：新增 `Connection.localTransportParameters()` 和
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
- 2026-05-29：新增 `applyPeerTransportParameterBytesOrClose()`，作为对端
  transport-parameter extension bytes 的显式 close 传播 wrapper。它保持
  `applyPeerTransportParameterBytes()` 只回滚不关闭的行为不变，但会把畸形
  extension 或非法对端参数语义排队为 `TRANSPORT_PARAMETER_ERROR` transport
  CONNECTION_CLOSE，并把 frame_type 标为 CRYPTO。测试覆盖 parse 和语义校验两条
  close 路径，`examples/transport_parameters.zig` 会打印 auto-close code 和 frame type。
- 2026-05-28：新增 `examples/transport_parameters.zig` 和
  `zig build run-transport-parameters`。该示例覆盖本端 TLS extension byte
  导出、对端 extension bytes 解析/应用、client 省略 server-only
  `stateless_reset_token` 与 `preferred_address`、client 存储 server
  preferred-address/reset-token policy、有效 idle-timeout 选择、对端 stream-data
  limit enforcement，以及 server 拒绝 client 发送 server-only 参数。
- 2026-05-22：新增 `Connection.sendPathChallenge()`，支持 outbound
  PATH_CHALLENGE 排队、匹配 PATH_RESPONSE 校验、重复或不匹配 response 拒绝，
  并补充无效多帧 payload 的回滚测试；timeout/retry 策略仍待实现。
- 2026-05-22：在 `Connection` 增加对端签发 connection ID 生命周期跟踪。
  NEW_CONNECTION_ID 现在会保存 active peer CID、拒绝 sequence number 相同但
  内容不一致的重复帧、拒绝跨 CID stateless reset token 复用、遵守配置的
  active CID limit，并通过 retire_prior_to 排队 RETIRE_CONNECTION_ID；无效多帧
  payload 会回滚部分 CID 状态。本端 CID 签发与 endpoint route registration
  现在已有 lifecycle-owned bridge；完整 TLS-owned socket routing 仍待实现。
- 2026-05-22：在 `Connection` 增加本端 connection ID 签发。
  `issueConnectionId()` 会复制本端 CID 字节、分配 NEW_CONNECTION_ID sequence
  number、应用 `retire_prior_to` 后遵守对端 active CID limit、拒绝重复本端 CID
  和 stateless reset token 复用，并把未发送 CID 排队给
  `pollTx()`。入站 RETIRE_CONNECTION_ID 现在会把已发送本端 CID 标记为 retired，
  并在无效多帧 payload 中回滚 retirement。endpoint route-table skeleton 现在可保存
  可选 NEW_CONNECTION_ID sequence number，并可按 sequence 或 retire_prior_to
  threshold retire route，供后续 RETIRE_CONNECTION_ID wiring 使用；
  socket-backed replacement-CID route-retirement 和 caller-owned NEW/RETIRE
  证明现在位于 `examples/udp_replacement_cid_loopback.zig` 与
  `examples/udp_connection_ids_loopback.zig`，且
  `EndpointConnectionLifecycle.issueConnectionIdRoute()` 现在会把本端签发与
  endpoint route registration 串联。自动 socket 拥有的替换策略仍待实现。
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
- 2026-05-30：拒绝超过 2^60 的入站 MAX_STREAMS_BIDI/UNI 值。兼容 receive
  API 会回滚且不更新对端 stream limit；`processDatagramOrClose()` 会按 RFC
  9000 把同一非法 frame 映射为 FRAME_ENCODING_ERROR。测试覆盖 bidi/uni
  receive 回滚和 close 传播。
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
- 2026-06-01：本地发送侧 reset 后也忽略入站 MAX_STREAM_DATA。`Connection`
  现在用同一个发送侧关闭判断覆盖 FIN 与 RESET_STREAM，因此后续 credit 更新不能
  重新打开已 reset 的发送端，pending STREAM_DATA_BLOCKED 也复用同一关闭边界。
  测试覆盖 reset 边界，`examples/stream_reset.zig` 演示被忽略的 credit 更新。
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
- 2026-05-22：在 `Connection` 增加入站乱序 STREAM range 缓存。
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
- 2026-05-22：新增 `Connection.resetStream()` 与
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
- 2026-05-22：新增 `Connection.stopSending()` 与
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
- 2026-05-22：在 `Connection` 增加客户端侧 NEW_TOKEN 存储。
  client 连接会按 `Config.max_stored_new_tokens` 上限保存 opaque token
  字节，并通过 `latestNewToken()` 暴露最新 token。测试覆盖存储、容量、
  server 侧拒绝和无效 payload 回滚；认证 token 生成、过期和 endpoint
  peer-address binding 由后续 address-validation token 与 endpoint helper 覆盖。
- 2026-05-22：在 `Connection` 增加本端 close 发出能力，包含
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
- 2026-06-02：新增
  `EndpointConnectionLifecycle.checkIdleTimeoutsAndRetireConnection()`，让
  endpoint event loop 可在同一个受控时钟步骤中应用 connection idle timeout，
  并清理对应 destination-CID routes 和 recovery timer。
  `examples/idle_timeout.zig` 现在会输出 lifecycle 清理结果。
- 2026-06-03：新增 `Connection.checkCloseTimeouts()` 和
  `EndpointConnectionLifecycle.checkCloseTimeoutsAndRetireConnection()`，让
  endpoint event loop 可在同一个受控时钟步骤中应用 close/drain timeout 到期，
  并清理对应 destination-CID routes 和 recovery timer。测试覆盖本端 closing
  与对端 draining 两条转换，`examples/udp_close_lifecycle_loopback.zig` 会输出
  timeout cleanup 结果。
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
- 2026-06-02：新增
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramAndUpdatePath()`。
  该 helper 只会在 routed protected short-packet 认证成功，且 packet 通过匹配
  PATH_RESPONSE 消费 outstanding PATH_CHALLENGE 后，提交 endpoint route path
  update。`run-path-validation` 与 `run-udp-path-validation-loopback` 现在使用这个
  validation-driven lifecycle path update，不再额外手动调用 `updateRoutePath()`。
- 2026-06-03：新增
  `EndpointConnectionLifecycle.processRoutedProtectedShortDatagramAndUpdatePathOrClose()`。
  它保持相同的验证驱动成功路径，同时会为认证后的 Application frame 错误排队
  CONNECTION_CLOSE，并在失败时保持 endpoint route 不变。测试覆盖 no-update close
  路径，`run-udp-path-validation-loopback` 现在使用这个 close-propagating helper。
- 2026-05-30：把 protected short-header PATH_CHALLENGE 和 PATH_RESPONSE
  datagram 在建模 peer-address 发送预算允许时扩展到至少 1200 字节，以符合
  RFC 9000 path-validation padding，同时在 anti-amplification 受限时保留小包
  fallback。测试覆盖扩展后的 exchange 与 fallback，`examples/path_validation.zig`
  会断言并打印 1200 字节 datagram 证据。
- 2026-05-30：对重复 PATH_CHALLENGE data 抑制重复的 pending PATH_RESPONSE。
  在首次响应发出前，连接仍会 ACK 收包，并为每个不同 challenge token 保留一个
  response，避免重复 challenge frame 用相同 payload 放大待发送响应队列。
- 2026-05-22：新增 `examples/connection_ids.zig` 和
  `zig build run-connection-ids`。该示例演示本端 NEW_CONNECTION_ID 签发、
  对端 RETIRE_CONNECTION_ID 处理，以及 lifecycle-owned issue/register endpoint
  replacement-CID route bridge 和 retire_prior_to。
- 2026-05-22：在 `quicz.packet` 增加 stateless reset helper，并在连接层增加
  只读 reset 检测。`encodeStatelessReset()` 使用调用方提供的不可预测字节和
  16 字节 token 序列化 reset datagram，`matchesStatelessReset()` 以 constant-time 方式比较尾部
  token，`Connection.detectStatelessReset()` 匹配 active peer-issued CID
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
- 2026-05-22：新增 `Connection.processInitialProtectedDatagram()`。
  该连接层 bridge 会用调用方提供的 RFC 9001 Initial keys 解开一个 QUIC v1
  protected Initial long packet，校验 packet type、packet number 和单 packet
  datagram 边界，再把 plaintext frame payload 投递到 Initial packet number
  space。测试覆盖受保护 Initial CRYPTO 投递、ACK 生成、next peer packet
  number 前进，以及篡改 packet 的状态回滚。CRYPTO-only long packet 之外的
  protected transmit、TLS traffic secret production、key discard 和 key update
  仍待实现。
- 2026-05-22：新增 `Connection.pollInitialProtectedDatagram()`，覆盖
  Initial CRYPTO bridge 的发送侧。它会从 Initial CRYPTO send queue 发出一个
  protected QUIC v1 Initial long packet，使用选定的 packet-number encoding，
  只在 header-protection sample 需要时补 PADDING，并把 protected datagram
  字节数计入 sent-packet、recovery、anti-amplification 和 idle-timeout 记账。
  测试覆盖 protected send 到 `processInitialProtectedDatagram()`、packet number
  前进、bytes-in-flight 记账，以及没有 Initial CRYPTO 排队时保持 idle。
  ACK-only、PING-only、coalesced protected packet、TLS traffic secret
  production、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `Connection.processProtectedLongDatagramInSpace()` 与
  `pollProtectedLongCryptoDatagramInSpace()`，把 protected long-packet bridge
  从 Initial 泛化到 Initial 和 Handshake 两个 packet number space。原有
  Initial-specific wrapper 继续保留以兼容现有调用。测试覆盖 protected
  Handshake CRYPTO 发出/解密/投递、packet-number 记账、long-packet packet
  type 不匹配时的回滚，以及 Handshake token 在修改发送状态前被拒绝。
  `examples/crypto_stream.zig` 现在会用调用方提供的 keys 让 Initial 与
  Handshake CRYPTO flight 都经过 protected long packet。Endpoint Retry policy、
  1-RTT protected transmit、TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `Connection.processProtectedLongDatagram()` 与
  `ProtectedLongDatagramKeys`，用于 coalesced protected long datagram 接收路由。
  该方法会先 peek 每个 long-header packet 的边界，确认所有 packet type 均可
  支持且调用方已提供对应 keys，再开始修改连接状态；随后逐个打开 Initial 或
  Handshake packet 并路由到对应 packet number space。测试覆盖一个 coalesced
  datagram 中同时包含 Initial+Handshake CRYPTO，以及缺少 Handshake key 时不会
  提前修改 Initial 状态。`examples/crypto_stream.zig` 现在演示 coalesced server
  Initial + Handshake flight。Endpoint Retry policy、1-RTT protected transmit、
  TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `Connection.pollProtectedLongDatagram()`，用于
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
  `Connection.processProtectedShortDatagram()`，用于调用方提供 key 的
  1-RTT short-header packet 接收。连接层 API 要求调用方提供 destination-CID
  长度上下文，打开单个 protected short datagram，要求 packet number 匹配
  Application packet number space 的下一个期望值，然后按 1-RTT frame 规则投递
  plaintext。测试覆盖 protected short-packet roundtrip、header-protection
  sample 长度边界、PING 投递到 Application ACK 状态、packet-number 不匹配回滚，
  以及 authentication failure 不修改状态。`examples/crypto_stream.zig` 现在会在
  建模 handshake confirmation 后演示 protected 1-RTT PING receive。Retry
  routing、TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-22：新增 `Connection.pollProtectedShortDatagram()`，用于调用方
  提供 key 的 1-RTT short-header PING/ACK transmit。该方法会保护
  Application-space PING 加可选 ACK，或 ACK-only 状态，检查 congestion 和
  anti-amplification 预算，推进 packet number，只为 ack-eliciting packet 记录
  bytes-in-flight，并清理已提交的 ACK/PING 状态。测试覆盖 protected 1-RTT
  PING 后接 ACK-only protected response，并确认 sender bytes-in-flight 被清空。
  `examples/crypto_stream.zig` 现在会在建模 handshake confirmation 后演示
  protected 1-RTT PING/ACK exchange。Endpoint Retry policy、TLS secret production、
  key discard 和 key update 仍待实现。
- 2026-05-22：扩展 `Connection.pollProtectedShortDatagram()`，支持把一个
  queued Application-space STREAM frame 和可选 ACK 保护为 1-RTT short packet。
  commit path 只会在 packet-number、congestion 和 anti-amplification 检查通过后
  消费已发送的 stream frame，并在这些检查阻塞发送时释放预构造的 datagram。测试覆盖
  protected STREAM 投递、随后 protected ACK 清空 sender bytes-in-flight，以及
  anti-amplification block 不消费 queued STREAM、后续仍可发送。`examples/crypto_stream.zig` 现在会在建模
  handshake confirmation 后演示调用方 key 的 protected 1-RTT PING/ACK 与
  STREAM/ACK exchange。Endpoint Retry policy、TLS secret production、key discard 和
  key update 仍待实现。
- 2026-05-22：扩展 `Connection.pollProtectedShortDatagram()`，支持把 queued
  Application-space `RESET_STREAM` 与 `STOP_SENDING` frame 加可选 ACK 保护为
  1-RTT short packet。protected path 现在沿用 `pollTx()` 的 stream-control
  优先级，只在 send commit 后消费 RESET/STOP 队列，并在 RESET_STREAM 发出后继续
  丢弃 stale STREAM data。测试覆盖 protected RESET_STREAM 投递、stale STREAM
  移除、protected ACK 清理，以及 protected STOP_SENDING 后接 protected
  RESET_STREAM response。`examples/crypto_stream.zig` 现在演示调用方 key 的
  protected 1-RTT PING/ACK、STREAM/ACK、RESET_STREAM/ACK 和
  STOP_SENDING/RESET_STREAM exchange。Endpoint Retry policy、TLS secret production、
  key discard 和 key update 仍待实现。
- 2026-05-22：扩展 `Connection.pollProtectedShortDatagram()`，支持把 queued
  Application-space CRYPTO frame 和可选 ACK 保护为 1-RTT short packet。
  protected path 只会在 packet-number、congestion 和 anti-amplification
  检查通过后消费 CRYPTO 队列，沿用 STREAM transmit 的回滚边界。测试覆盖
  protected CRYPTO 投递、随后 protected ACK 清空 sender bytes-in-flight，以及
  anti-amplification block 不消费 queued CRYPTO、后续仍可发送。
  `examples/crypto_stream.zig` 现在演示调用方 key 的 protected 1-RTT
  PING/ACK、CRYPTO/ACK、STREAM/ACK、RESET_STREAM/ACK 和
  STOP_SENDING/RESET_STREAM exchange。Endpoint Retry policy、TLS secret production、
  key discard 和 key update 仍待实现。
- 2026-05-22：扩展 `Connection.pollProtectedShortDatagram()`，支持把 queued
  Application-space `PATH_RESPONSE` 与 outbound `PATH_CHALLENGE` frame 和可选
  ACK 保护为 1-RTT short packet。PATH_RESPONSE 队列只在 send commit 后消费；
  PATH_CHALLENGE 也只会在 packet-number、congestion 和 anti-amplification
  检查通过后移动到 outstanding validation 状态。Protected PATH_CHALLENGE /
  PATH_RESPONSE datagram 会在 anti-amplification 预算允许时扩展到至少 1200
  字节。测试覆盖 protected PATH_CHALLENGE/PATH_RESPONSE/ACK 往返、
  PATH_RESPONSE padding 的 anti-amplification fallback，以及 anti-amplification
  block 不消费 pending PATH_CHALLENGE、后续仍可发送。`examples/path_validation.zig`
  现在会在 frame-payload 重试示例之外演示 protected short-header
  path-validation exchange 和 datagram 扩展。Endpoint Retry policy、TLS secret
  production、key discard 和 key update 仍待实现。
- 2026-05-23：新增 protected path-validation 与 endpoint-routing 集成测试。
  到达新 UDP tuple 的 datagram 会先被报告为 `path_changed`；只有在匹配的
  protected PATH_RESPONSE 被处理后，调用方才提交
  `EndpointRouter.updateRoutePath()`，之后同一 tuple 会在无 path-change 报告下
  路由。`examples/path_validation.zig` 现在输出 endpoint path-change 与
  path-update 结果。自动 socket-backed path-validation ownership 仍待实现。
- 2026-05-23：扩展 `Connection.pollProtectedShortDatagram()`，支持把 queued
  Application-space `RETIRE_CONNECTION_ID` frame 与未发送的本端
  `NEW_CONNECTION_ID` frame 和可选 ACK 保护为 1-RTT short packet。protected path
  只会在 packet-number、congestion 和 anti-amplification 检查通过后消费 RETIRE
  队列并把本端 connection ID 标记为 sent。测试覆盖 protected NEW/ACK、replacement
  NEW 触发 protected RETIRE+ACK、最终 ACK 清理，以及 anti-amplification block 不标记
  未发送的 NEW_CONNECTION_ID、后续仍可发送。`examples/connection_ids.zig` 现在会演示
  lifecycle-owned issue/register route bridge 和调用方 key 的 protected 1-RTT
  NEW_CONNECTION_ID/RETIRE_CONNECTION_ID exchange。
  Endpoint Retry policy、TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-23：扩展 `Connection.pollProtectedShortDatagram()`，支持把 queued
  Application-space MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS_BIDI/UNI、
  DATA_BLOCKED、STREAM_DATA_BLOCKED 与 STREAMS_BLOCKED_BIDI/UNI frame 和可选
  ACK 保护为 1-RTT short packet。protected path 会先丢弃过期 MAX/BLOCKED，
  并且只在 packet-number、congestion 和 anti-amplification 检查通过后消费 queued
  frame。测试覆盖 protected MAX_DATA/MAX_STREAM_DATA 投递、所有 protected
  BLOCKED 变体，以及 anti-amplification block 不消费 queued MAX/BLOCKED、后续仍可发送。
  `examples/flow_control.zig` 现在演示调用方 key 的 protected short
  STREAM_DATA_BLOCKED + MAX_DATA/MAX_STREAM_DATA exchange，并恢复 stream 发送。
  Endpoint Retry policy、TLS secret production、key discard 和 key update 仍待实现。
- 2026-05-23：扩展 `Connection.pollProtectedShortDatagram()`，支持把 queued
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
  并扩展 `Connection.pollProtectedShortDatagram()`，支持把 queued
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
- 2026-05-23：新增客户端侧 `Connection.processRetryDatagram()`，用于
  Retry packet 路由。该方法会使用 Original Destination Connection ID 校验
  RFC 9001 Retry Integrity Tag，拒绝 server 侧、重复、Initial space 已丢弃
  和格式错误的 Retry datagram 且不修改状态，保存 `latestRetryToken()` 与
  `retrySourceConnectionId()`，并在后续 protected Initial packetization 收到空
  explicit token 时自动使用已保存的 Retry token。测试覆盖 token/Retry SCID
  保存、Initial 自动带 token、篡改拒绝、重复拒绝和 server 侧拒绝。
  `examples/retry_token.zig` 现在演示 connection-layer Retry 处理路径。后续条目
  覆盖内存态 endpoint 级 Retry DCID switching 和 token policy。
- 2026-05-23：新增 server 侧 `Connection.issueRetryDatagram()`，用于连接层
  Retry 签发。它会生成带 RFC 9001 Retry Integrity Tag 的 QUIC v1 Retry
  datagram，注册 opaque token 供一次性校验，记录 Original Destination
  Connection ID 与 Retry Source Connection ID，并通过 `localTransportParameters()`
  导出两者。测试覆盖 Retry integrity、本端 transport-parameter 导出、client
  处理、token 消费、重复签发拒绝和无效输入回滚。`examples/retry_token.zig`
  现在使用这条连接层签发路径。后续条目覆盖内存态 endpoint 级 Retry DCID
  switching 和 token policy。
- 2026-05-23：新增 `quicz.address_validation_token` 以及
  `Connection.issueAddressValidationToken()` /
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
  `Connection.validateAddressValidationTokenWithSecrets()`。调用方可以按
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
  migration 仍待实现；UDP loopback 现在会先通过 server preferred_address
  transport-parameter bytes 学到 preferred CID/token，再提交调用方验证后的 route。
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
  先证明 active CID 会正常 route 并抑制 reset token，再证明 unknown CID 会被
  drop 且不发 reset，然后退役该 CID 并保留其 stateless reset token，把同一个
  trigger datagram 投递到 server socket，由
  `EndpointConnectionLifecycle.handleDatagram()` 通过 lifecycle-owned route
  state 分类为 reset response，再把 reset datagram 发回客户端，并验证客户端
  可以匹配保留的 token。完整 TLS-owned connection lifecycle 集成仍待实现。
- 2026-05-22：为 `Connection` 增加按 packet number space 隔离的 ECN
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
- 2026-05-22：在 `Connection` ACK 处理中增加简化 RFC 9002
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
  仍在 flight 时，该 hook 现在 service 最早到期且未 discard 的 Initial、
  Handshake 或 Application packet number space，推进 connection-level PTO
  backoff，并为其他 in-flight space 排 peer probe。后续更新让 Application PTO
  在 fallback 到 PING 前优先复用 queued 或 in-flight STREAM data。
- 2026-05-23：让 `checkPtoTimeouts()` 在新增 PING probe 前优先使用已经排队的
  ack-eliciting 数据。到期 PTO 仍会推进 connection-level backoff，但已排队的
  Application STREAM 数据、按 space 的 CRYPTO 或其他待发送 ack-eliciting frame
  可以直接作为 probe packet。测试覆盖 queued STREAM probe selection 且不会额外排队
  PING；后续更新已覆盖 ACK-lost 与 PTO-probed 1-RTT STREAM data、PTO-probed
  protected CRYPTO data、ACK-lost frame-payload CRYPTO data、ACK-lost
  protected CRYPTO data、protected 0-RTT STREAM data 和 protected 0-RTT
  RESET_STREAM/STOP_SENDING control data 的克隆。
- 2026-05-25：调整 packet-number-space PTO 计算，Initial 和 Handshake space
  不再计入 `max_ack_delay`，Application PTO 保持现有 peer-delay 项。
  `recovery.Recovery.ptoMsWithoutMaxAckDelay()` 暴露该 timer 基础，
  `ptoDeadlineMillis(.initial/.handshake)` 已使用它；`examples/pto_recovery.zig`
  会打印 100ms initial RTT 下 10ms/20ms 发包得到的 310ms/320ms 可控时钟 deadline。
- 2026-05-22：新增 `examples/pto_recovery.zig` 和
  `zig build run-pto-recovery`。该示例演示 handshake confirmation 前的
  Application PTO gating、deadline gating、PTO 触发的 PING 排队、通过
  `pollTx()` 发出 Application PING、queued STREAM 数据作为 PTO probe、
  in-flight STREAM 数据作为 PTO probe、protected 1-RTT CRYPTO 作为 PTO
  probe，以及通过 `pollTxInSpace()` 发出 Initial/Handshake PING。
- 2026-05-22：新增通过 client-side HANDSHAKE_DONE 与 `confirmHandshake()`
  建模 handshake confirmation。RTT 更新现在会忽略 Initial 与 Handshake ACK
  Delay，并把合法 RTT sample 共享到各 packet number space；同时按对端
  `ack_delay_exponent` 解码 ACK Delay，并在 handshake confirmed 后把解码后的
  ACK Delay 截到对端 `max_ack_delay`。单元测试覆盖 ACK-delay 计算、RTT 影响、
  shared RTT rollback 和无效 payload 回滚，`examples/loss_recovery.zig` 演示
  该截断，`examples/pto_recovery.zig` 演示跨 space RTT 共享。
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
- 2026-05-29：为同一组 packet-type frame 规则新增 opt-in close 路径。
  `processDatagramForPacketTypeOrClose()` 会先对 frame payload 做无副作用分类，
  再进入正常 receive 处理；frame encoding 或 packet-type violation 会排队
  transport CONNECTION_CLOSE，旧 receive API 仍只拒绝并回滚 invalid payload。
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
  handoff、非法对端 transport-parameter 在排队出站输出前拒绝、非法对端
  transport-parameter 在拉取出站输出前的 close-propagating 处理、乱序
  Handshake CRYPTO 投递、分块 backend 输出排队、handshake confirmation，
  以及 zero-length scratch buffer 在消费前拒绝；`examples/crypto_stream.zig`
  现在会打印 mock backend bridge flow 和 backend transport-parameter
  auto-close 证据。
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
| `codec_roundtrip` | 演示 varint、packet header、RFC 9369 QUIC v2 long-header type-bit 映射、short-header spin-bit 保留、long/short-packet envelope、header packet number 截断/重建、packet number 编码、RFC 8999 Version Negotiation packet codec、reserved-version skip、client-side VN selection、显式 RFC 9368 compatible-version selection、follow-up config propagation、RFC 9368 downgrade-check state 和 `VERSION_NEGOTIATION_ERROR` close-code 证据、frame、包含 RFC 9368 `version_information` 的 transport parameter、连接层参数暴露（含 TLS extension bytes 和 server preferred_address）与包含 `VERSION_NEGOTIATION_ERROR`、transport-parameter `TRANSPORT_PARAMETER_ERROR`、frame decode `FRAME_ENCODING_ERROR`、packet-type `PROTOCOL_VIOLATION` 分类的 transport error codec。 | 已存在 |
| `transport_parameters` | 专门演示 transport parameter 用法：本端 TLS extension byte 导出、reserved-parameter greasing/ignore、对端 byte 解析/应用、server-only 参数角色过滤、带 peer Version Information snapshot 的 compatible-version selection apply、transport-parameter auto-close、preferred-address/reset-token 存储、有效 idle timeout、peer max_udp_payload_size recovery max_datagram_size/initial-cwnd resync 与对端 stream limit enforcement。 | 已存在 |
| `crypto_stream` | 当前乱序 Handshake CRYPTO 重组、ACK 驱动的 frame-payload Handshake CRYPTO loss requeue/retransmission、ACK 驱动的 protected 1-RTT CRYPTO loss requeue/retransmission、mock `CryptoBackend` bridge 投递/输出排队/本端和对端 TP handoff/compatible peer Version Information handoff progress/peer-TP protected auto-close/Handshake、0-RTT 与 1-RTT secret handoff/confirmation、backend-confirmed no-output 和 post-final-outbound-CRYPTO Handshake discard、显式 handshake-state 可观测状态、带合法首个 client Initial DCID 和 1200 字节 Initial datagram 流程的 protected Initial 与 Handshake CRYPTO transmit/receive bridge、installed-key Handshake 与显式 accept 后的 0-RTT long-packet exchange、无 Retry Original DCID 导出/校验、通过 `localTransportParameters()` 导出本端 Initial SCID、coalesced server Initial+Handshake transmit/receive、peer Initial SCID 捕获与 `initial_source_connection_id` 校验、protected client Initial ACK-only + Handshake PING/ACK probe、建模 handshake confirmation、调用方 key 的 protected 1-RTT PING/ACK、CRYPTO/ACK、STREAM/ACK、RESET_STREAM/ACK、STOP_SENDING/RESET_STREAM exchange、ACK-gated installed-key 1-RTT key-update PING、调用方持有 key-phase 状态的 key-update PING，以及可配置 short-header spin-bit 状态。 | 已存在 |
| `tls_backend_adapter` | 可运行的 C-ABI `TlsBackend` adapter 契约检查：在绑定具体 C TLS 库之前，先通过现有 `CryptoBackend` drive 路径验证本端/对端 transport-parameter byte handoff、入站/出站 CRYPTO byte 投递、输入 callback status 拒绝、output-buffer pending/byte 一致性、Handshake traffic-secret 安装和 handshake confirmation。 | 已存在 |
| `tls_c_abi_adapter` | 可运行的 C-object-backed `TlsBackend` 检查：由 C 编译单元里的 callback object 通过 Zig adapter 驱动 transport-parameter、CRYPTO byte、Handshake secret 和 confirmation 路径，为后续替换成成熟 C TLS 库绑定做边界验证。 | 已存在 |
| `tls_openssl_probe` | 可运行的 OpenSSL QUIC TLS API/link probe：通过 `pkg-config` 使用 OpenSSL，创建 OpenSSL full QUIC client method object，在 callback-mode TLS object 上设置 QUIC TLS callbacks 与本端 transport parameters，并打印 crypto send、secret yield 和 peer transport-parameter callback 所需 dispatch ID。 | 已存在 |
| `tls_openssl_pair_transcript` | 可运行的 OpenSSL client/server callback-mode transcript 检查：固定示例 PSK 避免证书 fixture 噪声，CRYPTO bytes 按 OpenSSL protection level 路由，双端无 alert 完成 TLS 1.3，双端都会触发 peer transport-parameter callback 与 Handshake/1-RTT secret callback，quicz 编码的按角色区分本端 transport-parameter bytes 会配置给 OpenSSL，随后从 peer transport-parameter callback 复制并解析，并记录 keylog callback 次数和字节数但不打印 key material；生成的 CRYPTO bytes 会投递到 quicz Initial/Handshake/Application CRYPTO 队列，同时会把 client Initial CRYPTO bytes 经 quicz protected Initial long-packet helper 组包并投递到 server connection，也会通过 quicz endpoint lifecycle 在 loopback UDP 上投递双向 Initial flight；手动 OpenSSL context 检查会把 live Initial 和 Handshake TLS CRYPTO bytes 通过同一 socket/lifecycle 边界双向路由；用 OpenSSL 产出的 Handshake secrets 驱动双向 installed-key protected Handshake CRYPTO 投递，包括通过同一个 lifecycle 路由的 loopback UDP 投递；同一个手动 OpenSSL context 会通过同一 socket/lifecycle 路径驱动 1-RTT STREAM request/echo/final-ACK、Handshake key discard 和 protected close/route cleanup，并用 OpenSSL 产出的 1-RTT secrets 驱动 short packet 上的 installed-key protected STREAM request/response，以及通过同一个 lifecycle 路由的 loopback UDP STREAM echo。 | 已存在 |
| `tls_openssl_backend_adapter` | 可运行的 OpenSSL-backed `TlsBackend` wrapper 检查：endpoint lifecycle-owned backend drive 会把 quicz 本端 transport parameters 设置到 OpenSSL TLS object，调用 `SSL_do_handshake()` 产出第一段 TLS CRYPTO flight，把该 adapter 产出的 Initial CRYPTO flight 作为 protected Initial datagram 通过 loopback UDP 投递，并消费 quicz 编码后配置给 OpenSSL 的 pair-transcript server transport parameters，让真实 pair-transcript Handshake/1-RTT secrets 经 OpenSSL callback 边界进入连接层，随后把真实 pair-transcript Handshake CRYPTO 作为 protected Handshake datagram 通过 loopback UDP 投递后再喂回 adapter，并在 backend confirmation 前验证 OpenSSL recv/release callback 已消费入站 Handshake CRYPTO，最后用 adapter 安装的 client keys 和匹配 peer transcript secrets 驱动 loopback UDP 1-RTT STREAM echo，通过同一个 lifecycle owner 服务 Application PTO 并路由 protected probe，通过 OpenSSL-backed `handshake_confirmed` callback 报告 `backend_confirmed=true`，输出匹配的 `peer_tp_bytes` 与 `transcript_tp`、transcript keylog 证据和当前 wrapper keylog 边界，通过 lifecycle-owned backend-confirmed no-output Handshake drive 丢弃 client Handshake packet-number space 和 keys 并刷新聚合 recovery timer，通过 server connection probe 从 backend 拉取真实 pair-transcript 1-RTT secrets、记录 OpenSSL secret callbacks、确认 server connection、证明已应用 transport parameters 后的 peer stream-count limit enforcement，并丢弃 server Handshake packet-number-space keys；通过 paired loopback server backend 消费 loopback UDP 上的 client Handshake CRYPTO、拉取 peer transport parameters 与 Handshake/1-RTT secrets、确认并清理 Handshake keys，再通过同一个 socket/lifecycle loop owner 完成 protected close 投递和 route cleanup。 | 已存在 |
| `initial_keys` | 基于 client Initial DCID 的 RFC 9001 QUIC v1 和 RFC 9369 QUIC v2 Initial secret/key/IV/header-protection key 派生、RFC 9001 `quic ku` key-update 派生、protected Initial long-packet seal/open、configured v2 connection Initial packetization 与 AES header-protection masking。 | 已存在 |
| `endpoint_routing` | 当前内存态 endpoint DCID/IPv4 UDP 四元组 routing、long-header DCID peeking、unsupported-version RFC 8999 Version Negotiation response generation、client Initial Source CID route registration、supported-version unknown-DCID Initial accept classification、accepted Initial Original DCID/server Initial SCID route registration、short-header registered-CID matching、zero-length CID tuple routing、Retry Source CID route switching、调用方验证后的 preferred-address migration commit、sequence/retire-prior-to/connection-handle route retirement、stateless reset token reuse rejection、调用方验证后的 path update、active-migration-disabled rejection、route retirement、inactive CID 的 stateless reset token lookup、用调用方提供 unpredictable bytes 构造 reset datagram，以及 route/version-negotiation/reset/drop/accept receive action classification。 | 已存在 |
| `endpoint_recovery_timers` | Endpoint-owned recovery timer scheduling：endpoint lifecycle route ownership、跨 caller-owned connection handle 选择最早 aggregate timer、deadline 前 no-op refresh、PTO service/re-arm、ACK 驱动 disarm、loss-time service、最终 timer disarm、connection-handle route retirement、带 processed-count preservation 的 routed protected long-header receive timer refresh、client Initial ACK 后保留 anti-deadlock Handshake PTO、caller-keyed 与 installed-key Handshake/0-RTT protected long-header recovery timer service 和 PTO probe polling、基于 endpoint record 的 route-bound 与 non-route server Initial PTO output、protected long-header send timer refresh、routed caller-keyed Handshake CRYPTO-space 与 0-RTT long-packet receive timer refresh、caller-keyed Initial/Handshake CRYPTO-space 与 0-RTT long-packet send timer refresh、routed caller-keyed protected 1-RTT short-packet receive timer refresh、caller-keyed protected 1-RTT short-packet send timer refresh、installed-key protected 1-RTT recovery timer service 与 PTO probe polling、routed explicit key-phase/key-update short-packet receive timer refresh、caller-owned key-phase-state short-packet send timer refresh、routed installed-key Handshake/0-RTT long-packet receive timer refresh、installed-key Handshake/0-RTT long-packet send timer refresh，以及 installed-key protected 1-RTT short-packet send/receive timer refresh。 | 已存在 |
| `udp_endpoint_loopback` | Socket-backed loopback UDP endpoint routing：lifecycle-owned unsupported-version Initial 到 Version Negotiation response delivery、client-side VN selection、带 follow-up Original DCID 与 recovery-timer 证据的 protected follow-up Initial emission、lifecycle-owned accepted protected Initial processing、protected server Initial response emission 与 routed client-side processing、follow-up client 上的 server transport-parameter byte validation 和 malformed-byte `TRANSPORT_PARAMETER_ERROR` close classification、server-side follow-up Initial CRYPTO receive、client Initial Source CID response routing、accepted server Initial Source CID registration，以及 short-header registered-CID routing。 | 已存在 |
| `udp_zero_cid_loopback` | Socket-backed loopback UDP zero-length CID：lifecycle-owned short/long datagram 按 UDP tuple identity 路由、更新前拒绝未注册 tuple、按 path 退役 zero-CID route，以及把 route path 更新到新 tuple。 | 已存在 |
| `udp_preferred_address_loopback` | Socket-backed loopback UDP preferred-address：server preferred_address transport-parameter byte handoff、lifecycle-owned 调用方验证后的 preferred route commit、旧 route 退役、preferred CID 在 preferred server address 上路由、stray path 上 active-migration-disabled 拒绝，以及退役后的 reset-token lookup。 | 已存在 |
| `udp_replacement_cid_loopback` | Socket-backed loopback UDP replacement CID：lifecycle-owned NEW_CONNECTION_ID-style replacement route registration、retire_prior_to route retirement、inactive old-CID reset-token lookup、active replacement token suppression、invalid retire_prior_to rejection，以及 active-migration-disabled stray-path rejection。 | 已存在 |
| `udp_connection_ids_loopback` | Socket-backed loopback UDP connection ID：lifecycle-routed protected NEW_CONNECTION_ID delivery、lifecycle-owned issue/register endpoint route update、inactive old-CID reset-token lookup、active replacement CID route probing、lifecycle-routed protected RETIRE_CONNECTION_ID 经 active replacement CID 路由、lifecycle-routed ACK cleanup 和 server-side local CID retirement。 | 已存在 |
| `udp_protected_loopback` | Socket-backed loopback UDP lifecycle protected packet：lifecycle-owned caller-keyed protected client Initial route registration、认证 accepted protected Initial 后再注册 server route、anti-amplification budget accounting、protected server Initial response emission 与 routed client-side processing、routed caller-keyed 1-RTT PING processing 和 routed caller-keyed 1-RTT ACK processing。 | 已存在 |
| `udp_handshake_keys_loopback` | Socket-backed loopback UDP Handshake-key：lifecycle-routed installed-key Handshake CRYPTO 双向投递、已服务的 installed-key Handshake PTO probe routing 与重复 CRYPTO discard 证据，以及 routed Handshake ACK cleanup。 | 已存在 |
| `udp_crypto_stream_loopback` | Socket-backed loopback UDP CryptoBackend CRYPTO stream：mock `CryptoBackend` Handshake traffic-secret 安装、本端/对端 transport-parameter byte handoff、lifecycle-routed protected Handshake CRYPTO flight、backend receive/output 和 routed ACK cleanup。 | 已存在 |
| `udp_zero_rtt_loopback` | Socket-backed loopback UDP 0-RTT：lifecycle-routed installed-key 0-RTT STREAM delivery、explicit accept-before-process enforcement、rejection-driven peer key discard、已服务的 installed-key 0-RTT PTO probe routing 与重复 STREAM discard 证据、accepted early ACK 证据、routed 1-RTT ACK cleanup，以及 1-RTT 边界上的 client/server 0-RTT key discard 证据。 | 已存在 |
| `udp_one_rtt_loopback` | Socket-backed loopback UDP 1-RTT：建模 handshake confirmation 后 lifecycle-routed installed-key 1-RTT STREAM delivery、已服务的 installed-key 1-RTT PTO probe routing 与重复 STREAM discard 证据，以及 routed Application-space ACK cleanup。 | 已存在 |
| `udp_echo_loopback` | Socket-backed loopback UDP installed-key 1-RTT echo：lifecycle-routed client STREAM delivery、server bidirectional STREAM echo、request/echo payload equality、已服务的 server-side 1-RTT PTO probe routing 与重复 STREAM discard 证据、final ACK cleanup、client final-ACK timer-state 证据，以及 server bytes-in-flight/timer cleanup 证据。 | 已存在 |
| `udp_crypto_backend_loopback` | Socket-backed loopback UDP CryptoBackend：mock `CryptoBackend` 1-RTT traffic-secret handoff、modeled handshake confirmation、lifecycle-routed installed-key STREAM echo、已服务的 client/server installed-key 1-RTT PTO probe routing 与重复 STREAM discard 证据、client/server 发送侧 recovery-timer deadline 证据、final ACK cleanup、client final-ACK timer-state 证据，以及 server bytes-in-flight/timer cleanup 证据。 | 已存在 |
| `udp_handshake_done_loopback` | Socket-backed loopback UDP HANDSHAKE_DONE：lifecycle-routed installed-key HANDSHAKE_DONE confirmation、server/client Handshake key discard 证据、公开 handshake/connection-state 证据，以及 routed ACK pending/cleanup 证据。 | 已存在 |
| `udp_flow_control_loopback` | Socket-backed loopback UDP flow control：lifecycle-routed protected STREAM delivery 到 receive limit、lifecycle-routed protected STREAM_DATA_BLOCKED routing、lifecycle-routed 接收侧 MAX_DATA/MAX_STREAM_DATA credit refresh delivery、lifecycle-routed 带 FIN final-size 证据的 resumed STREAM data、caller-keyed resumed STREAM PTO probe routing 与重复 discard 证据，以及 lifecycle-routed final ACK cleanup。 | 已存在 |
| `udp_spin_bit_loopback` | Socket-backed loopback UDP spin bit：启用单路径 spin-bit signaling、lifecycle-routed protected short PING/ACK receive path、第一轮 false spin、带 `path_changed` 的迁移端口第二轮 true-spin PING、lifecycle-owned route update/reset、server ACK/client outgoing spin reset 证据和 final ACK cleanup。 | 已存在 |
| `udp_ecn_validation_loopback` | Socket-backed loopback UDP ECN validation：lifecycle-routed modeled ECT(0) protected short PING routing、lifecycle-routed protected ACK_ECN success、lifecycle-routed ACK_ECN CE 驱动的 NewReno recovery 响应、active UDP tuple 的 lifecycle-owned endpoint ECN state update，以及不声称真实 IP-header ECN marking 的 migrated-path ECN isolation。 | 已存在 |
| `udp_loss_recovery_loopback` | Socket-backed loopback UDP lifecycle loss recovery：lifecycle-routed protected short PING/ACK receive path、protected ACK 驱动的 packet-threshold loss，以及 lifecycle timer 驱动的 time-threshold cleanup 和最终 timer disarm。 | 已存在 |
| `udp_congestion_recovery_loopback` | Socket-backed loopback UDP lifecycle congestion recovery：lifecycle-routed protected short PING/ACK receive path、显式 NewReno recovery-period 重复 loss 抑制证据、persistent congestion 降到 minimum congestion window 的显式证据，以及建模 ACK_ECN CE 驱动的一次性 protected STREAM probe routing。 | 已存在 |
| `udp_pto_recovery_loopback` | Socket-backed loopback UDP lifecycle PTO recovery：lifecycle-routed protected long/short 和 installed-key 0-RTT receive path、lifecycle timer service 加 protected long Handshake PTO probe polling、installed-key 0-RTT RESET_STREAM PTO probe polling 和 protected short probe polling 驱动 ACK-loss PTO、protected long-header PING/ACK delivery、protected 0-RTT retransmission 与 1-RTT ACK cleanup、protected short PING fallback probe delivery、queued STREAM data 作为 protected PTO probe、in-flight STREAM/CRYPTO data 作为 protected PTO probe、重复 receive/CRYPTO range 丢弃、ACK cleanup 和最终 timer disarm。 | 已存在 |
| `udp_stream_retransmission_loopback` | Socket-backed loopback UDP lifecycle STREAM retransmission：lifecycle-routed sparse protected ACK receive 把 1-RTT STREAM packet 标记为 lost，sender 发出新的 protected STREAM retransmission packet，receiver 幂等丢弃重复 stream range，并由 final ACK 清空 bytes in flight。 | 已存在 |
| `udp_key_update_loopback` | Socket-backed loopback UDP key update：使用 installed 1-RTT traffic secret 的 lifecycle-owned route selection 与 protected receive processing、本端 key update 发起、可观测 key-update generation count、可观测 ACK-gate threshold、retained-generation old-key discard 证据、next key-phase PING routing、认证后的 peer key-phase advancement、ACK delivery、ACK-gate clearing、second-update packet delivery、已服务的 second-update PTO probe routing 与当前 key-phase 证据、server generation-2 advancement、带状态保持的 stale old-generation packet rejection 和第二次 ACK-gate clearing。 | 已存在 |
| `udp_path_validation_loopback` | Socket-backed loopback UDP path-validation：lifecycle-routed protected PATH_CHALLENGE 投递到新的对端端口、验证前 protected PING 以 `path_changed` 路由但不更新 route、lifecycle-routed PATH_RESPONSE 以 `path_changed` 路由、close-propagating validation-driven `EndpointConnectionLifecycle` 在 PATH_RESPONSE 消费 outstanding challenge 后提交 route path update，以及新路径上的 confirmed routing。 | 已存在 |
| `udp_retry_loopback` | Socket-backed loopback UDP lifecycle Retry/address-validation：lifecycle-owned server Retry delivery、Retry Source CID route switching、lifecycle-owned 地址绑定 token 校验和一次性消费、replay rejection、lifecycle-owned follow-up protected Initial acceptance/processing，以及通过 TLS extension bytes 执行 Retry CID transport-parameter validation。 | 已存在 |
| `udp_close_lifecycle_loopback` | Socket-backed loopback UDP close lifecycle：lifecycle-owned client/server route registration、lifecycle-routed protected CONNECTION_CLOSE delivery、认证后 frame 错误的 lifecycle-routed protected receive auto-close、close/drain deadline 证据、close/drain 到期后的 timeout-driven endpoint route cleanup、带剩余 route/reset-token count 的 connection-handle route retirement、保留的 inactive-CID stateless reset token lookup、reset emission 和 client token match。 | 已存在 |
| `udp_stateless_reset_loopback` | Socket-backed loopback UDP stateless reset：active CID route classification 和 reset-token suppression、unknown-CID drop classification、lifecycle-owned retired-CID route retirement、trigger datagram classification、server reset datagram 发出，以及 client token match。 | 已存在 |
| `udp_echo_client` / `udp_echo_server` | 真实 QUIC-over-UDP/TLS stream echo。 | 计划中 |
| `uni_stream` | 当前内存态单向 stream 发送/接收、方向校验、重复 STREAM 重传丢弃与 FIN completion 可观测。 | 已存在 |
| `stream_reset` | 当前本地 RESET_STREAM 发出、公开 stream 状态快照证据（含 reset-read 与 reset-acked 观测）、final-size 可观测、未发送 STREAM 丢弃行为、reset 后 MAX_STREAM_DATA 忽略，以及 reset 后 late STREAM 忽略。 | 已存在 |
| `stop_sending` | 当前本地 STOP_SENDING 发出、公开 stream 状态快照证据、对端 RESET_STREAM 响应、Data Recvd 抑制、对端发起 bidirectional stream 的 pre-STREAM STOP_SENDING、隐式低编号接收 stream 创建，以及 reset 后 ACK-loss STREAM 抑制。 | 已存在 |
| `flow_control` | 演示 connection、stream、stream-count、接收侧 MAX、MAX_STREAMS overflow 拒绝、可配置目标 receive window、完成 stream 后 MAX_STREAMS credit、peer-BLOCKED MAX 重发/增长、对端发起 bidirectional stream 的 pre-STREAM MAX_STREAM_DATA 与隐式低编号接收 stream 创建、final-size MAX_STREAM_DATA 抑制、stale STREAM_DATA_BLOCKED 抑制，以及调用方 key 的 protected short MAX/BLOCKED exchange 行为。 | 已存在 |
| `graceful_close` | 当前内存态、调用方 key protected long Initial/Handshake CONNECTION_CLOSE、调用方 key protected short CONNECTION_CLOSE/APPLICATION_CLOSE 收发、非法 ACK/ACK_ECN range close、非法 STREAMS_BLOCKED limit close、包含 flow-control、ACK/ACK_ECN 确认从未发送 packet、冲突 STREAM data、非法 stream-control frame、未匹配 PATH_RESPONSE、NEW_CONNECTION_ID limit/reuse、RETIRE_CONNECTION_ID unknown-CID 和 role-specific NEW_TOKEN/HANDSHAKE_DONE 的语义 frame 错误 auto-close、protected receive auto-close、lifecycle-routed protected receive auto-close、protected long/0-RTT close-state discard、peer close 诊断、默认/space/packet-type 非法 frame-payload auto-close、重发与 closing/draining 状态行为。 | 已存在 |
| `idle_timeout` | 当前 max_idle_timeout transport parameter 应用、活动 deadline 刷新、active-to-closed 过期和 endpoint route/timer 清理。 | 已存在 |
| `packet_spaces` | 当前 frame-payload Initial/Handshake/Application ACK/recovery 隔离、RFC 9001 Initial discard、会清理 ECN 状态的 Initial/Handshake discard cleanup、0-RTT packet-type filtering，以及使用调用方 key 的 protected 0-RTT STREAM/RESET_STREAM/STOP_SENDING 投递和 ACK-loss retransmission。 | 已存在 |
| `path_validation` | 当前 frame-payload PATH_CHALLENGE 超时重试、成功、重试耗尽、重复 pending PATH_RESPONSE 抑制、调用方 key 的 protected 1-RTT PATH_CHALLENGE/PATH_RESPONSE exchange（含 1200 字节 datagram 扩展和 anti-amplification fallback），以及 protected PATH_RESPONSE 验证后的 validation-driven `EndpointConnectionLifecycle` route path update。 | 已存在 |
| `connection_ids` | 当前带 stateless-reset-token uniqueness checks 的本端 NEW_CONNECTION_ID 签发、对端 RETIRE_CONNECTION_ID 处理、带 retire_prior_to route retirement 的 lifecycle-owned issue/register endpoint route bridge，以及调用方 key 的 protected 1-RTT NEW_CONNECTION_ID/RETIRE_CONNECTION_ID exchange。 | 已存在 |
| `stateless_reset` | 当前 constant-time stateless reset token 匹配、误判拒绝和 lifecycle-owned endpoint inactive-CID reset action construction。 | 已存在 |
| `ecn_validation` | 当前 frame-payload ECT 发送建模、ACK_ECN counter 校验、ACK_ECN CE 拥塞响应和 endpoint path-identity ECN state isolation。 | 已存在 |
| `loss_recovery` | 当前 frame-payload invalid ACK range rejection、largest-acknowledged RTT sampling、跨 packet number space bytes-in-flight 拥塞发送准入、packet-threshold loss、time-threshold loss、aggregate loss-time timer service、NewReno underutilized-cwnd suppression、slow-start/congestion-avoidance 字节计数与 batched-ACK 增长、recovery period、recovery-period ACK accounting without congestion growth、loss/CE-driven 新拥塞事件后一次性 STREAM recovery probe、minimum-window ssthresh clamp、不受 PTO backoff 放大的 persistent congestion、persistent-congestion min-RTT refresh、persistent-congestion recovery-period 清理/重新进入、非连续 persistent-congestion 抑制与 ACK-delay 处理。 | 已存在 |
| `pto_recovery` | 当前 frame-payload Initial/Handshake/Application PTO hook，包含 aggregate PTO timer service、handshake confirmation 前 Application PTO gating、client Initial ACK PTO-backoff reset suppression、client no-in-flight anti-deadlock PTO、anti-amplification-limited server PTO disarm/rearm，以及新 datagram 解除发送阻塞时的 expired-PTO service、跨 packet number space 的 connection-level RTT 估计共享与 PTO backoff、Initial/Handshake RTT ACK-delay suppression、Initial/Handshake max_ack_delay suppression、已 armed 的单个 PTO probe 绕过 congestion window、PING fallback probe、其他 in-flight packet number space 的 cross-space peer probe、queued STREAM data probe selection、in-flight STREAM retransmission probe selection、已 ACK 的 RESET_STREAM 重传抑制和 protected 1-RTT CRYPTO PTO probe selection。 | 已存在 |
| `address_validation` | 当前建模的 server anti-amplification 预算、显式 peer-address validation、lifecycle-owned protected HANDSHAKE_DONE/NEW_TOKEN emission/delivery timer 证据、server 侧 HANDSHAKE_DONE 触发的 Handshake discard、endpoint peer-address binding、`AddressValidationPolicy` NEW_TOKEN 签发/轮换/originating-version binding/secret-set 和 replay-filter 导出恢复/校验/replay 拒绝，以及 lifecycle-owned address-validation unblocking。 | 已存在 |
| `udp_address_validation_loopback` | Socket-backed loopback UDP address-validation：lifecycle-owned protected HANDSHAKE_DONE/NEW_TOKEN emission/delivery timer 证据、带显式 changed-path rejection 的 NEW_TOKEN path/version binding、secret rotation、replay snapshot restore rejection，以及 lifecycle-owned server address-validation block/unblock 证据。 | 已存在 |
| `retry_token` | 当前 v1/v2 Retry packet integrity-tag encode/verify/parse、server 侧 Retry datagram 签发、客户端侧 Retry datagram 处理、通过 TLS extension bytes 执行 Retry CID transport-parameter 校验/导出、endpoint peer-address binding、`AddressValidationPolicy` Retry token 签发/path 校验、lifecycle-owned 一次性 Retry token 消费与 address-validation unblocking。 | 已存在 |
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
zig build run-tls-backend-adapter
zig build run-tls-c-abi-adapter
zig build run-tls-openssl-probe
zig build run-tls-openssl-pair-transcript
zig build run-tls-openssl-backend-adapter
zig build run-graceful-close
zig build run-idle-timeout
zig build run-packet-spaces
zig build run-ecn-validation
zig build run-loss-recovery
zig build run-pto-recovery
zig build run-endpoint-recovery-timers
zig build run-path-validation
zig build run-address-validation
zig build run-udp-address-validation-loopback
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
zig build run-udp-handshake-keys-loopback
zig build run-udp-crypto-stream-loopback
zig build run-udp-zero-rtt-loopback
zig build run-udp-one-rtt-loopback
zig build run-udp-echo-loopback
zig build run-udp-crypto-backend-loopback
zig build run-udp-handshake-done-loopback
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
