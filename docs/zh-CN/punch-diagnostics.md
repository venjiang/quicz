# 单次打洞诊断计数

`PunchAttempt.diagnostics`为固定大小、饱和递增的观测快照，不参与路由、重试或认证决策。每次`init`从零开始，由同一attempt执行线程维护，调用方只能在驱动结束或已同步停止后读取，不能跨线程并发读取。

- `probe_sends`、`acknowledgement_sends`：socket发送调用成功的次数，不代表对端收到。
- `datagrams_received`、`source_rejected`：驱动收到的可放入缓冲区的数据报及其中来源不符的数量。
- `oversized_received`：接收接口报告超长的数据报，独立于`datagrams_received`。
- `packets_checked`：进入状态机报文检查的数量；直接调用`receive`也计数。
- `malformed_rejected`、`authentication_rejected`、`attempt_rejected`、`nonce_rejected`：报文格式、MAC、attempt或nonce校验拒绝。

单向进展继续使用已有`peer_probe_received`与`local_probe_acknowledged`，只有两者都满足才validated。静默、错误来源和校验拒绝可能最终都返回`PunchFailed`，调用方应同时观察计数与原始I/O/取消错误，不推断具体NAT类型。

计数不保留地址、端口、报文、密钥、nonce或身份。wire、C ABI、截止时间、来源校验和socket所有权不变；失败报文仍按原规则拒绝，不增加接收线程或网络探测。

验证：`zig test src/connectivity/punch_attempt.zig`覆盖格式/MAC/attempt/nonce拒绝和有效双向证明；`zig test src/connectivity/punch_driver.zig -lc`用本地UDP区分静默与错误来源，并验证成功、ACK重传与取消；`zig build test`覆盖完整库和移动ABI回归。
