# IPv4认证peer候选学习（独立、未接入产品）

目标：预先交换的IPv4端点与实际来源不同、但认证probe能够到达时，在同一UDP socket上验证实际peer。
不解决双方完全零收包；不扫描端口、不调用STUN、不修改旧严格driver、wire、C ABI、QUIC或持久状态。
参考[RFC 8445 §7.3.1.3/4](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.3.1.3)的peer-reflexive候选与triggered check思路，不宣称实现完整ICE协议。

新增独立`peer_punch.runUntilValidated`返回通过验证的实际endpoint，并更新调用者的PunchAttempt为赢家；
调用者必须用返回endpoint及赢家nonce创建PunchResponder和后续QUIC通道。现有严格入口保持原行为。
输入只允许新建IPv4 attempt；socket借用且独占接收，取消及I/O错误原样传播。

| 收包/状态 | 行为 |
|---|---|
| 原候选 | 原有PunchAttempt处理，保留其重试与证明状态 |
| 未知来源，MAC/attempt/nonce非法或仅ACK | 拒绝，不创建候选，不回复 |
| 首个未知来源的有效probe | 至多增加一个候选；独立随机nonce、独立双向证明，立即回ACK并触发新probe |
| 新来源的原候选ACK重放 | 新nonce不匹配，不完成验证 |
| 第三个来源 | 拒绝；不覆盖既有候选或延长时间 |
| 任一候选双向证明完整 | 返回该endpoint，只采用该候选的证明状态 |
| 原始绝对截止到达 | PunchFailed，不延长等待；上层照常保留Relay |

最多两个候选；各自最多原配置的5次probe，总计最多10次。额外发送只针对已经通过本attempt认证的probe来源，
不改变旧API的5次预算。绝对时间预算由原配置完整重试序列确定（默认2500ms），学习不会续期。
ACK不超过收到的已认证probe数量，报文仍为60字节；新nonce不能与原nonce及收到的peer nonce相同。
所有来源的probe均须拒绝任何本地候选nonce，不仅拒绝当前候选自身nonce；否则本机两个检查之间的反射可能
生成可被错误组合的ACK。该规则不影响来自peer的正常ACK，ACK仍只能匹配其来源候选的新挑战。
累计诊断沿用既有字段，不输出地址/端口/密钥/nonce。成功时返回赢家的nonce和双向证明，不拼接不同来源证据。
计数累计两个检查；失败时证明标志只保留原候选的状态，不能将两个候选各一半的证明合成为成功。

验收：真实loopback UDP下原候选成功、来源变化成功、静默失败；错误MAC/attempt、反射、未知ACK不得学习；
跨来源ACK和旧nonce重放不得组合为成功；原严格测试及完整库回归通过。默认不接入Mons；后续Host/移动接口接入
需独立验证socket交接、实际endpoint传递、取消及原会话隔离。真实蜂窝P2P另行验收，不以本地通过代替。

## 验证记录

首次以原严格driver实现新入口，同一真实UDP用例在来源变化时因`PunchFailed`红灯；独立学习实现后该用例通过。
专项入口为`zig build test-peer-punch`，覆盖原候选、来源变化、未知ACK、错误MAC/attempt、反射、截断报文、
跨来源ACK、旧挑战重放、晚到候选绝对截止、取消、原候选继续成功及非法目标发送前拒绝。
`zig build test --summary all`为1940/1940：库1931、移动C接口8、runtime keepalive 1，均通过。
本分支未更改旧driver、wire、移动ABI或QUIC runtime，也未启用任何公网探针。

多候选反射自审用例先复现`expected 3, found 1`：只拒绝当前候选nonce不能拒绝其它本地候选的反射。
修复为所有已认证probe均先比较全部本地nonce；同例随后同时验证3次nonce拒绝、仅1次合法ACK和无伪造peer证明。
取消后借用socket仍能收发，所有权不转移给此driver。接入方必须保留这些安全回归，不以返回endpoint替代QUIC及SSH身份验证。

最终补上取消后socket收发断言后，全局Zig缓存曾缺失`libcompiler_rt.a`，该次库测试未执行；未删除缓存，改用独立
`ZIG_GLOBAL_CACHE_DIR`复跑，全量仍为1940/1940。此环境失败不计为测试通过，也不修改产品代码绕过验证。
最终状态的`test-peer-punch`连续10轮通过，每轮13项（含模块导入测试），没有公网流量或服务部署。
