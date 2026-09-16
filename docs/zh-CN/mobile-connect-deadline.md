# 移动 C ABI 的成功截止与关闭唤醒

## 已复现的问题

- iOS真机`quicz_mobile_client_connect_timeout(..., 3000)`成功仍用3001ms。
- 固定iOS模拟器本机回环中，1000ms截止下首次成功1007ms；同一已连接client再次调用仍1009ms。后者不执行新握手，不能归因网络RTT。
- 线程采样另确认`quicz_mobile_client_destroy`等待接收group，UDP读线程仍阻塞`recvmsg`。普通Mac示例不复现，嵌入宿主线程的信号环境需纳入测试。

## 目标、边界与选择

保留ABI v1、函数签名/返回码、TLS验证、打洞协议和每client独立socket；不修改宿主线程信号掩码，不缩短调用者指定的截止时间。只消除成功路径等待落败计时器、以及关闭时无限接收无法退出的依赖。

- 连接截止直接等待Client持有的握手完成Event；成功立即返回，不创建需要取消的sleep或连接future。绝对期限到期直接返回，后台驱动仍由原Client持有，没有引用调用栈的残留任务；虚假唤醒不延长原期限。第一次实现使用连接future，黑洞反例证明其取消join同样可能阻塞，故不保留这层竞速。
- Client停止时先设置stopping并唤醒drive，再向自身UDP socket发送一个本地唤醒报文，使阻塞接收能退出；只在任务已启动时执行。保留socket到所有任务退出之后才释放，不依赖关闭并复用FD，不向远端发送额外保活。
- 备选为改变宿主信号掩码或降低截止：不采用，前者影响嵌入宿主，后者改变网络容忍度而非修复等待语义。

## 不变量与验证

| 场景 | 结果 |
| --- | --- |
| 首次连接成功 | 保留TLS验证，成功后立即返回 |
| 同一client已连接 | 无新握手、不等截止 |
| 黑洞/握手失败 | 原有限截止、错误码和资源回收 |
| 调用线程屏蔽SIGIO | 不更改其掩码，成功和清理仍可完成 |
| Client关闭 | 接收worker退出后释放内存/socket |
| 多client | 唤醒仅发送给自己的socket |

先运行公共C ABI本机回环红灯；修复后同例绿灯。再跑原C ABI、同socket打洞及全量测试，并在Mons固定iOS模拟器复跑同一回归；真机解锁后补同一LAN分段基准。性能数据不能替代TLS/关闭正确性断言。

## 当前证据

- `run-mobile-deadline-regression`使用仅调用线程屏蔽SIGIO的本机回环。旧实现已连接调用仍耗1010ms，且清理超过8秒上限，红灯记录`/private/tmp/quicz-mobile-deadline-red.log`。
- 最终实现同例在224ms内完成全部场景：1000/3000ms截止的已连接调用均为0ms量级，真实100ms黑洞仍返回原超时码并及时清理，调用线程信号掩码不变。
- 完整`zig build test`为1929/1929通过；公共C ABI、P2P QUIC及shared-socket互操作全部通过，证据`/private/tmp/quicz-mobile-deadline-final-regression.log`。ABI/header、证书验证及协议数据不变。
- 相同iPhone 14 Pro模拟器C接口回归`/private/tmp/mons-terminal-regression.oGgWWL`通过：首次连接31.8/8.5ms，已连接重复调用0.002/0.001ms；1秒及3秒截止均不再成为成功路径最低等待，销毁正常完成。
