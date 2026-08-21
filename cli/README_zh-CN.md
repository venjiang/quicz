# quicz CLI

`quicz` 是独立于库的日常 QUIC / HTTP/3 开发工具包。它把 quicz 当普通包依赖引用，
库本身不内置该 CLI。

[English](README.md)

## 构建

```bash
cd cli
zig build                  # 产出 cli/zig-out/bin/quicz
zig build run -- --help
zig build test             # CLI 单元测试
```

## 安装

在仓库根目录构建 Release 二进制并安装到 PATH：

```bash
make install-local                  # 推荐：安装到 $HOME/.local/bin
make install PREFIX="$HOME/.local"  # 等价，显式指定前缀
make install                        # 安装到 /usr/local/bin/quicz（可能需 sudo）
```

`make install-local`（或 `make install PREFIX="$HOME/.local"`）使用
`-Doptimize=ReleaseFast` 构建，并把独立二进制安装到 `$HOME/.local/bin/quicz`。
macOS 上 `/usr/local/bin` 通常当前用户不可写，建议用该目标，并在 shell 配置里
加入 `export PATH="$HOME/.local/bin:$PATH"`。卸载用
`make uninstall PREFIX="$HOME/.local"`。

## 子命令

```bash
# H3 请求客户端：发 GET/POST，输出状态、响应体和连接指标
quicz h3 https://127.0.0.1:4433/hello.txt -k
quicz h3 https://host:4433/api -k -X POST -H 'content-type: application/json' --data '{"ok":true}' --timeout-ms 15000
quicz h3 https://host/api -d 'a=1&b=2'             # -d 隐含 POST + 表单 content-type
quicz h3 https://host/api -A 'my-agent/1.0'        # 自定义 User-Agent（默认 quicz/0.1.0）
quicz h3 https://host/api -u 'user:pass'           # HTTP Basic 认证
quicz h3 https://host/api -e 'https://ref.example/' # Referer 头
quicz h3 https://host/api -b 'sid=abc123'          # Cookie 头
quicz h3 https://host/api -T ./file.bin            # PUT 上传（octet-stream）
quicz h3 https://host/api -G -d 'a=1&b=2'          # GET，data 拼到 URL query
quicz h3 https://host/api --max-filesize 100000    # 响应体超限则失败
quicz h3 https://host/api --resolve host:443:127.0.0.1   # 强制 host 指向指定 IPv4
quicz h3 https://host/api -v                      # verbose：DNS/连接/重定向追踪
quicz h3 https://host/api --max-time 30            # 整个请求超时（秒）
quicz h3 https://host/api --connect-timeout 5      # 握手超时（秒）
quicz h3 https://host/api -o /dev/null -w 'code=%{http_code} time=%{time_total_ms}ms\n'
quicz h3 https://host/api -i -L -s -f -o resp.html # 响应头、重定向、静默、4xx/5xx 失败、保存正文
quicz h3 https://host/api -I                          # HEAD 请求，只要响应头
quicz h3 https://host/api -X POST --data @body.json   # 从文件读取请求体上传
quicz h3 https://host/api -D headers.txt              # 把响应头保存到文件
quicz h3 https://host/api -o -                        # 显式把正文写到 stdout

# HTTP/3/QUIC 健康检查：pass/fail + 失败阶段（见下方）
quicz probe https://example.com --json
quicz probe https://127.0.0.1:4433/ -k --resolve example.com:443:127.0.0.1

# Prometheus exporter：在 /metrics 暴露实时 probe 结果
quicz exporter --target https://127.0.0.1:4433/ -k --bind 127.0.0.1 --port 9633
curl -s http://127.0.0.1:9633/metrics

# 静态文件服务：TCP HTTPS（浏览器）+ HTTP/3 + /metrics + /echo
quicz serve --dir ./dist --port 4433
quicz serve --dir ./dist --port 4433 --cert cert.pem --key key.pem
quicz serve --dir ./dist --index index.htm         # 自定义索引文件（默认 index.html）
curl -k https://127.0.0.1:4433/                    # 浏览器打开这个地址（自签证书需信任）
quicz h3 https://127.0.0.1:4433/echo -k -d 'ping'    # HTTP/3 客户端：/echo 回显 method/path/authority/body

# 原始 QUIC 流 echo：验证 quicz 与外部对端的互通
quicz echo --server --port 4433
quicz echo --client 127.0.0.1 4433 --data "ping"

# 基准：握手延迟 + 单流吞吐（对端是 quicz echo --server）
quicz bench 127.0.0.1 4433 --size 1048576
```

## Probe（HTTP/3 健康检查）

`quicz probe <url>` 输出一次 HTTP/3/QUIC 健康检查，并把失败归因到单一阶段：
URL、DNS、UDP、QUIC/TLS 握手或 HTTP/3 请求。无 scheme 的目标自动按 `https://`
处理；显式 `http://`、`ftp://` 等非 HTTPS scheme 报用法错误并退出 2。

检查顺序：

1. 解析 HTTPS URL。
2. 解析 IPv4 地址。
3. 执行 QUIC 1-RTT + TLS 1.3 + ALPN `h3`（默认系统 CA，`-k` 跳过，`--ca` 指定 PEM）。
4. 对原 URL path 发起 HTTP/3 GET。
5. 额外尽力发起 TCP+TLS HTTP/1.1 GET，报告状态码、`Alt-Svc` 是否包含 `h3`、
   以及 HTTP/3 失败时是否出现 fallback；`--no-alt-svc` 可跳过该附加检查。

输出支持 text / `--json` / `--prometheus` / `--nagios`。通过退出 0，探测失败
退出 1，用法错误退出 2（`--nagios` 探测失败按 CRITICAL 退出 2）。JSON 会转义
`Alt-Svc` 中的引号等字符；Prometheus 输出包含
`quic_alt_svc_h3`、`quic_fallback_reachable` 和 `quic_fallback_detected`。

```bash
./zig-out/bin/quicz probe https://cloudflare-quic.com/ --json
./zig-out/bin/quicz probe https://127.0.0.1:4433/ -k
./zig-out/bin/quicz probe https://example.com --prometheus
```

边界：QUIC 客户端只协商 `h3`，因此无法观察 `alpn_not_h3`；fallback 请求使用
Zig 标准 TLS client 且不发送 ALPN，所以报告的是 HTTP/1.1 而不是协商 HTTP/2。
`-k` 时标准 TLS client 也会省略 SNI；证书校验开启时始终发送 URL hostname。

## Exporter（Prometheus 指标端点）

`quicz exporter` 运行一个小型 HTTP 服务，对配置的一个或多个 HTTPS 目标重复执行
`quicz probe`，并在 `http://<bind>:<port>/metrics` 暴露 Prometheus 文本格式指标。
它是 probe 产品计划的常驻形态，可直接接入 Prometheus 抓取。

```bash
quicz exporter --target https://example.com --target https://cloudflare-quic.com/ --bind 127.0.0.1 --port 9633
curl -s http://127.0.0.1:9633/metrics
```

probe 选项与 `quicz probe` 共用（`-k`、`--ca`、`--resolve`、
`--connect-timeout`、`--max-time`、`-A`、`--no-alt-svc`、`-v`）。每次抓取会对
每个 target 串行执行一次实时探测，指标反映抓取时刻的状态。指标名与
`quicz probe --prometheus` 一致；多 target 时 `# HELP`/`# TYPE` 元数据只输出一次。
只服务 `/metrics` 的 `GET`/`HEAD`，其它路径与方法返回 404。

## 线上 H3 验证

`h3` 子命令已针对真实线上 HTTP/3 服务器做端到端验证（QUIC 握手 + HTTP/3 + QPACK），
随后再跑一次本地 `serve` 回环：

```bash
../scripts/cli_h3_live_test.sh                  # 线上服务器 + 本地回环
../scripts/cli_h3_live_test.sh --skip-live      # 只跑本地回环
```

线上目标为 `https://cloudflare-quic.com/` 和 `https://www.fastly.com/`；
每次必须返回 `HTTP/3 200` 且正文非空。直接命令效果相同：

```bash
./zig-out/bin/quicz h3 https://cloudflare-quic.com/ --timeout-ms 25000
# HTTP/3 200
# <完整响应正文>
```

Cloudflare 边缘会在请求/响应流的首个 HEADERS 帧前插入 GREASE 帧（RFC 9114 §7.2.8）。
runtime 解析器在扫描 HEADERS 时会跳过保留帧类型与未知帧类型（RFC 9114 §9）。
回归测试覆盖双向：

- `src/h3/client.zig` - "H3Client skips GREASE frames before response HEADERS"
- `src/h3/server.zig` - "H3Server skips GREASE frames before request HEADERS"

## 证书校验

`h3` 默认使用系统 CA 包校验服务器证书。用 `-k` 跳过校验，或用
`--ca /绝对路径.pem` 信任自定义 CA：

```bash
./zig-out/bin/quicz h3 https://cloudflare-quic.com/          # 默认用系统 CA 校验
./zig-out/bin/quicz h3 https://host/api -k                   # 跳过校验
./zig-out/bin/quicz h3 https://host/api --ca /abs/ca.pem     # 信任指定 CA
```

系统 CA 从 `/etc/ssl/cert.pem`（macOS、Debian/Ubuntu）、
`/etc/ssl/certs/ca-certificates.crt` 或 `/etc/pki/tls/certs/ca-bundle.crt` 加载。
找不到系统 CA 时禁用校验并打印警告。

## 请求选项

- `-d` / `--data` 发送请求体并隐含 `POST` 与 `content-type: application/x-www-form-urlencoded`；
  `--data @file` 从文件读取请求体。
- `-A` / `--user-agent` 覆盖默认 `User-Agent: quicz/0.1.0`；会替换任何
  `-H user-agent:` 头。
- `-u` / `--user user:pass` 添加 HTTP Basic 认证；`-e` / `--referer` 与
  `-b` / `--cookie` 设置 `Referer` 与 `Cookie` 头。
- `-T` / `--upload-file FILE` 以 PUT 上传文件内容作为请求体，默认
  `content-type: application/octet-stream`（可覆盖）。
- `-G` / `--get` 把 `--data` 拼到 URL query 且保持 GET；
  `--max-filesize BYTES` 在响应体超限时使请求失败。
- `-w` / `--write-out FORMAT` 输出 curl 风格变量到 stdout，支持
  `%{http_code}` `%{url_effective}` `%{time_total_ms}` `%{time_connect_ms}`
  `%{size_download}` `%{num_redirects}`；支持 `\n`/`\r`/`\t` 转义。
- `--resolve host:port:addr` 为指定 host/port 覆盖 DNS（仅 IPv4），适合拿真实
  域名测试本地服务。
- `--connect-timeout` / `--connect-timeout-ms` 只限制 QUIC 握手；
  `--max-time` / `--timeout-ms` 限制整个请求（默认 10s）。
- `-v` / `--verbose` 在 stderr 输出 DNS 解析、连接、重定向和请求行。
- `-o -` 把响应体写到 stdout；其他 `-o` 路径写入文件。

`serve` 在子目录没有索引文件时会生成目录列表，`--index FILE` 可指定目录请求
使用的索引文件名。

## 边界

- H3 客户端和服务端当前只支持 IPv4 / `localhost`；`--ca` 需要绝对路径 PEM。
- `serve` 监听 TCP（HTTPS over TLS，浏览器可直接访问）与 UDP（HTTP/3）。
  浏览器打开 `https://127.0.0.1:PORT/`（自签证书需点继续/信任）；HTTP 响应带
  `Alt-Svc: h3=":PORT"; ma=86400`，浏览器信任该源证书后会升级到 HTTP/3。
  `quicz h3 https://127.0.0.1:PORT/ -k`（或 `--ca`）直接测 HTTP/3 端点。
- `bench` 以 insecure 方式连接 `echo --server`，测的是传输路径而非证书链路。
- 客户端子命令默认 10s 超时（`--timeout-ms`），连不上或服务端卡住会直接失败，不挂死。
