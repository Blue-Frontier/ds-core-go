# ds-core-go

dev-sidecar 内核的 Go 实现：本地 MITM 代理 + 拦截规则引擎。

桌面端（[ds-core](https://github.com/Blue-Frontier/ds-core)，Node/Electron）与手机端（[dev-sidecar-android](https://github.com/Blue-Frontier/dev-sidecar-android)）将来共用这一份内核，统一由 Go 提供代理能力，通过 gomobile 打包成 AAR 给 Kotlin 的 `VpnService` 调用。

## 为什么是 Go

| 需求 | Go 标准库是否覆盖 |
|---|---|
| 按域名现场签发证书（MITM 必需） | 覆盖：`crypto/x509` + `crypto/tls` |
| TLS 终结与上游重连 | 覆盖：`crypto/tls` |
| 目标语言之外的第二套工具链 | 不需要：静态二进制，交叉编译到 `android/arm64` 一条命令 |
| 第三方依赖 | 零；`go.mod` 无 require |

Rust 也能做（`rcgen`、`rustls`），但要额外引入 cargo-ndk 与 JNI 层；`benchmark` 上的体积/性能优势对一个代理应用不是瓶颈。

## 与 JS 内核的关系

配置契约完全一致：直接读 dev-sidecar 线上分发的 `remote_config.json5`（JSON5 子集：`//`、`/* */`、单引号、尾逗号），规则语义一致（主机模式 + 路径正则，`redirect`/`sni`/`proxy` 三类动作）。JS 内核继续承担桌面端，直到这里达到功能对等。

## 目录

```
config/      JSON5 子集解析 + 配置结构（providers / mapping / preSetIpList）
hostmatch/   主机模式匹配（精确 / 通配）
rules/       规则编译与匹配（路径正则、exclusions、确定性排序）
certcache/   CA 加载/生成，按需签发叶子证书并缓存
dnsres/      DNS子系统：预设IP、按域名的DNS提供方（DoH/DoT/TCP/UDP）、
             DNS连接自身的SNI改写、ForSNI、IP优选与失败降位
proxy/       CONNECT 终结、明文 HTTP、上游拨号、规则动作
cmd/ds-core/ 独立运行的 CLI
```

## 现状

已实现并测试：

- CONNECT 隧道 + TLS 终结，证书按 ClientHello 的 SNI 现场签发（IP 目标回退到 CONNECT 主机，带 IP SAN）
- 路径级规则：`redirect`（返回 302 到镜像）、`proxy`（换上游主机）、`sni`（改写上游 SNI，之后按真实主机名校验证书链）
- 明文 HTTP 代理（绝对形式请求）
- DNS（对齐 JS 内核 `mitmproxy/src/lib/dns`）：
  - `preSetIpList` 最优先（数组与 `{ip: true}` 对象两种写法，`null` 删除条目占位）
  - `server.dns.providers`：`https://`/`http://`（DoH, RFC 8484 wire+JSON 兜底）、
    `tls://`/`dot://`（DoT, RFC 7858）、`tcp://`、纯 IP（UDP）四类传输
  - **DNS 连接自身的 SNI 改写**：provider 配 `sni`（或 `servername`）时，到加密 DNS 的
    TLS ClientHello 带伪 SNI、跳过证书校验（与桌面内核 `rejectUnauthorized:false` 一致）；
    `forSNI`/`forSni` 标记的提供方是「有 sni 规则但无 DNS 映射」主机的默认解析器
    （无标记时回退到 PreSet，与 `dnsMap.ForSNI ||= PreSet` 一致）
  - `dns.mapping` 支持字符串与 `{dns, family}` 对象两种写法；旧配置直接写解析器名
    （`quad9` 等）时按桌面默认地址回填 UDP 提供方
  - 每提供方独立缓存 + IP 优选：拨号失败的上游 IP 降位到候选列表尾部（JS 内核
    DynamicChoice 的重排版，配合本内核的「每个请求逐个拨号」模型）
  - 主提供方解析为空时依次尝试其余提供方，再回退系统 DNS（`getFallbackDnsList` 语义）
- CLI：`-config`、`-listen`、`-ca-dir`、`-v`
- 响应体注入（对齐 JS 的 `InsertScriptMiddleware` + `script.js`）：
  - `script` 支持字符串与数组；`tampermonkeyScript` 先于其它脚本插入
  - 绝对 URL 在启动时登记进脚本站，注入标签指向内核自己的 `/____ds_script____/<key>`，
    脚本按需下载并缓存，因此始终与页面同源
  - `</head>`（其次 `</body>`）前切拼；`Content-Security-Policy` 的 `script-src`
    补 `'self'`，已有 `nonce-` 时透传给注入标签
  - 只对 `text/html` 生效；有脚本规则的请求把上游 `Accept-Encoding` 收窄为
    `gzip, deflate`，解压后重新 gzip，避免标准库不支持的 `br`/`zstd`
  - github.com 特判：`turbo-frame: repo-content-turbo-frame` 的响应不注入，
    并追加 `github.githubassets.com/assets/fakefile.js` 纠正其异步 loader 的根路径
- `whiteList` / `proxy.excludeIpList`：命中的主机在 CONNECT 阶段直接做字节隧道，
  不终结 TLS（客户端看到的是源站证书）
- WebSocket / 长连接升级：`Connection: Upgrade` 请求透传到上游，101 响应原样回写后双向管道
- 流量统计：请求、响应、注入、隧道、卡顿、字节数以及 per-host 计数，
  通过移动端 `KernelStats(handle)` 以 JSON 导出
- 本地端点（不走上游）：`/____ds_script____/<key>` 返回注入脚本，
  `/__ds_stats__` 返回计数器 JSON
- `verifyHost`：`sni` 故意换成另一个真实域名时，按该名字校验证书链
- `server.compatible.request["host:port"].rejectUnauthorized = false`：按目标跳过上游校验

尚未实现（按优先级）：

- HTTP/2（`NextProtos` 只提供 `http/1.1`；要支持需要在 MITM 之后按流处理请求，
  等于第二套代理实现，且无法离线验证）
- ECH / NAT64 / SVCB/HTTPS(65)（`server.dns.ech`、`nat64` 已解析占位）
- 配置热更新
- `speedTest`（已解析但未执行；等价能力由拨号失败降位提供）
- `sni: ""` 显式禁用 SNI（当前空串等同于未配置）

## 构建与运行

```bash
go build ./...
go test ./...

go run ./cmd/ds-core -config remote_config.json5 -listen 127.0.0.1:31191 -ca-dir ./ca
```

把 `ca/ca.crt` 装进系统/浏览器信任库后，HTTPS 才能通过；不装的话隧道仍可用，但客户端会拒绝我们签发的证书（这是有意的行为，测试里也有对应用例）。

## 验证记录（2026-10-24）

用线上分发的 `remote_config.json5` 跑 CLI 冒烟，客户端只信任 `ca/ca.crt`：

```
200 https://www.baidu.com/                                   # 透传，证书链按内核 CA 验证通过
302 https://github.com/docmirror/dev-sidecar/releases/download/...
    Location: https://ghp.ci/https://github.com/docmirror/...  # 真实路径规则命中
```

`go test ./...` 覆盖：JSON5 解析（含 providers / 对象形态 mapping 与 preSetIpList）、规则匹配
（含通配与 `exclusions`）、证书签发与校验（域名/IP）、
DNS 报文编解码（A/AAAA、压缩指针）、DoH（wire + JSON）、DoT（含 SNI 改写与正常校验）、
UDP/TCP 传输、预设 IP / 映射 / ForSNI 选择、IP 失败降位优选、
端到端 MITM 透传、302 重定向、明文 HTTP、ForSNI 代理链路、
以及"客户端不信任内核 CA 时必须失败"的负向用例。
对外网依赖的冒烟（本机实测）：阿里 DoH / DoT / UDP 三传输经代理建连均 200，
`sni` 改写访问 DoT/DoH 端点生效。
