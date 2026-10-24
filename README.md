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
config/      JSON5 子集解析 + 配置结构
hostmatch/   主机模式匹配（精确 / 通配）
rules/       规则编译与匹配（路径正则、exclusions、确定性排序）
certcache/   CA 加载/生成，按需签发叶子证书并缓存
dnsres/      预设 IP、按域名的 DNS 服务器、系统解析回退
proxy/       CONNECT 终结、明文 HTTP、上游拨号、规则动作
cmd/ds-core/ 独立运行的 CLI
```

## 现状

已实现并测试：

- CONNECT 隧道 + TLS 终结，证书按 ClientHello 的 SNI 现场签发（IP 目标回退到 CONNECT 主机，带 IP SAN）
- 路径级规则：`redirect`（返回 302 到镜像）、`proxy`（换上游主机）、`sni`（改写上游 SNI，之后按真实主机名校验证书链）
- 明文 HTTP 代理（绝对形式请求）
- DNS：`preSetIpList` 优先、`dns.mapping` 选择解析器、系统解析兜底
- CLI：`-config`、`-listen`、`-ca-dir`、`-v`

尚未实现（按优先级）：

- 响应体注入（`script` / `tampermonkeyScript`）——需要 HTML 改写
- HTTP/2（当前 `NextProtos` 只提供 `http/1.1`）
- WebSocket 与长连接升级
- 流量/速度统计（桌面端 GUI 依赖）
- 配置热更新、per-host 排除（`excludeIpList` 已解析未使用）
- gomobile 封装与 Android 集成

## 构建与运行

```bash
go build ./...
go test ./...

go run ./cmd/ds-core -config remote_config.json5 -listen 127.0.0.1:31181 -ca-dir ./ca
```

把 `ca/ca.crt` 装进系统/浏览器信任库后，HTTPS 才能通过；不装的话隧道仍可用，但客户端会拒绝我们签发的证书（这是有意的行为，测试里也有对应用例）。

## 验证记录（2026-10-24）

用线上分发的 `remote_config.json5` 跑 CLI 冒烟，客户端只信任 `ca/ca.crt`：

```
200 https://www.baidu.com/                                   # 透传，证书链按内核 CA 验证通过
302 https://github.com/docmirror/dev-sidecar/releases/download/...
    Location: https://ghp.ci/https://github.com/docmirror/...  # 真实路径规则命中
```

`go test ./...` 覆盖：JSON5 解析、规则匹配（含通配与 `exclusions`）、证书签发与校验（域名/IP）、端到端 MITM 透传、302 重定向、明文 HTTP、以及"客户端不信任内核 CA 时必须失败"的负向用例。
