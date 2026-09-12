# browserfp

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

浏览器的**网络指纹**：构造、识别，以及**证明它是对的**。

一个 C 库（带 **Lua / Go / Node.js·Bun** 绑定），复刻真实浏览器在链路上的样子 ——
TLS 1.3 的 ClientHello 与 HTTP/2 的开场帧。给一条 User-Agent，输出那个浏览器会
发的字节。

Node.js 绑定还多带一件东西：**原生 TLS 1.2 / 1.3 客户端** + HTTP/1.1 + HTTP/2，
以及 `fetch()` / `axios()` 适配。因为 Node 内置 `tls` 模块**不允许注入自定义
ClientHello**（业内也没有 `curl_cffi` 那样成熟的第三方替代），我们干脆把 TLS 与
HTTP 层原生写了一遍，一进程搞定，无需 sidecar。

重点在第三件事。指纹这类工作最容易出的问题是「看起来对了」：JA4 一致、测试全绿，
实际发出去的字节和真浏览器差着关键一处。所以这里每个结论都要求一个**能红的判据**。

English: [README.md](README.md)

## ❤️ 赞助商

> [想出现在这里？](mailto:sale@fizzgate.com)

<table>
<tr>
<td width="180"><a href="https://dash.augmunt.com/#/login"><img src="https://www.augmunt.com/logo.png" alt="Augmunt" width="150"></a></td>
<td>Augmunt 是一家稳定、高效的 Agentic LLM 网关平台，覆盖主流代码智能体及国际领先模型生态，为开发者与企业提供统一接入能力。支持企业采购流程、对公付款，服务规范可靠。</td>
</tr>
</table>

## 支持范围

| 浏览器 | 版本 |
|---|---|
| Chrome（桌面 & 移动） | **70 – 153** |
| Edge | **79 – 153** |
| Firefox（桌面 & 移动） | **78 – 153** |
| Opera（桌面 & 移动） | **70 – 153** |
| Safari（桌面 & 移动） | **15 – 27** |

合计 **570 个 (品牌, 版本) 组合**。它们去重后只剩很少的字节形态，因为相邻版本的
ClientHello 通常逐字节相同：**82 种唯一指纹**（从 321 个目标名按 13 个确定性字段去重）。

这张表是**问库本身**要出来的（枚举哪些组合能通过 `Select()`），不是数外部数据文件：
「数据里有」不等于「能用」，一个组合要 TLS profile 与 HTTP/2 指纹**两层都有**才算。
Safari 的区间稀疏，是因为 WebKit 改动线上形态的频率远低于 Chromium。

> Chromium 系衍生浏览器（Edge、Opera）按**它们 UA 里的 Chrome 版本**索引，不是自己
> 那个 —— Opera 110 的 UA 里写着 `Chrome/125`，差 15 个大版本。`ParseUA` 已经处理好。

| | |
|---|---|
| 经**第三方回显确认**的字节形态 | **44 / 44** |
| 密钥交换 | X25519、P-256、P-384、X25519MLKEM768、X25519Kyber768Draft00 |
| 覆盖层 | TLS 1.3（含 HRR、RFC 8879 证书压缩）、HTTP/2 开场 + Akamai 指纹 |

不覆盖：QUIC/HTTP-3 的**构造**（只识别，理由见下）。

## 安装

```sh
cd csrc && make            # 产出 libbrowserfp.so
```

需要 C99 编译器与 Python 3（构建期生成 profile 表）。**不链接期依赖 OpenSSL**：
SHA-256 与 EVP 密钥交换都走运行时 `dlsym`，优先用宿主进程已经加载的那份 libcrypto。
两个后果，都是有意的：

- **能干净地交叉编译**：`zig cc -target x86_64-linux-gnu` 在 macOS 上就能出 Linux 的 `.so`
- **进程里不会有第二份 OpenSSL**：链进来意味着 OpenResty worker 里存在两份

Go 绑定用 cgo 直接编译 C 源，`go build` 一步到位，不需要预先做出 `.so`
（但 `csrc/profiles.inc` 要先有：`make -C csrc profiles.inc`）。

Node 绑定用 `koffi` FFI 加载 `libbrowserfp.so`，按 `BROWSERFP_LIB` 环境变量、
`../csrc/libbrowserfp.so`（相对包内）、以及系统路径顺序查找。安装
`npm install @fizzgate/browserfp` 或 `bun add @fizzgate/browserfp`；显式指定路径
用 `browserfp.load('/path/to/libbrowserfp.so')`。

## 用法

**两个绑定都不会拿别的浏览器顶替**。认不出 UA、或那个版本没有 profile 时直接报错。
拿 Chrome 的 TLS 指纹配 Safari 的 UA，比不伪装更显眼 —— 那正是指纹检测在找的东西。

### Go

```go
import browserfp "github.com/fizzgate/browserfp/go"

p, err := browserfp.SelectUA(userAgent)   // 认不出就报错，绝不猜
if err != nil { return err }

keys, err := p.Keygen()                   // 私钥留在句柄里
defer keys.Close()

hello, _ := p.ClientHello("example.com", keys)  // 完整 TLS record
preface, pseudoOrder, _ := p.H2Preface()
```

`Select` 的失败带一个有限枚举的 `Reason`（`no_ua` / `unknown_ua` / `no_profile` /
`no_h2`），供调用方做日志聚合与降级决策 —— 错误串是给人看的，别拿它做分支。

### Lua

Lua 绑定更早，仍是**模块级函数而非句柄**；对齐 Go 的形状是计划中的事，还没做。
实际可用的写法：

```lua
local bfp = require("browserfp")
bfp.load("/path/to/libbrowserfp.so")

local brand, version = bfp.parse_ua(ua)
if not brand then return end                    -- 认不出 → 不要猜
local profile = bfp.by_ua(brand, version)
if not profile then return end                  -- 那个版本没有 profile

local keys  = bfp.gen_key_shares(brand, version)      -- {shares, derive, free}
local hello = bfp.client_hello(brand, version, "example.com", keys.shares)
local preface, pseudo_order = bfp.h2_preface(brand, version)
```

⚠ `bfp.h2_akamai(brand, version)` 对少数「有 TLS profile 但没有 h2 指纹」的版本返回
`nil` —— 用之前要查，否则会握完手却说不了话。Go 的 `Select` 已经替你查了两层。

### Node.js / Bun

两种玩法：**高层**（`fetch` / `axios`，整条链一进程搞定，无 sidecar）或**低层**
（只用 FFI，自己接 TLS 与 HTTP）。

```js
const bfp = require('@fizzgate/browserfp');

// 高层 —— 一次调用，端到端
const res = await bfp.fetch('https://tls.peet.ws/api/all', {
  ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
});
const j = await res.json();
// j.tls.ja4 与 j.http2.akamai_fingerprint 是服务端**看到的**东西：
// 与 browserfp 声明的 Chrome profile 字节一致。

// axios 接口，方便接现成代码：
const axios = bfp.axios({ ua });
const r = await axios.get('https://example.com/api');
```

`bfp.fetch` 与 `bfp.axios` 支持 HTTPS 上的 TLS 1.2 与 TLS 1.3、HTTP/1.1 与 HTTP/2、
自动解 gzip/br/zstd、重定向跟随。TLS 握手是**原生 JS 实现**（不走 `node:tls`，那里
不允许自定义 ClientHello）；证书链用 Node 的内置根信任库校验。完整 API、已知边界与
配置见 `node/README.md`。

低层用法（只要 FFI 字节，其它自己接）：

```js
const bfp = require('@fizzgate/browserfp');
const profile = bfp.selectUA(ua);        // 认不出直接抛
const keys = profile.keygen();
try {
  const hello = profile.clientHello('example.com', keys); // 完整 TLS record
  const { preface, pseudoOrder } = profile.h2Preface();
  // …自己开 socket 送字节…
} finally {
  keys.close();
}
```

`select()` 失败带一个 `SelectError`，`reason` 与 Go 绑定同一枚举
（`no_ua` / `unknown_ua` / `no_profile` / `no_h2`），供聚合与降级判断。

## 怎么验的

这一节才是重点。

**第三方回显 + 台账**：所有组合去重成 44 种字节形态，逐个打公开回显服务，按 8 个轴
比对（JA4 两段、JA3、扩展顺序、ALPN、supported_versions、PSK 模式、证书压缩、
HTTP/2 Akamai）。台账记录每种最后确认的日期，离线门禁会因「从未确认 / 过期 /
已不存在」而红。

**真实生产 UA**：覆盖数字描述的是我们自己枚举的集合，回答不了线上的问题 —— 用户发的
是 UA 字符串，中间隔着 `parse_ua`。另一条门禁拿 60 条去重后的线上 UA 量，并把两件事
**分开**：认不出扫描器是**对的**（给爬虫套浏览器指纹才是错的），认不出浏览器才是缺口。

**变异测试**：每条断言都要被「改坏它守的东西」验证过能变红。「断言打不到」在这个仓里
抓到过不止一次 —— 从不触发的 padding 检查、两侧用同一默认种子的逐字节比对、被轮换
GREASE 值骗过的扩展顺序度量，以及一个「发 HPACK 表大小更新」的开关其实从来没发过。

**阴性对照**：只走通顺路径的门禁什么也证明不了。证书压缩那条会断言**对端确实压缩了**
—— 否则「握手成功」只证明了没压缩的路径还能用。

**跨绑定一致**：Go 与 Lua 共用同一份 C 实现与 profile 表，有断言确认两边的注册表值
逐字节相同。漂移了的话，验过一边并不能代表另一边发出去的字节。

## 跑测试

```sh
pip install -r requirements.txt         # 需要 cryptography >= 49
python3 spec/verify_all.py              # 离线门禁，不联网

cd go && go test ./...                  # Go 绑定
```

推荐用 virtualenv，但不是必须 —— 任何装好依赖的 Python 3 都行：

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python spec/verify_all.py
```

⚠ `cryptography >= 49` 是硬要求不是偏好：它是密钥交换、ML-KEM、证书解析的
**独立对照实现**（`spec/test_kx.py`）。46.x 没有 `asymmetric.mlkem`，那几条跑不了。

51 条离线门禁不联网；联网的要显式 `LIVE=1`，正常跑一遍不会碰任何公开服务。

**第一次**跑要注意两点：

- 有些门禁需要几个小的 Go 测试服务端（强制 HelloRetryRequest 的 TLS 服务端、
  对 h2 较真的服务端、会发 103 Early Hints 的）。二进制不入库、按需构建，
  所以第一次会慢一些且需要 Go 工具链；没有 Go 时那些门禁报带标注的 SKIP。
- `requirements-dev.txt` 里是可选依赖（`curl_cffi` / `aioquic` / `wreq`），
  用于采集与几条额外校验。它们**未必装得上** —— `wreq` 要 Python ≥3.11，
  `curl_cffi` 的 macOS wheel 在某些环境里 import 就崩。需要它们的门禁会带着
  确切原因 SKIP，且汇总里**跳过与通过分开计数**，所以一台什么都没装的机器
  永远不会显示成「全绿」。

## 目录

```
csrc/      C 库：profile 表、ClientHello 构造、密钥交换
lua/       Lua 绑定（LuaJIT FFI）
go/        Go 绑定（cgo）
node/      Node.js / Bun 绑定 + 原生 TLS 1.2/1.3 + HTTP/1.1 + HTTP/2 + fetch/axios。
             独立成栈 —— 除 libbrowserfp.so 之外不再链任何东西。
spec/      测试：离线门禁、golden 向量、回显台账
oracle/    测试用的对端：Go 服务端（HRR、严格 h2、Early Hints）与采集脚本
docs/      设计笔记与开发日志
```

`oracle/` 不属于库本身，不参与构建、不随库分发。

## 边界

以浏览器为主；bun / rust 这类运行时正在加进来 —— 注册表里已经有采自 `curl_cffi`、
`utls`、`tls-client`、`wreq` 的条目，但那是**数据从哪来**，不是伪装目标。
指纹数据的完整来源见 [NOTICE](NOTICE)。

**QUIC/HTTP-3 只识别不构造，这是有意的。** 构造意味着从零写 QUIC 传输层（包与头部
保护、丢包恢复、拥塞控制、流控）再加 HTTP/3 与 QPACK —— 量级是这里整个 TLS 栈的
十倍以上，而收益是几条 profile（对比 HTTP/2 的 570 个组合）。这是实测不是假设：
所查的场景里 iOS Safari 根本不发 UDP。

**这不是完整的浏览器模拟器。** 它覆盖 TLS 与 HTTP/2 开场 —— 不含 HTTP 语义、
不含 JavaScript、不含 Canvas/WebGL 指纹。

## 参与

欢迎 issue 与 PR。三件本项目特有的事：

- **新增或改动指纹要有来源**：说明字节是在哪观测到的（真机浏览器，还是哪个工具的哪个
  版本），才能带着正确的 `source` 前缀进注册表。追不到观测的指纹，以后没法复验。
- **新断言必须能失败**：提交前把它守的东西改坏一次，确认会红。上面「怎么验的」里列的
  每一条发现，都来自这么做之后发现断言其实是死的。
- **整型返回值不是 C 惯例**：`browserfp_parse_ua` 成功返回 1；`browserfp_kx_keygen`、
  `browserfp_kx_derive`、`browserfp_build_client_hello_ex` 返回**产出的字节长度**，
  失败返回 -1。拿 0 去比会把每次成功都当成失败 —— 两个绑定都栽在这上面过。

提 PR 前请跑 `python3 spec/verify_all.py` 与 `cd go && go test ./...`，
两个都要绿（SKIP 没关系，它们是分开计数的）。

## 许可

Apache License 2.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

## 免责声明

**使用前请先读 [DISCLAIMER.md](DISCLAIMER.md)。** 摘要：

- 按**原样提供，不附带任何担保**。指纹会过期 —— 测试全绿只说明字节与**记录下来的**
  一致，不代表与**当前浏览器实际发送的**一致。
- 与 Google、Mozilla、Apple、Microsoft、Opera、Cloudflare、Akamai **无任何隶属关系**。
  浏览器名与指纹名属指称性使用，仅用于标识所复现的线上行为。
- 伪装浏览器是**双用途能力**。用它绕过你未被授权绕过的访问控制，不在本项目范围内、
  不受支持，且后果由你自己承担。
