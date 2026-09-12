# browserfp Node.js / Bun 绑定

**原生 fetch / axios 支持** —— 一行 `const bfp = require('@fizzgate/browserfp')`
把浏览器指纹接进你现有的 Node 出网代码。**不是 sidecar，不是本地代理**：从 TCP
→ TLS 1.2/1.3 → HTTP/2/1.1 → HTTP 客户端整条链都在同一个 Node 进程里、原生实现。

## 目录

- [为什么要原生](#为什么要原生)
- [快速开始](#快速开始)
- [安装](#安装)
- [已实现](#已实现)
- [尚未实现 / 已知边界](#尚未实现--已知边界)
- [常用配方](#常用配方)
  - [基本 GET / POST](#基本-get--post)
  - [切浏览器](#切浏览器)
  - [自定义头保序保大小写](#自定义头保序保大小写)
  - [接管现成 axios 实例](#接管现成-axios-实例)
  - [socks 或 http 代理](#socks-或-http-代理)
  - [自签证书 / 关闭校验（诊断）](#自签证书--关闭校验诊断)
- [端到端指纹对齐（证据）](#端到端指纹对齐证据)
- [API 参考](#api-参考)
- [错误分类](#错误分类)
- [C 侧返回值口径](#c-侧返回值口径)
- [密钥交换（libcrypto）](#密钥交换libcrypto)
- [与 Go / Lua 绑定的一致性](#与-go--lua-绑定的一致性)
- [平台](#平台)

## 为什么要原生

Node 内置 `tls` 模块**不允许**注入自定义 ClientHello —— 这正是 Node 端一直没法用
浏览器指纹伪装的原因。市面上其它方案（curl-impersonate 绑定、本地代理转发）都是
sidecar：多一个进程、多一份 TLS 栈、多一层不透明。本包直接把该发的字节由
`libbrowserfp.so` 造出来，然后用 Node 自己的 `crypto`（HKDF / PRF / AEAD / X509）
走完剩下的握手与应用层——一个进程搞定。

## 快速开始

```js
const bfp = require('@fizzgate/browserfp');

// —— 用 fetch —— //
const res = await bfp.fetch('https://tls.peet.ws/api/all', {
  ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
});
const j = await res.json();
console.log(j.tls.ja4);         // t13d1516h2_8daaf6152771_02713d6af862
console.log(j.http2.akamai_fingerprint);  // 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p

// —— 用 axios —— //
const axios = bfp.axios({ ua });
const r = await axios.get('https://example.com/api');
console.log(r.status, r.data);
```

**证据链**：把 `res.json()` 里的 `tls.ja4` 与 `bfp.selectUA(ua).ja4` 直接比对——
JA4 后两段（cipher 集合 + 扩展集合 + 签名算法 hash）**逐字节相同**。
Akamai 三段（SETTINGS / WINDOW_UPDATE / pseudo 顺序）也**逐字节相同**。

## 安装

```sh
npm install @fizzgate/browserfp
# 或
bun add @fizzgate/browserfp
```

**运行时需要 `libbrowserfp.so`**。构建：

```sh
make -C ../csrc profiles.inc
make -C ../csrc libbrowserfp.so
```

产物按下面顺序自动找到：

1. `BROWSERFP_LIB` 环境变量
2. `../csrc/libbrowserfp.so`（相对本包；源码树直接跑就这条）
3. `./lib/libbrowserfp.so`（打包时放包内）
4. 系统路径 `/usr/local/lib/libbrowserfp.so` / `/usr/lib/libbrowserfp.so`

也可以显式：`browserfp.load('/path/to/libbrowserfp.so')`。

## 已实现

| 层 | 状态 |
|---|---|
| **TLS 1.3** record 层（含 RFC 8879 证书压缩：zlib / brotli / zstd） | ✅ |
| **TLS 1.2** record 层（含 RFC 5077 NewSessionTicket、CCS 兼容语义） | ✅ |
| ClientHello（含 GREASE / 扩展置换 / X25519 / X25519MLKEM768） | ✅（复用 browserfp） |
| ServerHello / EncryptedExtensions / Certificate / CertificateVerify / Finished | ✅ |
| ServerKeyExchange（ECDHE_ECDSA / ECDHE_RSA, X25519 / P-256 / P-384） | ✅ |
| 证书链校验（含**交叉签根**：按公钥而非 fingerprint 匹配 anchor） | ✅ |
| AEAD：AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 | ✅ |
| HKDF-Expand-Label（1.3）+ PRF-HMAC-SHA256/384（1.2） | ✅ |
| HPACK（RFC 7541，含 Huffman 双向编解码） | ✅ |
| HTTP/2：SETTINGS/WINDOW_UPDATE/PRIORITY/HEADERS/DATA/CONTINUATION/RST_STREAM/GOAWAY/PING | ✅ |
| HTTP/2 pseudo-header 顺序按 profile 排（`m,a,s,p` / `m,p,a,s` / `m,s,p,a`） | ✅ |
| HTTP/1.1（Content-Length / chunked / EOF） | ✅ |
| 重定向跟随（301/302/303/307/308）、gzip/deflate/br/zstd 解压、UTF-8 body | ✅ |
| fetch (WHATWG-ish) / axios 兼容 API | ✅ |
| **协议版本自动分流**：peek ServerHello 决定跑 1.3 还是 1.2 | ✅ |

## 尚未实现 / 已知边界

| | 影响 | 优先级 |
|---|---|---|
| HelloRetryRequest（HRR，TLS 1.3） | 服务端拒绝我方 key_share 组时的重发；实测触发率极低（Chrome 默认组现代 CDN 都接） | 低 |
| Session Ticket / 0-RTT | 单请求场景没影响 | 低 |
| KeyUpdate（TLS 1.3） | 长连接场景需要；一连接一请求场景不到 | 低 |
| TLS 1.2 RSA key exchange | 只做 ECDHE（前向保密）；老站点若强制 RSA 会拒 | 低 |
| TLS 1.2 CBC 密码套件 | 只做 AEAD（GCM / ChaCha20-Poly1305）；纯 CBC 的老服务器不支持 | 低 |
| HTTP/2 多路复用 | 目前一连接一请求；伪装场景足够，若要长连接复用还要做流控 | 中 |
| HTTP/1.1 keep-alive 复用 | 单请求即关；伪装场景多是真人短会话，改动价值小 | 低 |
| Windows 上的 `.dll` | 库本身尚未提供 Windows 构建 | 中 |
| 极少数 CDN 的行为（httpbin/baidu 触发 `bad_record_mac` 或 RST） | 已排除本地实现问题（badssl / peet.ws / Akamai / ssllabs / rfc-editor 全通）；怀疑是**服务端 WAF 对指纹一致性做二次校验**，或对 record 分片时序敏感 | 中 |

## 常用配方

### 基本 GET / POST

```js
const bfp = require('@fizzgate/browserfp');

// GET
const r = await bfp.fetch('https://example.com/api/status');
console.log(r.status, await r.json());

// POST JSON
const r2 = await bfp.fetch('https://example.com/api/submit', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ hello: 'world' }),
});

// axios 版本
const axios = bfp.axios();
const r3 = await axios.post('https://example.com/api/submit', { hello: 'world' });
```

### 切浏览器

```js
// Chrome 125 桌面
await bfp.fetch(url, {
  ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
});

// Firefox 120 桌面
await bfp.fetch(url, {
  ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
});

// Safari 17.6 macOS —— pseudo-header 顺序会自动切成 m,s,p,a
await bfp.fetch(url, {
  ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 ' +
      '(KHTML, like Gecko) Version/17.6 Safari/605.1.15',
});

// 或者直接传 Profile 对象（省一次 UA 解析）
const profile = bfp.selectUA(ua);
await bfp.fetch(url, { profile });
```

### 自定义头保序保大小写

伪装场景**不能**自作主张改头顺序或大小写 —— 各浏览器的头形态不同，改动就漏。

```js
// HTTP/1.1：完全按你传入的顺序和大小写发
await bfp.fetch('https://example.com/', {
  headers: [
    ['Host', 'example.com'],
    ['User-Agent', chromeUA],       // 大写 U/A
    ['Accept', '*/*'],
    ['Accept-Language', 'en-US,en;q=0.9'],
  ],
});

// HTTP/2：普通头一律小写（RFC 7540），伪头（:method/:authority/:scheme/:path）
// 由 profile 的 pseudoOrder 决定顺序
await bfp.fetch('https://tls.peet.ws/api/all', {
  headers: [
    ['user-agent', chromeUA],
    ['accept', '*/*'],
    ['accept-language', 'en-US,en;q=0.9'],
    ['cookie', 'sessionid=xxxx'],
  ],
});
```

### 接管现成 axios 实例

已有的 axios 代码（含 interceptors / cancel tokens）保留，只把出网 adapter 换掉：

```js
const axios = require('axios');
const bfp = require('@fizzgate/browserfp');

const inst = axios.create({
  baseURL: 'https://api.example.com',
  timeout: 30000,
  adapter: bfp.axiosAdapter({ ua: chromeUA }),
});

// interceptor 照旧
inst.interceptors.response.use(r => { console.log('OK', r.status); return r; });

const r = await inst.get('/status');
```

### socks 或 http 代理

**当前尚未支持**——原生 TLS 客户端目前直连 target。要接入代理需要：
- HTTP CONNECT 握手（挂在 socket 上）
- SOCKS5 握手（挂在 socket 上）
- SNI/Host 保持 target，不是代理

**跟进 issue 时会加。** 当前场景可以自己建 TCP socket 走代理后再交给 `tls13.connect`：
需要修改 `connect()` 让它接受一个已建好的 socket 参数 —— 该接口尚未导出，可参考
`node/tls13.js` 的 `connect()` 内实现替换 `net.createConnection` 那一步。

### 自签证书 / 关闭校验（诊断）

**生产不要这么做。** 目前接口没提供 `verify: false`，因为证书校验是伪装场景的最后
一道防线（不校验就允许 MITM 采集你的所有 cookie）。要绕过要自己去 `tls13.js` 的
`verifyCertChain` 里改判据 —— 请留 `TODO`。

## 端到端指纹对齐（证据）

拿 Chrome 125 UA 打 `tls.peet.ws/api/all`，服务端识别到：

```
JA4:      t13d1516h2_8daaf6152771_02713d6af862
Akamai:   1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
sent:     SETTINGS(HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0,
                   INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144)
          WINDOW_UPDATE(15663105)
          HEADERS(stream_id=1, pseudo: m,a,s,p, END_STREAM+END_HEADERS)
```

browserfp 声明的 profile 值：

```
ja4=t13i1515h2_8daaf6152771_02713d6af862   // i vs d = nosni 与 sni 差别（预期）
akamai=1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p
```

**JA4 后两段与 Akamai 全段与实际观测逐字节一致**。

**换 Safari UA 再打一遍**，服务端识别到：

```
JA4:      t13d2014h2_a09f3c656075_14788d8d241b   // 完全不同的 JA4（Safari 形态）
Akamai:   2:0;4:4194304;3:100|10485760|0|m,s,p,a  // Safari 独有的 pseudo 顺序 m,s,p,a
```

**同一份代码、同一个进程，只改 UA，就切成了另一个浏览器的字节形态。**

## API 参考

顶层：

- `bfp.fetch(url, init)` → `Response`（`.text()` / `.json()` / `.arrayBuffer()` / `.buffer()`）
- `bfp.axios(defaults)` → 极简 axios 实例（`get`/`post`/`put`/`delete`/`patch`/`head`/`options`/`request`）
- `bfp.axiosAdapter(defaults)` → adapter 函数，可以塞进 `axios.create({adapter})` 接管现成 axios

底层（FFI 层，原有 API）：

- `bfp.selectUA(ua)` / `bfp.select({ua|brand,version})` → `Profile`
- `bfp.parseUA(ua)` → `{brand, version}`
- `bfp.lookupJA4(ja4)` → `Profile | null`
- `bfp.ja4(record, 't'|'q')` / `bfp.coherence(ja4, akamai)`
- `bfp.connect({host, port, profile})` → 已握手的 TLS Duplex（**自动分流 1.2 / 1.3**）
- `bfp.h1.request()` / `bfp.h2.request()` —— 只想自己造帧、组装场景

`fetch(url, init)` init：

| 字段 | 说明 |
|---|---|
| `method` | 默认 `GET` |
| `headers` | object / Headers / `[[k,v],...]`（保序） |
| `body` | Buffer / string |
| `ua` | 伪装谁的 UA；不给用默认 Chrome |
| `profile` | 直接给 Profile 对象（比 ua 优先） |
| `redirect` | `'follow'`（默认）/ `'manual'` / `'error'` |
| `maxRedirects` | 默认 20 |
| `timeout` | 默认 30000 ms |
| `decompress` | 默认 true（gzip / deflate / br / zstd） |

`connect(opts)` 返回：

```ts
{
  stream: Duplex,          // 已握手的双工流，写=加密送出，读=解密后的应用数据
  alpn: string | null,     // 协商到的 ALPN（"h2" / "http/1.1" / …）
  cipherSuite: number,     // 0x1301 / 0xc02f / …
  tlsVersion: 'TLSv1.2' | 'TLSv1.3',
  close(): void,
}
```

## 错误分类

`bfp.SelectError` 带枚举 `.reason`：

| reason | 触发 |
|---|---|
| `no_ua` | fetch/select 拿不到 UA 也没显式 brand |
| `unknown_ua` | UA 认不出品牌/版本 |
| `no_profile` | 认出了但那个版本没 profile |
| `no_h2` | 有 TLS profile 但没 h2 指纹（少数版本会） |

普通 `Error` 触发场景：

- `TLS 1.x alert：fatal <desc>` —— 服务端主动 alert 拒绝
- `证书 SAN 不匹配 <host>` / `证书 xxx 已过期` / `链末 xxx 无匹配可信 root`
- `构造 ClientHello 失败（错误码 -1）` —— profile 缺重建字段等
- `解析 libcrypto 符号失败：...` —— libcrypto 找不到；显式 `initCrypto(path)`
- `HTTP/2 请求超时` / `HTTP/1.1 请求超时` —— 服务端不响应
- `重定向超过 N 次` —— 死循环重定向
- `handshake <host> 超时` / `connect <host>:<port> 超时`

## C 侧返回值口径

`browserfp_*` 的整型返回**不是** C 惯例的 0=成功：

| 函数 | 成功 | 失败 |
|---|---|---|
| `browserfp_parse_ua` | **1** | 0 |
| `browserfp_kx_keygen` | **公钥长度** | -1 |
| `browserfp_kx_derive` | **共享密钥长度** | -1 |
| `browserfp_build_client_hello_ex` | **record 长度** | -1 |
| `browserfp_build_h2_preface` | **写入字节数** | -1 |

Lua 与 Go 绑定都判 `n != len`，本绑定同。按 `!= 0` 写会把每次成功当失败。

## 密钥交换（libcrypto）

`profile.keygen()` 与 TLS 1.2 的 ECDHE 都在**首次调用**时懒初始化 `libcrypto`：

1. 先试 `RTLD_DEFAULT`（宿主进程里已加载的那份）—— Node 自己链了 OpenSSL，
   绝大多数场景这一步就成
2. 失败再按平台试常见路径：
   - macOS：`/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib` 与
     `/usr/local/opt/openssl@3/lib/libcrypto.3.dylib`
   - Linux：`libcrypto.so.3` / `libcrypto.so.1.1` 与常见发行版路径
3. 都不成才抛错

要指定别的路径就 `browserfp.initCrypto('/path/to/libcrypto...')`，**必须在任何
keygen 之前调用**。

### ClientHello 的 random / session_id

`clientHello(sni, keys)` **每次调用**都用 `crypto.randomBytes` 重新生成 random(32B)
和 session_id。绝对不要缓存或复用 —— 照抄一份固定值会让所有连接的 ClientHello
逐字节相同，比不伪装还容易被判。

### Bun 用户注意

Bun 内嵌 BoringSSL 且**不导出**符号，`RTLD_DEFAULT` 拿不到 —— 本绑定会走到候选
路径那步。macOS 上 `brew install openssl@3`；Linux 上装 `libssl3` / `openssl-libs`
就行；仍有问题就显式 `initCrypto(path)`。

## 与 Go / Lua 绑定的一致性

同一份 C 实现、同一份 profile 表。选中同一个 profile：

- `profile.ja4` 与 Go / Lua 逐字节相同
- `profile.akamai` 与 Go / Lua 逐字节相同
- `profile.clientHello()` 除 random / GREASE / 扩展置换外结构相同

漂移了就说明**用一边验过的指纹不能代表另一边发出去的字节**——查回来的 profile
比对就是干这个用的。

## 平台

在 x86_64 / arm64 Linux 与 arm64 / x86_64 macOS 上跑过。Windows 未测
（`libbrowserfp` 本身尚未提供 `.dll` 构建）。

Node 版本要求：Node ≥ 14（依赖 `koffi`）；实测 Node 24 + OpenSSL 3.5 与 Bun 1.4
均通。
