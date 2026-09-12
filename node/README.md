# browserfp Node.js / Bun 绑定

**原生 fetch / axios 支持** —— 一行 `const bfp = require('@fizzgate/browserfp')` 就把
浏览器指纹接进你现有的 Node 出网代码。**不是 sidecar，不是本地代理** —— 从 TCP →
TLS 1.3 → HTTP/2/1.1 → HTTP 客户端整条链都在同一个 Node 进程里、原生实现。

## 为什么要原生

Node 内置 `tls` 模块**不允许**注入自定义 ClientHello —— 这正是 Node 端一直没法用
浏览器指纹伪装的原因。市面上其它方案（curl-impersonate 绑定、本地代理转发）都是
sidecar：多一个进程、多一份 TLS 栈、多一层不透明。本包直接把该发的字节由
`libbrowserfp.so` 造出来，然后用 Node 自己的 `crypto`（HKDF / AEAD / X509）走完
剩下的握手与应用层——一个进程搞定。

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
const axios = bfp.axios({ ua });  // 返回一个 axios 兼容实例
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
| TLS 1.3 record 层 | ✅ |
| ClientHello（含 GREASE / 扩展置换 / X25519 / X25519MLKEM768） | ✅（复用 browserfp） |
| ServerHello / EncryptedExtensions / Certificate / CertificateVerify / Finished | ✅ |
| **RFC 8879 证书压缩**（zlib / brotli / zstd） | ✅ |
| 证书链校验（含**交叉签根**：按公钥而非 fingerprint 匹配 anchor） | ✅ |
| AEAD：AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 | ✅ |
| HPACK（RFC 7541，含 Huffman 双向） | ✅ |
| HTTP/2：SETTINGS/WINDOW_UPDATE/PRIORITY/HEADERS/DATA/CONTINUATION/RST_STREAM/GOAWAY/PING | ✅ |
| HTTP/2 pseudo-header 顺序按 profile 排（`m,a,s,p` / `m,p,a,s` 等） | ✅ |
| HTTP/1.1（Content-Length / chunked / EOF） | ✅ |
| 重定向、gzip/deflate/br/zstd 解开、UTF-8 body | ✅ |
| fetch / axios 兼容 API | ✅ |

## 尚未实现

| | 影响 | 优先级 |
|---|---|---|
| TLS 1.2 后备 | 只支持 TLS 1.3 站点（现代 CDN 都开了；老站会 `supported_versions=0x0` 报错） | 中 |
| HelloRetryRequest（HRR） | 服务端拒绝我方 key_share 组时的重发；实测触发率很低（Chrome 默认组现代服务端都接） | 低 |
| Session Ticket / 0-RTT | 单请求场景没影响 | 低 |
| KeyUpdate | 长连接场景需要；一连接一请求场景不到 | 低 |
| HTTP/2 多路复用 | 目前一连接一请求；伪装场景足够，若要长连接复用还要做流控 | 中 |
| Windows 上的 `.dll` | 库本身尚未提供 Windows 构建 | 中 |

## 端到端指纹对齐（**证据**）

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

## API

顶层：

- `bfp.fetch(url, init)` → `Response`（`text()` / `json()` / `arrayBuffer()` / `buffer()`）
- `bfp.axios(defaults)` → 极简 axios 实例（`get`/`post`/`put`/`delete`/`patch`/`head`/`options`/`request`）
- `bfp.axiosAdapter(defaults)` → adapter 函数，可以塞进 `axios.create({adapter})` 接管现成 axios

底层（原有 FFI 层）：

- `bfp.selectUA(ua)` / `bfp.select({ua|brand,version})` → `Profile`
- `bfp.parseUA(ua)` → `{brand, version}`
- `bfp.lookupJA4(ja4)` → `Profile | null`
- `bfp.ja4(record, 't'|'q')` / `bfp.coherence(ja4, akamai)`
- `bfp.connect({host, port, profile})` → 已握手的 TLS Duplex
- `bfp.h1.request()` / `bfp.h2.request()` —— 只想造帧、自己组装场景

`fetch` init：

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

## C 侧返回值口径（最容易踩的一处）

`browserfp_*` 的整型返回**不是** C 惯例的 0=成功：

| 函数 | 成功 | 失败 |
|---|---|---|
| `browserfp_parse_ua` | **1** | 0 |
| `browserfp_kx_keygen` | **公钥长度** | -1 |
| `browserfp_kx_derive` | **共享密钥长度** | -1 |
| `browserfp_build_client_hello_ex` | **record 长度** | -1 |
| `browserfp_build_h2_preface` | **写入字节数** | -1 |

Lua 与 Go 绑定都判 `n != len`，本绑定同。按 `!= 0` 写会把每次成功当失败。

## ClientHello 的 random / session_id

`clientHello(sni, keys)` **每次调用**都用 `crypto.randomBytes` 重新生成 random(32B)
和 session_id。绝对不要缓存或复用 —— 照抄一份固定值会让所有连接的 ClientHello
逐字节相同，比不伪装还容易被判。

## 密钥交换（libcrypto）

`profile.keygen()` 在**首次调用**时懒初始化 `libcrypto`：

1. 先试 `RTLD_DEFAULT`（宿主进程里已加载的那份）—— Node 自己链了 OpenSSL，
   绝大多数场景这一步就成
2. 失败再按平台试常见路径：
   - macOS：`/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib` 与
     `/usr/local/opt/openssl@3/lib/libcrypto.3.dylib`
   - Linux：`libcrypto.so.3` / `libcrypto.so.1.1` 与常见发行版路径
3. 都不成才抛错

要指定别的路径就 `browserfp.initCrypto('/path/to/libcrypto...')`，**必须在任何
keygen 之前调用**。

## 与 Go / Lua 绑定的一致性

同一份 C 实现、同一份 profile 表。选中同一个 profile：

- `profile.ja4` 与 Go / Lua 逐字节相同
- `profile.akamai` 与 Go / Lua 逐字节相同
- `profile.clientHello()` 除 random / GREASE / 扩展置换外结构相同

漂移了就说明**用一边验过的指纹不能代表另一边发出去的字节**。

## 平台

在 x86_64 / arm64 Linux 与 arm64 / x86_64 macOS 上跑过。Windows 未测。
