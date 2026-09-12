// browserfp —— Node.js / Bun 绑定。用 koffi 加载 csrc/libbrowserfp.so。
//
// 与 Lua 绑定 (../lua/browserfp.lua) 和 Go 绑定 (../go/browserfp.go) 共用同一份
// C 实现和同一份 profile 表，三边不会漂移。API 形状与 Go 那份对齐。
//
// # 认不出就报错，绝不顶替
// select() 认不出 UA、或该版本没有 profile 时抛 SelectError，**不会退回另一个浏览器**。
// 拿 Chrome 的 TLS 指纹配 Safari 的 UA 比不伪装更显眼。
//
// # 线程/并发
// Profile 只读、可共用；Keys 持私钥且**不可并发**，用完必须 close()（也挂了 finalizer，
// 忘了 close 不会漏私钥，但显式 close 更早释放）。Node/Bun 天然单线程，无需额外锁。
//
// # 常见坑
//  1. `browserfp_parse_ua` 返回 1=成功、0=失败（不是 C 惯例 0=成功）。
//  2. `browserfp_kx_keygen` / `_derive` / `_build_client_hello_ex` 返回值是**长度**，
//     失败 -1。按 !=0 判会把每次成功当失败。
//  3. random(32B) 与 session_id **每次连接都必须重新生成** —— 照抄一份固定值让所有
//     连接的 ClientHello 逐字节相同，比不伪装还容易被判。本绑定用 crypto.randomBytes。
//  4. macOS 上：Node/Bun 都不静态链 libcrypto，只能走 dlopen。系统 LibreSSL 会
//     在 dlopen 时主动 abort（`loading libcrypto in an unsafe way`），所以初始化时
//     优先尝试 Homebrew 的 openssl@3；仍失败请显式 `initCrypto('/path/to/libcrypto.3.dylib')`。

'use strict';

const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');
const koffi = require('koffi');

// ---- 库加载 ----------------------------------------------------------------

let lib = null;
const fn = {};      // 函数句柄
const types = {};   // koffi 结构体类型

function _defaultLibCandidates() {
  const c = [];
  if (process.env.BROWSERFP_LIB) c.push(process.env.BROWSERFP_LIB);
  // 相对本文件的 ../csrc（源码树内直接跑）
  c.push(path.join(__dirname, '..', 'csrc', 'libbrowserfp.so'));
  // node_modules 打包场景可能把 .so 放在包内 lib/
  c.push(path.join(__dirname, 'lib', 'libbrowserfp.so'));
  c.push('libbrowserfp.so');
  c.push('/usr/local/lib/libbrowserfp.so');
  c.push('/usr/lib/libbrowserfp.so');
  return c;
}

/**
 * 加载 libbrowserfp.so。可显式指定路径，也可靠环境变量 BROWSERFP_LIB 或默认搜索路径。
 * 只需调用一次；重复调用会替换当前 handle。
 */
function load(libPath) {
  const tried = libPath ? [libPath] : _defaultLibCandidates();
  let lastErr;
  for (const p of tried) {
    try {
      lib = koffi.load(p);
      _bindAll();
      return;
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(
    `加载 libbrowserfp.so 失败（试过：${tried.join('  |  ')}）：` +
      (lastErr && lastErr.message)
  );
}

function _ensureLoaded() {
  if (!lib) load();
}

// koffi 结构体只允许注册一次；用一个 flag 避免同进程重复注册报错。
let _bound = false;

function _bindAll() {
  if (!_bound) _defineTypes();
  _defineFuncs();
  _bound = true;
}

function _defineTypes() {
  // 一份 u16 list（parse_client_hello 输出用；固定 64）
  const U16List = koffi.struct('browserfp_u16list', {
    items: koffi.array('uint16_t', 64),
    len: 'size_t',
  });

  types.Hello = koffi.struct('browserfp_hello', {
    client_version: 'uint16_t',
    session_id_len: 'uint8_t',
    ciphers: U16List,
    extensions: U16List,
    curves: U16List,
    sig_algs: U16List,
    supported_versions: U16List,
    has_grease: 'int',
    has_sni: 'int',
    alpn_first: koffi.array('char', 16, 'string'),
    alpn_count: 'size_t',
  });

  // 读 profile 字段用（`string` 让 koffi 自动把 const char* 解成 JS 串）
  types.Profile = koffi.struct('browserfp_profile', {
    id: 'string',
    ja4: 'string',
    h2_akamai: 'string',
    mode: 'string',
    ciphers: 'void *',
    n_ciphers: 'size_t',
    exts: 'void *',
    n_exts: 'size_t',
    curves: 'void *',
    n_curves: 'size_t',
    sigalgs: 'void *',
    n_sigalgs: 'size_t',
    rawciph: 'void *',
    n_rawciph: 'size_t',
    rawext: 'void *',
    n_rawext: 'size_t',
    extblob: 'void *',
    extoff: 'void *',
    extlen: 'void *',
    client_version: 'uint16_t',
    session_id_len: 'uint16_t',
    engine: 'string',
  });

  types.H2 = koffi.struct('browserfp_h2', {
    settings: 'void *',
    n_settings: 'size_t',
    window: 'uint32_t',
    prio: 'void *',
    n_prio: 'size_t',
    pseudo: 'string',
    akamai: 'string',
    engine: 'string',
    ver_lo: 'uint16_t',
    ver_hi: 'uint16_t',
  });

  types.Keyshare = koffi.struct('browserfp_keyshare', {
    group: 'uint16_t',
    pub: 'const uint8_t *',
    pub_len: 'size_t',
  });
}

function _defineFuncs() {
  // 识别 / 查表
  fn.parse_ua = lib.func(
    'int browserfp_parse_ua(const char *ua, _Out_ char *brand_out, size_t brand_cap, _Out_ uint16_t *version)'
  );
  fn.lookup_ua = lib.func(
    'browserfp_profile *browserfp_lookup_ua(const char *brand, uint16_t version, _Out_ int *confidence)'
  );
  fn.lookup_ja4 = lib.func(
    'browserfp_profile *browserfp_lookup_ja4(const char *ja4)'
  );
  fn.profile_count = lib.func('size_t browserfp_profile_count()');
  fn.profile_at = lib.func('browserfp_profile *browserfp_profile_at(size_t idx)');

  // HTTP/2
  fn.lookup_h2 = lib.func(
    'browserfp_h2 *browserfp_lookup_h2(const char *brand, uint16_t version)'
  );
  fn.identify_h2 = lib.func('browserfp_h2 *browserfp_identify_h2(const char *akamai)');
  fn.coherence = lib.func(
    'int browserfp_coherence(const char *ja4, const char *akamai, void *tls_engine, void *h2_engine)'
  );
  fn.h2_pseudo = lib.func('const char *browserfp_h2_pseudo(const browserfp_h2 *h)');
  fn.build_h2_preface = lib.func(
    'int browserfp_build_h2_preface(const browserfp_h2 *h, _Out_ uint8_t *out, size_t outlen)'
  );

  // ClientHello 构造
  fn.build_client_hello_ex = lib.func(
    'int browserfp_build_client_hello_ex(browserfp_profile *p, const char *sni, ' +
      'const uint8_t *random32, const uint8_t *session_id, ' +
      'const browserfp_keyshare *ks, size_t n_ks, unsigned int flags, ' +
      '_Out_ uint8_t *out, size_t outlen)'
  );
  fn.key_share_groups = lib.func(
    'size_t browserfp_key_share_groups(browserfp_profile *p, _Out_ uint16_t *groups, ' +
      '_Out_ size_t *lens, size_t max)'
  );

  // 入站识别
  fn.parse_client_hello = lib.func(
    'int browserfp_parse_client_hello(const uint8_t *record, size_t len, _Out_ browserfp_hello *out)'
  );
  fn.ja4 = lib.func(
    'int browserfp_ja4(const browserfp_hello *h, char transport, _Out_ char *out, size_t outlen)'
  );

  // 密钥交换（libcrypto）
  fn.kx_init = lib.func('int browserfp_kx_init(const char *libcrypto_path)');
  fn.kx_openssl_version = lib.func('const char *browserfp_kx_openssl_version()');
  fn.kx_pub_len = lib.func('size_t browserfp_kx_pub_len(uint16_t group)');
  fn.kx_secret_len = lib.func('size_t browserfp_kx_secret_len(uint16_t group)');
  fn.kx_keygen = lib.func(
    'int browserfp_kx_keygen(uint16_t group, _Out_ uint8_t *pub, size_t publen, _Out_ void **out)'
  );
  fn.kx_derive = lib.func(
    'int browserfp_kx_derive(void *ctx, const uint8_t *peer, size_t peerlen, _Out_ uint8_t *secret, size_t seclen)'
  );
  fn.kx_free = lib.func('void browserfp_kx_free(void *ctx)');
}

// ---- 错误类型 --------------------------------------------------------------

const Reason = Object.freeze({
  NoUA: 'no_ua',
  UnknownUA: 'unknown_ua',
  NoProfile: 'no_profile',
  NoH2: 'no_h2',
});

class SelectError extends Error {
  constructor(reason, detail) {
    super(`${reason}: ${detail}`);
    this.name = 'SelectError';
    this.reason = reason;
    this.detail = detail;
  }
}

// ---- libcrypto 初始化（懒） ------------------------------------------------

let _kxInited = false;
let _kxErr = null;

/**
 * 显式指定 libcrypto 路径。**必须在任何 keygen 之前调用**。
 * 不调用时 kxInit 走自动探测（进程里已加载的那份 → 常见 Homebrew 路径）。
 */
function initCrypto(libcryptoPath) {
  _ensureLoaded();
  if (_kxInited) return _kxErr;
  const rc = fn.kx_init(libcryptoPath || null);
  _kxInited = true;
  if (rc !== 0) {
    _kxErr = new Error(`初始化 libcrypto 失败（path=${libcryptoPath || '<auto>'}）`);
  }
  return _kxErr;
}

function _kxAutoInit() {
  _ensureLoaded();
  if (_kxInited) return _kxErr;
  // 先试 NULL —— 让 kx.c 走 RTLD_DEFAULT，命中宿主已加载的 libcrypto。
  // Node 自己就链了 OpenSSL，绝大多数场景这一步就成。
  if (fn.kx_init(null) === 0) {
    _kxInited = true;
    return null;
  }
  // Node 有时候把 OpenSSL 符号藏在自己进程里，dlsym(RTLD_DEFAULT) 也拿得到，
  // 但 Bun 的 BoringSSL 是内嵌不可见的 —— 试几条常见的 Homebrew / 系统路径。
  const candidates = [];
  if (os.platform() === 'darwin') {
    // brew --prefix openssl@3
    candidates.push('/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib');
    candidates.push('/usr/local/opt/openssl@3/lib/libcrypto.3.dylib');
  } else if (os.platform() === 'linux') {
    // 走 ldconfig 拿得到的常见名
    candidates.push('libcrypto.so.3');
    candidates.push('libcrypto.so.1.1');
    candidates.push('/usr/lib/x86_64-linux-gnu/libcrypto.so.3');
    candidates.push('/usr/lib64/libcrypto.so.3');
  }
  for (const p of candidates) {
    try {
      // 存在性预判 —— 传不存在的路径给 kx_init 会污染错误上下文
      if (p.includes('/') && !fs.existsSync(p)) continue;
    } catch (_) {}
    if (fn.kx_init(p) === 0) {
      _kxInited = true;
      return null;
    }
  }
  _kxInited = true;
  _kxErr = new Error(
    '解析 libcrypto 符号失败：宿主进程里没有可用的 libcrypto。' +
      '请显式 initCrypto("/path/to/libcrypto...") —— 例如 Homebrew 的 openssl@3。'
  );
  return _kxErr;
}

/** 已解析到的 OpenSSL 版本串；未初始化时返回空串。**建议记进日志** —— 版本不同意味着能不能做 ML-KEM 不同。 */
function opensslVersion() {
  _ensureLoaded();
  if (!_kxInited) _kxAutoInit();
  const v = fn.kx_openssl_version();
  return v || '';
}

// ---- 识别 API --------------------------------------------------------------

/**
 * 从 User-Agent 解析 (品牌, 主版本)。认不出抛 SelectError('unknown_ua')。
 * Chromium 系衍生浏览器（Edge/Opera）取的是**内核 Chrome 的版本**，不是自己那个。
 */
function parseUA(ua) {
  _ensureLoaded();
  if (typeof ua !== 'string' || ua.trim() === '') {
    throw new SelectError(Reason.NoUA, '空 User-Agent');
  }
  const brand = Buffer.alloc(32);
  const ver = [0];
  // ⚠ 返回 1=成功 / 0=失败（不是 C 惯例的 0=成功）。按 !=0 判会让每个 UA 都被认作失败。
  const rc = fn.parse_ua(ua, brand, brand.length, ver);
  if (rc !== 1) {
    const d = ua.length > 60 ? ua.slice(0, 60) + '…' : ua;
    throw new SelectError(Reason.UnknownUA, d);
  }
  const nul = brand.indexOf(0);
  return {
    brand: brand.slice(0, nul >= 0 ? nul : brand.length).toString('utf8'),
    version: ver[0],
  };
}

/** Profile 是一次可用的浏览器指纹句柄；只读、可并发。 */
class Profile {
  constructor(ptr, decoded, brand, version, akamai) {
    this._ptr = ptr;
    this.id = decoded.id;
    this.brand = brand;
    this.version = version;
    // JA4 是**注册表记录值**（多为 nosni 采集）；要与线上观测比对请用 ja4For(sni)。
    this.ja4 = decoded.ja4;
    this.akamai = akamai;
    this.engine = decoded.engine;
    this.sessionIdLen = decoded.session_id_len;
  }

  /**
   * 组装一条完整的 TLS record（含 5 字节头）。
   * GREASE 值每次调用重新随机（RFC 8701），Chrome 106+ 的扩展顺序置换也在这里做 ——
   * 所以同一个 profile 连续调用产出的字节**本来就应该不同**。
   */
  clientHello(sni, keys) {
    _ensureLoaded();
    if (!keys || keys._closed) {
      throw new Error('需要一组有效的 Keys（先调 profile.keygen()）');
    }
    // key_share 数组
    const ks = new Array(keys._groups.length);
    for (let i = 0; i < keys._groups.length; i++) {
      ks[i] = {
        group: keys._groups[i],
        pub: keys._pubs[i],
        pub_len: keys._pubs[i].length,
      };
    }
    // random(32B) 与 session_id：C 侧 !random32 || (session_id_len && !session_id) → -1；
    // **每次调用都要重新生成**：照抄 golden 里那份会让所有连接的 CH 逐字节相同。
    const random32 = crypto.randomBytes(32);
    const sid = Buffer.alloc(32);
    if (this.sessionIdLen > 0) {
      crypto.randomFillSync(sid, 0, this.sessionIdLen);
    }
    const out = Buffer.alloc(8192);
    const n = fn.build_client_hello_ex(
      this._ptr,
      sni || null,
      random32,
      sid,
      ks.length > 0 ? ks : null,
      ks.length,
      0,
      out,
      out.length
    );
    if (n <= 0) throw new Error(`构造 ClientHello 失败（错误码 ${n}）`);
    return out.slice(0, n);
  }

  /**
   * HTTP/2 开场字节（MAGIC + SETTINGS + WINDOW_UPDATE + PRIORITY）与伪头顺序。
   * **一个字节都不要改**：Akamai 指纹取的正是这几帧。
   */
  h2Preface() {
    _ensureLoaded();
    const h2ptr = fn.lookup_h2(this.brand, this.version);
    if (!h2ptr) throw new SelectError(Reason.NoH2, `${this.brand} ${this.version}`);
    const out = Buffer.alloc(512);
    const n = fn.build_h2_preface(h2ptr, out, out.length);
    if (n <= 0) throw new Error(`构造 h2 开场失败（错误码 ${n}）`);
    // pseudo 是 const char *；koffi 把 'const char *' 返回值当作字符串自动解码
    const pseudoOrder = fn.h2_pseudo(h2ptr) || '';
    return { preface: out.slice(0, n), pseudoOrder };
  }

  /** 为该 profile 生成全部需要的 key_share。 */
  keygen() {
    return _keygenForProfile(this._ptr);
  }

  /** 按给定 SNI 现算 JA4（与线上观测比较用这个，别用 profile.ja4）。 */
  ja4For(sni) {
    const keys = this.keygen();
    try {
      const rec = this.clientHello(sni, keys);
      return ja4(rec, 't');
    } finally {
      keys.close();
    }
  }
}

/**
 * 按 spec 挑一个可用的 profile。TLS profile 与 h2 指纹**两层都要有**才算可用。
 * spec: { ua?, brand?, version?, kind? } —— 有 ua 优先按 ua 解析。
 */
function select(spec) {
  _ensureLoaded();
  const kind = spec.kind || 'browser';
  if (kind !== 'browser') {
    throw new SelectError(Reason.UnknownUA, `kind=${kind} 暂不支持（目前只有 browser）`);
  }
  let brand = spec.brand;
  let version = spec.version;
  if (spec.ua) {
    const r = parseUA(spec.ua);
    brand = r.brand;
    version = r.version;
  }
  if (!brand) throw new SelectError(Reason.NoUA, '既没有 ua 也没有 brand');

  const confidence = [0];
  const pptr = fn.lookup_ua(brand, version, confidence);
  if (!pptr) {
    throw new SelectError(Reason.NoProfile, `${brand} ${version} 没有可用 profile`);
  }
  const h2ptr = fn.lookup_h2(brand, version);
  if (!h2ptr) {
    // 有 TLS 却没有 h2：握得上手但说不了话，出网即失败。宁可在这里拒绝。
    throw new SelectError(
      Reason.NoH2,
      `${brand} ${version} 有 TLS profile 但没有 h2 指纹`
    );
  }
  const decoded = koffi.decode(pptr, types.Profile);
  const h2 = koffi.decode(h2ptr, types.H2);
  return new Profile(pptr, decoded, brand, version, h2.akamai);
}

/** select({ua}) 的便捷包装。 */
function selectUA(ua) {
  return select({ ua });
}

/** 内置 profile 总数。差分测试遍历用；生产走 select()。 */
function count() {
  _ensureLoaded();
  return Number(fn.profile_count());
}

/** 按下标取 profile。差分测试用；生产走 select()。 */
function profileAt(idx) {
  _ensureLoaded();
  const p = fn.profile_at(idx);
  if (!p) return null;
  const d = koffi.decode(p, types.Profile);
  return new Profile(p, d, '', 0, d.h2_akamai);
}

/** 按 JA4 反查内置 profile。**不做近似匹配**；未命中返回 null。 */
function lookupJA4(ja4Str) {
  _ensureLoaded();
  const p = fn.lookup_ja4(ja4Str);
  if (!p) return null;
  const d = koffi.decode(p, types.Profile);
  return new Profile(p, d, '', 0, d.h2_akamai);
}

/**
 * 解析一条 ClientHello record 并算出 JA4。transport 传 't'(TCP) 或 'q'(QUIC)。
 * record 可以是 Buffer / Uint8Array。
 */
function ja4(record, transport) {
  _ensureLoaded();
  if (!record || record.length === 0) throw new Error('空 record');
  const buf = Buffer.isBuffer(record) ? record : Buffer.from(record);
  const h = {};
  if (fn.parse_client_hello(buf, buf.length, h) !== 0) {
    throw new Error('解析 ClientHello 失败');
  }
  const out = Buffer.alloc(40); // TLSFP_JA4_LEN
  const tr = typeof transport === 'string' ? transport.charCodeAt(0) : transport | 0;
  if (fn.ja4(h, tr, out, out.length) !== 0) {
    throw new Error('计算 JA4 失败');
  }
  const nul = out.indexOf(0);
  return out.slice(0, nul >= 0 ? nul : out.length).toString('ascii');
}

/**
 * JA4 与 Akamai h2 指纹是否出自同一引擎。对不上就是「TLS 像 Chrome、h2 像 Firefox」
 * 这种现实中不存在的组合。返回 true=一致 / false=矛盾或信息不足。
 */
function coherence(ja4Str, akamai) {
  _ensureLoaded();
  return fn.coherence(ja4Str, akamai, null, null) === 0;
}

// ---- 密钥交换 --------------------------------------------------------------

// 忘了 close() 也不至于泄漏私钥的兜底
const _keyFinalizer = new FinalizationRegistry((ctxs) => {
  try {
    for (const c of ctxs) if (c) fn.kx_free(c);
  } catch (_) {}
});

/** Keys 是一次连接用的密钥材料。**私钥不出这个对象**，用完必须 close()。不可并发。 */
class Keys {
  constructor(groups, ctxs, pubs) {
    this._groups = groups;
    this._ctxs = ctxs;
    this._pubs = pubs;
    this._closed = false;
    _keyFinalizer.register(this, ctxs.slice(), this);
  }

  /** 这批密钥覆盖的组（顺序与 ClientHello 里一致）。 */
  groups() {
    return this._groups.slice();
  }

  /** 用服务端选中组的公钥算共享密钥。 */
  derive(group, peer) {
    if (this._closed) throw new Error('Keys 已 close');
    if (!peer || peer.length === 0) throw new Error('peer 公钥为空');
    for (let i = 0; i < this._groups.length; i++) {
      if (this._groups[i] !== group) continue;
      const slen = Number(fn.kx_secret_len(group));
      if (slen === 0) throw new Error(`组 0x${group.toString(16)} 没有共享密钥长度`);
      const out = Buffer.alloc(slen);
      const buf = Buffer.isBuffer(peer) ? peer : Buffer.from(peer);
      // 返回值是**共享密钥长度**，失败 -1
      const n = fn.kx_derive(this._ctxs[i], buf, buf.length, out, slen);
      if (n !== slen) {
        throw new Error(
          `组 0x${group.toString(16)} 算共享密钥失败（要 ${slen} 字节，得 ${n}）——服务端那段长度对不上？`
        );
      }
      return out;
    }
    throw new Error(
      `这批密钥里没有组 0x${group.toString(16)}（有 [${this._groups
        .map((g) => '0x' + g.toString(16))
        .join(',')}]）`
    );
  }

  /** 释放全部私钥。可重复调用。 */
  close() {
    if (this._closed) return;
    this._closed = true;
    _keyFinalizer.unregister(this);
    for (const c of this._ctxs) if (c) fn.kx_free(c);
    this._ctxs = [];
  }
}

function _keygenForProfile(pptr) {
  _ensureLoaded();
  const err = _kxAutoInit();
  if (err) throw err;

  const maxGroups = 8;
  const groups = new Array(maxGroups).fill(0);
  const lens = new Array(maxGroups).fill(0);
  const n = Number(fn.key_share_groups(pptr, groups, lens, maxGroups));
  if (n <= 0) throw new Error('该 profile 没有 key_share 组');

  const outGroups = [];
  const outCtxs = [];
  const outPubs = [];
  try {
    for (let i = 0; i < n; i++) {
      const g = groups[i];
      const publen = Number(fn.kx_pub_len(g));
      if (publen === 0) {
        throw new Error(`不支持的 key_share 组 0x${g.toString(16)}`);
      }
      const pub = Buffer.alloc(publen);
      const ctxHolder = [null];
      // ⚠ 返回值是**公钥长度**，失败 -1
      const rc = fn.kx_keygen(g, pub, publen, ctxHolder);
      if (rc !== publen) {
        throw new Error(
          `组 0x${g.toString(16)} 生成密钥失败（要 ${publen} 字节，得 ${rc}）——` +
            `这一组当前的 OpenSSL 可能不支持`
        );
      }
      outGroups.push(g);
      outCtxs.push(ctxHolder[0]);
      outPubs.push(pub);
    }
    return new Keys(outGroups, outCtxs, outPubs);
  } catch (e) {
    // 部分成功时也要释放已建的 ctx
    for (const c of outCtxs) if (c) fn.kx_free(c);
    throw e;
  }
}

// ---- exports ---------------------------------------------------------------

module.exports = {
  load,
  initCrypto,
  opensslVersion,
  parseUA,
  select,
  selectUA,
  lookupJA4,
  ja4,
  coherence,
  count,
  profileAt,
  Profile,
  Keys,
  SelectError,
  Reason,
};
