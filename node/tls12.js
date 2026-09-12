// TLS 1.2 客户端（RFC 5246 + RFC 5288/GCM + RFC 8446 兼容 ClientHello）。
//
// 与 TLS 1.3 的关键差异（写这个之前如果你只熟悉 1.3 会踩这些）：
//   1. ChangeCipherSpec 是**真**的（不是兼容性 payload）。收/发都要做，作为切换加密的信号。
//   2. 密钥派生用 PRF (HMAC-SHA256 / SHA384)，不是 HKDF-Expand-Label。
//   3. 加密 record 的**类型不改**（22/23/21 各自出现），不像 1.3 全套壳成 23。
//   4. GCM AEAD 的 nonce = **implicit_salt(4)** + **explicit_nonce(8)**，后者随 record 写在
//      payload 头部；AAD = seq(8) | type(1) | version(2) | plaintext_length(2)，与 1.3 完全不同。
//   5. 握手序列固定：SH → Cert → ServerKeyExchange → SHD → CKE → CCS → Finished ↔ CCS → Finished。
//   6. Master secret = PRF(pre_master, "master secret", client_random || server_random, 48)；
//      key material = PRF(master, "key expansion", server_random || client_random, ...)，
//      **随机数拼接的顺序不同**（master 是 c||s，key 是 s||c）——踩过。
//   7. Finished verify_data = PRF(master, "client finished"|"server finished",
//      Hash(所有握手消息), 12)。**Hash 是该 cipher suite 的 PRF 哈希**（SHA-256 或 SHA-384）。
//
// 支持范围（现代 CDN 都覆盖，老站可能不够）：
//   - 密钥交换：ECDHE_ECDSA / ECDHE_RSA（curve X25519 / P-256 / P-384）
//   - AEAD：AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305（RFC 7905）
//   - CBC 与 RSA-key-exchange 不做（前者废弃、后者不给前向保密）

'use strict';

const net = require('net');
const crypto = require('crypto');
const tls = require('tls');
const zlib = require('zlib');
const { Duplex } = require('stream');

// ---- 常量 -------------------------------------------------------------------

const CT_CHANGE_CIPHER_SPEC = 20;
const CT_ALERT = 21;
const CT_HANDSHAKE = 22;
const CT_APPLICATION_DATA = 23;

const HS_HELLO_REQUEST = 0;
const HS_CLIENT_HELLO = 1;
const HS_SERVER_HELLO = 2;
const HS_CERTIFICATE = 11;
const HS_SERVER_KEY_EXCHANGE = 12;
const HS_CERTIFICATE_REQUEST = 13;
const HS_SERVER_HELLO_DONE = 14;
const HS_CERTIFICATE_VERIFY = 15;
const HS_CLIENT_KEY_EXCHANGE = 16;
const HS_FINISHED = 20;
const HS_NEW_SESSION_TICKET = 4; // RFC 5077，服务端在 CCS 之前送
const HS_COMPRESSED_CERTIFICATE = 25; // RFC 8879（在 TLS 1.2 里也能用）

const CERT_COMPRESS_ZLIB = 1;
const CERT_COMPRESS_BROTLI = 2;
const CERT_COMPRESS_ZSTD = 3;

const EXT_SERVER_NAME = 0;
const EXT_ALPN = 16;
const EXT_SUPPORTED_VERSIONS = 43;

// TLS 1.2 GCM/CHACHA20 密码套件
const CIPHER_SUITES = {
  // ECDHE_ECDSA
  0xc02b: { kx: 'ECDHE_ECDSA', hash: 'sha256', aead: 'aes-128-gcm', keyLen: 16, ivLen: 4, tagLen: 16, prfHash: 'sha256' },
  0xc02c: { kx: 'ECDHE_ECDSA', hash: 'sha384', aead: 'aes-256-gcm', keyLen: 32, ivLen: 4, tagLen: 16, prfHash: 'sha384' },
  0xcca9: { kx: 'ECDHE_ECDSA', hash: 'sha256', aead: 'chacha20-poly1305', keyLen: 32, ivLen: 12, tagLen: 16, prfHash: 'sha256' },
  // ECDHE_RSA
  0xc02f: { kx: 'ECDHE_RSA', hash: 'sha256', aead: 'aes-128-gcm', keyLen: 16, ivLen: 4, tagLen: 16, prfHash: 'sha256' },
  0xc030: { kx: 'ECDHE_RSA', hash: 'sha384', aead: 'aes-256-gcm', keyLen: 32, ivLen: 4, tagLen: 16, prfHash: 'sha384' },
  0xcca8: { kx: 'ECDHE_RSA', hash: 'sha256', aead: 'chacha20-poly1305', keyLen: 32, ivLen: 12, tagLen: 16, prfHash: 'sha256' },
};

// 曲线：与 browserfp.kx 支持一致
const NAMED_CURVE_TO_KX_GROUP = {
  0x001d: 0x001d, // X25519
  0x0017: 0x0017, // secp256r1
  0x0018: 0x0018, // secp384r1
};

// ChaCha20-Poly1305（RFC 7905）：把 seq 用 salt 一次性 XOR 到 12B iv 里，
// **不发** explicit_nonce（0 长度）
function isChacha(suite) { return suite.aead === 'chacha20-poly1305'; }

const ALERT_LEVELS = { 1: 'warning', 2: 'fatal' };
const ALERT_DESCS = {
  0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac',
  40: 'handshake_failure', 42: 'bad_certificate', 46: 'certificate_unknown',
  47: 'illegal_parameter', 48: 'unknown_ca', 50: 'decode_error',
  51: 'decrypt_error', 70: 'protocol_version', 80: 'internal_error',
  109: 'missing_extension', 110: 'unsupported_extension', 112: 'unrecognized_name',
};

// ---- Reader / Writer（与 tls13.js 一样；本地复制避免循环依赖） -------------

class Reader {
  constructor(buf, off = 0, end = buf.length) { this.buf = buf; this.off = off; this.end = end; }
  remaining() { return this.end - this.off; }
  bytes(n) { if (this.off + n > this.end) throw new Error('Reader 越界'); const s = this.buf.subarray(this.off, this.off + n); this.off += n; return s; }
  u8() { return this.bytes(1)[0]; }
  u16() { return this.bytes(2).readUInt16BE(0); }
  u24() { const b = this.bytes(3); return (b[0] << 16) | (b[1] << 8) | b[2]; }
  vec(lenBytes) {
    let len;
    if (lenBytes === 1) len = this.u8();
    else if (lenBytes === 2) len = this.u16();
    else if (lenBytes === 3) len = this.u24();
    else throw new Error('vec lenBytes 1/2/3');
    return this.bytes(len);
  }
}

// ---- PRF (RFC 5246 §5) ------------------------------------------------------

function prf(hash, secret, label, seed, length) {
  // P_hash(secret, label + seed)
  const labelSeed = Buffer.concat([Buffer.from(label, 'ascii'), seed]);
  const out = [];
  let A = crypto.createHmac(hash, secret).update(labelSeed).digest();
  let got = 0;
  while (got < length) {
    const block = crypto.createHmac(hash, secret).update(A).update(labelSeed).digest();
    out.push(block);
    got += block.length;
    A = crypto.createHmac(hash, secret).update(A).digest();
  }
  return Buffer.concat(out).subarray(0, length);
}

// ---- 证书链校验（与 tls13.js 相同实现；复制以免循环依赖） ------------------

let _rootCache = null;
function _pubKeyDER(cert) { return cert.publicKey.export({ type: 'spki', format: 'der' }); }
function _rootCerts() {
  if (_rootCache) return _rootCache;
  const arr = tls.rootCertificates.map((pem) => new crypto.X509Certificate(pem));
  const bySubject = new Map(), byPubKey = new Map();
  for (const c of arr) {
    if (!bySubject.has(c.subject)) bySubject.set(c.subject, []);
    bySubject.get(c.subject).push(c);
    const pk = _pubKeyDER(c).toString('hex');
    if (!byPubKey.has(pk)) byPubKey.set(pk, c);
  }
  _rootCache = { all: arr, bySubject, byPubKey };
  return _rootCache;
}

function verifyCertChain(hostname, derChain) {
  if (derChain.length === 0) throw new Error('cert chain 为空');
  const chain = derChain.map((der) => new crypto.X509Certificate(der));
  const roots = _rootCerts();
  const now = Date.now();
  if (!chain[0].checkHost(hostname)) {
    throw new Error(`证书 SAN 不匹配 ${hostname}（subject=${chain[0].subject}）`);
  }
  for (const c of chain) {
    if (Date.parse(c.validFrom) > now) throw new Error(`证书 ${c.subject} 尚未生效`);
    if (Date.parse(c.validTo) < now) throw new Error(`证书 ${c.subject} 已过期`);
  }
  let anchorIdx = -1;
  for (let i = 0; i < chain.length; i++) {
    const pk = _pubKeyDER(chain[i]).toString('hex');
    if (roots.byPubKey.has(pk)) { anchorIdx = i; break; }
  }
  if (anchorIdx >= 0) {
    for (let i = 0; i < anchorIdx; i++) {
      if (!chain[i].verify(chain[i + 1].publicKey)) {
        throw new Error(`${chain[i].subject} 签名不能由 ${chain[i + 1].subject} 验证`);
      }
    }
    return chain;
  }
  const last = chain[chain.length - 1];
  const cands = roots.bySubject.get(last.issuer) || [];
  let anchor = null;
  for (const r of cands) {
    if (Date.parse(r.validFrom) > now || Date.parse(r.validTo) < now) continue;
    if (last.verify(r.publicKey)) { anchor = r; break; }
  }
  if (!anchor) throw new Error(`链末 ${last.subject}（issuer=${last.issuer}）无匹配可信 root`);
  for (let i = 0; i < chain.length - 1; i++) {
    if (!chain[i].verify(chain[i + 1].publicKey)) {
      throw new Error(`${chain[i].subject} 签名不能由 ${chain[i + 1].subject} 验证`);
    }
  }
  return chain;
}

// ---- 签名方案验签（TLS 1.2 用 SignatureAndHashAlgorithm，字节形态与 1.3 相同） ---
function verifyScheme(scheme, publicKey, data, sig) {
  switch (scheme) {
    case 0x0403: return crypto.verify('sha256', data, { key: publicKey, dsaEncoding: 'der' }, sig);
    case 0x0503: return crypto.verify('sha384', data, { key: publicKey, dsaEncoding: 'der' }, sig);
    case 0x0603: return crypto.verify('sha512', data, { key: publicKey, dsaEncoding: 'der' }, sig);
    // TLS 1.2 里 RSA 常用 PKCS#1 v1.5，也允许 PSS（更少见）
    case 0x0401: return crypto.verify('sha256', data, publicKey, sig);
    case 0x0501: return crypto.verify('sha384', data, publicKey, sig);
    case 0x0601: return crypto.verify('sha512', data, publicKey, sig);
    case 0x0804: return crypto.verify('sha256', data, {
      key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32,
    }, sig);
    case 0x0805: return crypto.verify('sha384', data, {
      key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48,
    }, sig);
    case 0x0806: return crypto.verify('sha512', data, {
      key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64,
    }, sig);
    case 0x0807: return crypto.verify(null, data, publicKey, sig);
    default:
      throw new Error(`TLS 1.2 未支持的签名方案 0x${scheme.toString(16)}`);
  }
}

// ---- TLS 1.2 GCM 加/解封 ----------------------------------------------------

// AAD = seq(8) | type(1) | version(2) | plaintext_length(2)
function aadFor(seq, type, plaintextLen) {
  const b = Buffer.alloc(13);
  b.writeBigUInt64BE(BigInt(seq), 0);
  b[8] = type;
  b[9] = 0x03; b[10] = 0x03;
  b.writeUInt16BE(plaintextLen, 11);
  return b;
}

class TLS12Sealer {
  constructor(suite, key, salt) {
    this.suite = suite;
    this.key = key;
    this.salt = salt; // 4 字节 implicit
    this.seq = 0;
  }
  // 返回 record 的 payload（不含 5 字节 record 头）：explicit_nonce(8) + ciphertext + tag  (GCM)
  //                                              或 ciphertext + tag                     (ChaCha20-Poly1305)
  seal(type, plaintext) {
    let nonce, explicit;
    if (isChacha(this.suite)) {
      // RFC 7905：nonce = pad_left(seq, 4) XOR salt(12) —— salt 用了 12 字节 iv 版本
      // 但 browserfp 场景下 TLS 1.2 ChaCha20 罕见；仍支持。
      const seqBuf = Buffer.alloc(12);
      seqBuf.writeBigUInt64BE(BigInt(this.seq), 4);
      nonce = Buffer.alloc(12);
      for (let i = 0; i < 12; i++) nonce[i] = seqBuf[i] ^ this.salt[i];
      explicit = Buffer.alloc(0);
    } else {
      // GCM：nonce = salt(4) | explicit(8)，explicit 递增序号即可
      explicit = Buffer.alloc(8);
      explicit.writeBigUInt64BE(BigInt(this.seq), 0);
      nonce = Buffer.concat([this.salt, explicit]);
    }
    const aad = aadFor(this.seq, type, plaintext.length);
    const c = crypto.createCipheriv(this.suite.aead, this.key, nonce, { authTagLength: 16 });
    c.setAAD(aad); // GCM 不需要 plaintextLength（CCM 才要）
    const enc = Buffer.concat([c.update(plaintext), c.final()]);
    const tag = c.getAuthTag();
    this.seq++;
    return Buffer.concat([explicit, enc, tag]);
  }
}

class TLS12Opener {
  constructor(suite, key, salt) {
    this.suite = suite; this.key = key; this.salt = salt; this.seq = 0;
  }
  open(type, payload) {
    let nonce, ct;
    if (isChacha(this.suite)) {
      const seqBuf = Buffer.alloc(12);
      seqBuf.writeBigUInt64BE(BigInt(this.seq), 4);
      nonce = Buffer.alloc(12);
      for (let i = 0; i < 12; i++) nonce[i] = seqBuf[i] ^ this.salt[i];
      ct = payload;
    } else {
      if (payload.length < 8 + 16) throw new Error('TLS 1.2 GCM 密文过短');
      const explicit = payload.subarray(0, 8);
      nonce = Buffer.concat([this.salt, explicit]);
      ct = payload.subarray(8);
    }
    const tag = ct.subarray(ct.length - 16);
    const body = ct.subarray(0, ct.length - 16);
    const aad = aadFor(this.seq, type, body.length);
    const d = crypto.createDecipheriv(this.suite.aead, this.key, nonce, { authTagLength: 16 });
    d.setAAD(aad);
    d.setAuthTag(tag);
    let out;
    try { out = Buffer.concat([d.update(body), d.final()]); }
    catch (e) { throw new Error(`TLS 1.2 AEAD 解密失败 seq=${this.seq}: ${e.message}`); }
    this.seq++;
    return out;
  }
}

// ---- Record 层 --------------------------------------------------------------

class Record12Layer {
  constructor(sock) {
    this.sock = sock;
    this.recvBuf = Buffer.alloc(0);
    this.sealer = null;
    this.opener = null;
    this._pendingHandshake = Buffer.alloc(0);
  }
  ingest(chunk) {
    this.recvBuf = this.recvBuf.length === 0 ? chunk : Buffer.concat([this.recvBuf, chunk]);
  }
  writePlain(type, payload) {
    const hdr = Buffer.from([type, 0x03, 0x03, (payload.length >> 8) & 0xff, payload.length & 0xff]);
    this.sock.write(Buffer.concat([hdr, payload]));
  }
  writeEncrypted(type, plaintext) {
    if (!this.sealer) throw new Error('sealer 未就绪');
    const p = this.sealer.seal(type, plaintext);
    const hdr = Buffer.from([type, 0x03, 0x03, (p.length >> 8) & 0xff, p.length & 0xff]);
    this.sock.write(Buffer.concat([hdr, p]));
  }
  // 读一条 record；加密时按当前 opener 解开；返回 { type, payload } 或 null
  _readOneRecord() {
    if (this.recvBuf.length < 5) return null;
    const type = this.recvBuf[0];
    const len = this.recvBuf.readUInt16BE(3);
    if (this.recvBuf.length < 5 + len) return null;
    const payload = this.recvBuf.subarray(5, 5 + len);
    this.recvBuf = this.recvBuf.subarray(5 + len);
    if (this.opener) {
      // 注意：CCS 之前的 record 不加密，之后（同方向）才加密。
      // 这里读方向的切换发生在收到 server CCS 之后 —— 由外层控制。
      return { type, payload: this.opener.open(type, payload) };
    }
    return { type, payload };
  }
  drain(callbacks) {
    for (;;) {
      const rec = this._readOneRecord();
      if (!rec) return;
      if (rec.type === CT_CHANGE_CIPHER_SPEC) {
        callbacks.onCCS && callbacks.onCCS();
        continue;
      }
      if (rec.type === CT_HANDSHAKE) {
        this._pendingHandshake = Buffer.concat([this._pendingHandshake, rec.payload]);
        for (;;) {
          if (this._pendingHandshake.length < 4) break;
          const hsLen = (this._pendingHandshake[1] << 16) |
                        (this._pendingHandshake[2] << 8) |
                        this._pendingHandshake[3];
          if (this._pendingHandshake.length < 4 + hsLen) break;
          const mt = this._pendingHandshake[0];
          const body = this._pendingHandshake.subarray(4, 4 + hsLen);
          const full = this._pendingHandshake.subarray(0, 4 + hsLen);
          this._pendingHandshake = this._pendingHandshake.subarray(4 + hsLen);
          callbacks.onHandshake && callbacks.onHandshake(mt, body, full);
        }
      } else if (rec.type === CT_APPLICATION_DATA) {
        callbacks.onApp && callbacks.onApp(rec.payload);
      } else if (rec.type === CT_ALERT) {
        callbacks.onAlert && callbacks.onAlert(rec.payload[0], rec.payload[1]);
      }
    }
  }
}

// ---- 客户端 -----------------------------------------------------------------

class TLS12Client extends Duplex {
  /**
   * opts:
   *   socket           net.Socket（TCP 已连）
   *   sni              主机名
   *   clientHelloBody  ClientHello 的 handshake_body(4B 头开始)；用于握手转录。
   *                    （我们的 ClientHello record 已经 socket.write 出去了，此处仅需要用来做转录）
   *   pendingBuf       连接层已经从 socket 读出但尚未消费的字节
   *   kxKeygen(group)          函数：为某 curve 生成，返回 { ctx, pub }
   *   kxDerive(ctx, group, peer) 函数：算 pre_master
   *   kxFree(ctx)              释放
   */
  constructor(opts) {
    super({ allowHalfOpen: false });
    this.sock = opts.socket;
    this.sni = opts.sni;
    this.rl = new Record12Layer(this.sock);
    this.pendingBuf = opts.pendingBuf || Buffer.alloc(0);
    this.clientHelloBody = opts.clientHelloBody;
    this.kxKeygen = opts.kxKeygen;
    this.kxDerive = opts.kxDerive;
    this.kxFree = opts.kxFree;

    this.state = 'wait_sh';
    this.transcript = [this.clientHelloBody]; // 每条握手消息（含 4B 头）
    this.suite = null;
    this.suiteId = 0;
    this.serverRandom = null;
    this.clientRandom = opts.clientRandom; // 32B，取自我们送出去的 ClientHello（外层调用者传入）
    this.serverCerts = [];
    this.serverPubKey = null;
    this.serverEcdheGroup = null;
    this.serverEcdhePub = null;
    this.serverKxSigScheme = 0;
    this.serverKxSig = null;
    this.serverKxParamsBytes = null; // 原始 ECParameters + server ECPoint 字节（用于验签）
    this.negotiatedAlpn = null;
    this.recvCcs = false;

    // 初始把 pendingBuf 灌进 record layer
    if (this.pendingBuf.length > 0) this.rl.ingest(this.pendingBuf);

    this.sock.on('data', (c) => {
      try { this.rl.ingest(c); this._pump(); } catch (e) { this._fail(e); }
    });
    this.sock.on('error', (e) => this._fail(e));
    this.sock.on('close', () => {
      if (this.state !== 'app') this._fail(new Error('socket 早关（握手未完）'));
      else this.push(null);
    });
  }

  handshake() {
    if (this._handshakeDone) return this._handshakeDone;
    this._handshakeDone = new Promise((res, rej) => {
      this._hsResolve = res; this._hsReject = rej;
    });
    // 送出去的 ClientHello 已经在连接层写完；这里立刻 _pump 一次消费已缓冲的 SH
    setImmediate(() => {
      try { this._pump(); } catch (e) { this._fail(e); }
    });
    return this._handshakeDone;
  }

  _fail(e) {
    if (this._hsReject && this.state !== 'app') {
      const rej = this._hsReject;
      this._hsReject = null; this._hsResolve = null;
      rej(e);
    }
    this.destroy(e);
  }

  _pump() {
    this.rl.drain({
      onHandshake: (mt, body, full) => this._onHandshake(mt, body, full),
      onApp: (chunk) => {
        if (this.state === 'app') this.push(chunk);
      },
      onAlert: (level, desc) => {
        const lv = ALERT_LEVELS[level] || `level=${level}`;
        const ds = ALERT_DESCS[desc] || `desc=${desc}`;
        if (desc === 0) { if (this.state === 'app') this.push(null); return; }
        this._fail(new Error(`TLS 1.2 alert：${lv} ${ds}`));
      },
      onCCS: () => {
        // 收到 server CCS：之后到来的握手/应用 record 由 opener 解密
        this.recvCcs = true;
      },
    });
  }

  _onHandshake(mt, body, full) {
    // 转录里**始终**用握手消息原文（含 4B 头）
    this.transcript.push(full);
    switch (mt) {
      case HS_SERVER_HELLO:
        return this._processServerHello(body);
      case HS_CERTIFICATE:
        return this._processCertificate(body, /*compressed=*/false);
      case HS_COMPRESSED_CERTIFICATE:
        return this._processCompressedCertificate(body);
      case HS_SERVER_KEY_EXCHANGE:
        return this._processServerKeyExchange(body);
      case HS_CERTIFICATE_REQUEST:
        throw new Error('本客户端不支持 client-auth（收到 CertificateRequest）');
      case HS_SERVER_HELLO_DONE:
        return this._processServerHelloDone();
      case HS_FINISHED:
        return this._processServerFinished(body);
      case HS_NEW_SESSION_TICKET:
        // RFC 5077：服务端在 CCS 之前送 NST 以支持 session resumption。
        // 我们不做 resumption，忽略即可 —— 但**转录**必须含它（server Finished 的
        // verify_data 是在包含 NST 的转录上算的，_onHandshake 顶部已 push）。
        return;
      case HS_HELLO_REQUEST:
        // RFC 5246 §7.4.1.1：服务端可以发 HelloRequest 要求重协商。忽略。
        return;
      default:
        throw new Error(`TLS 1.2 意外握手 type=${mt}`);
    }
  }

  _processServerHello(body) {
    const r = new Reader(body);
    r.u16(); // legacy_version
    this.serverRandom = Buffer.from(r.bytes(32));
    r.vec(1); // session_id echo
    this.suiteId = r.u16();
    this.suite = CIPHER_SUITES[this.suiteId];
    if (!this.suite) {
      throw new Error(`服务端选了不支持的 TLS 1.2 密码套件 0x${this.suiteId.toString(16)}`);
    }
    r.u8(); // legacy_compression_method
    // extensions (可选)
    if (r.remaining() > 0) {
      const extsRaw = r.vec(2);
      const er = new Reader(extsRaw);
      while (er.remaining() > 0) {
        const t = er.u16();
        const d = er.vec(2);
        if (t === EXT_ALPN) {
          const ar = new Reader(d);
          const listRaw = ar.vec(2);
          const lr = new Reader(listRaw);
          const nameLen = lr.u8();
          this.negotiatedAlpn = lr.bytes(nameLen).toString('ascii');
        }
      }
    }
  }

  _processCompressedCertificate(body) {
    const r = new Reader(body);
    const algo = r.u16();
    const uncompLen = r.u24();
    const compressed = r.vec(3);
    let plain;
    if (algo === CERT_COMPRESS_ZLIB) plain = zlib.inflateSync(compressed);
    else if (algo === CERT_COMPRESS_BROTLI) plain = zlib.brotliDecompressSync(compressed);
    else if (algo === CERT_COMPRESS_ZSTD) {
      if (typeof zlib.zstdDecompressSync !== 'function') {
        throw new Error('服务端选了 zstd 压缩证书但当前 Node 无 zlib.zstdDecompressSync');
      }
      plain = zlib.zstdDecompressSync(compressed);
    } else throw new Error(`未知证书压缩算法 ${algo}`);
    if (plain.length !== uncompLen) {
      throw new Error(`证书解压长度不符 ${uncompLen} vs ${plain.length}`);
    }
    this._processCertificate(plain, /*compressed=*/true);
  }

  _processCertificate(body, compressed) {
    // TLS 1.2 Certificate: opaque asn.1_cert<1..2^24-1> certificate_list<0..2^24-1>
    // 注意：TLS 1.2 的 Certificate 消息**没有** context 字段（那是 1.3 才加的）
    const r = new Reader(body);
    let listRaw;
    if (compressed) {
      // 压缩后的**是 Certificate body**（跟 1.3 语义一样但 1.2 里 body 是直接的 cert list）
      // 但注意 TLS 1.2 里 body 前没有 context 字段，直接是 cert list<3>
      listRaw = r.vec(3);
    } else {
      listRaw = r.vec(3);
    }
    const lr = new Reader(listRaw);
    const certs = [];
    while (lr.remaining() > 0) {
      const der = lr.vec(3);
      certs.push(Buffer.from(der));
    }
    if (certs.length === 0) throw new Error('Certificate 空');
    this.serverCerts = certs;
    this.serverX509 = verifyCertChain(this.sni, certs);
    this.serverPubKey = this.serverX509[0].publicKey;
  }

  _processServerKeyExchange(body) {
    // TLS 1.2 ECDHE 的 SKE (RFC 8422 §5.4)：
    //   ECParameters:
    //     ECCurveType curve_type = named_curve(3);   // 1 字节
    //     NamedCurve namedcurve;                     // 2 字节
    //   ECPoint public;                              // opaque<1..255>: len(1) + point
    //   SignatureAndHashAlgorithm algorithm;         // 2 字节
    //   opaque signature<0..2^16-1>;
    const r = new Reader(body);
    const curveType = r.u8();
    if (curveType !== 3) throw new Error(`SKE 非 named_curve (${curveType})`);
    const namedCurve = r.u16();
    const pointLen = r.u8();
    const point = r.bytes(pointLen);

    // 记录 ECParameters 原字节（前 4 字节：curve_type(1) + named_curve(2) + point_len(1) + point(len)）
    const paramsBytesLen = 1 + 2 + 1 + pointLen;
    this.serverKxParamsBytes = body.subarray(0, paramsBytesLen);
    this.serverEcdheGroup = namedCurve;
    this.serverEcdhePub = Buffer.from(point);

    // 签名部分（TLS 1.2 里 signature_and_hash 是 2 字节）
    this.serverKxSigScheme = r.u16();
    this.serverKxSig = Buffer.from(r.vec(2));

    // 验签：数据 = client_random || server_random || ECParameters
    const signedData = Buffer.concat([this.clientRandom, this.serverRandom, this.serverKxParamsBytes]);
    if (!verifyScheme(this.serverKxSigScheme, this.serverPubKey, signedData, this.serverKxSig)) {
      throw new Error(`TLS 1.2 SKE 签名校验失败（scheme=0x${this.serverKxSigScheme.toString(16)}）`);
    }
  }

  async _processServerHelloDone() {
    // 生成我方 ECDHE 密钥（照服务端选的曲线来）
    const kxGroup = NAMED_CURVE_TO_KX_GROUP[this.serverEcdheGroup];
    if (!kxGroup) throw new Error(`未支持的曲线 0x${this.serverEcdheGroup.toString(16)}`);
    const { ctx, pub } = this.kxKeygen(kxGroup);
    let preMaster;
    try {
      preMaster = this.kxDerive(ctx, kxGroup, this.serverEcdhePub);
    } finally {
      this.kxFree(ctx);
    }

    // 送 ClientKeyExchange（明文，走 record 22）
    //   ClientECDiffieHellmanPublic { opaque point<1..255>; }
    const cke = Buffer.concat([Buffer.from([pub.length]), pub]);
    const ckeHs = Buffer.concat([
      Buffer.from([HS_CLIENT_KEY_EXCHANGE, (cke.length >> 16) & 0xff, (cke.length >> 8) & 0xff, cke.length & 0xff]),
      cke,
    ]);
    // 一些中间盒（部分 CloudFront/AWS LB）对**CKE|CCS|Finished 三条 record**
    // 是否在同一 TCP 段里到达极度敏感，分开写会被无声 RST。用 cork 一次性刷。
    if (typeof this.sock.cork === 'function') this.sock.cork();
    this.rl.writePlain(CT_HANDSHAKE, ckeHs);
    this.transcript.push(ckeHs);

    // 派生 master_secret 与 key material（PRF）
    const master = prf(this.suite.prfHash, preMaster, 'master secret',
      Buffer.concat([this.clientRandom, this.serverRandom]), 48);

    // key expansion：seed 顺序是 server_random || client_random（**跟 master 相反**）
    const keySeed = Buffer.concat([this.serverRandom, this.clientRandom]);
    const keyLen = this.suite.keyLen;
    const ivLen = this.suite.ivLen; // GCM 4；ChaCha20 12
    const totalLen = 2 * keyLen + 2 * ivLen; // 没有 MAC key（AEAD）
    const km = prf(this.suite.prfHash, master, 'key expansion', keySeed, totalLen);
    let off = 0;
    const cKey = km.subarray(off, off + keyLen); off += keyLen;
    const sKey = km.subarray(off, off + keyLen); off += keyLen;
    const cIV = km.subarray(off, off + ivLen); off += ivLen;
    const sIV = km.subarray(off, off + ivLen); off += ivLen;

    // 计算 Finished verify_data（transcript 含 CKE，不含 Finished 本身）
    this.rl.sealer = new TLS12Sealer(this.suite, cKey, cIV);
    const th = crypto.createHash(this.suite.prfHash);
    for (const m of this.transcript) th.update(m);
    const cVerify = prf(this.suite.prfHash, master, 'client finished', th.digest(), 12);
    const finHs = Buffer.concat([
      Buffer.from([HS_FINISHED, 0, 0, cVerify.length]),
      cVerify,
    ]);
    this.rl.writePlain(CT_CHANGE_CIPHER_SPEC, Buffer.from([0x01]));
    this.rl.writeEncrypted(CT_HANDSHAKE, finHs);
    if (typeof this.sock.uncork === 'function') this.sock.uncork();
    this.transcript.push(finHs);

    // 记住这些以便验证 server Finished（server 用它自己的转录到 client Finished 前）
    this._master = master;
    this._sKey = sKey;
    this._sIV = sIV;
  }

  _processServerFinished(body) {
    // 校验 server Finished：verify_data = PRF(master, "server finished", Hash(transcript excl. this msg), 12)
    // 上面 _onHandshake 已经把 full 推入 transcript；先把它扣掉再算
    const savedFull = this.transcript.pop();
    const th = crypto.createHash(this.suite.prfHash);
    for (const m of this.transcript) th.update(m);
    const expected = prf(this.suite.prfHash, this._master, 'server finished', th.digest(), 12);
    if (Buffer.compare(body, expected) !== 0) {
      throw new Error('server Finished verify_data 不符');
    }
    this.transcript.push(savedFull); // 复原，虽然此后不再用

    // 到这里 server Finished 已经过；进入 application 阶段
    // 收方向的 opener 应该已经在 server CCS 之后就绪 —— TLS 1.2 收到 CCS 后
    // 后续 record 都由 opener 解开，但我们的 record layer 用同一个 opener 对象。
    // 现在补装 opener：server 侧从 CCS 之后开始加密，所以我们必须在**处理 server Finished
    // 那条 record**之前已经切换 —— 我们靠 `onCCS` 里设 recvCcs=true 但没装 opener，
    // 因此当前这条 Finished 是**明文**读进来的（seq=0），并没被解密。这与 TLS 1.2 行为不符。
    // 正确做法：CCS 到达时立刻装 opener；此处已到 Finished，若 opener 尚未装说明解密路径没走。
    // —— 见下面 _onCCS 的实现：CCS 触发 opener 装载。
    if (this._hsResolve) {
      const res = this._hsResolve;
      this._hsResolve = null; this._hsReject = null;
      this.state = 'app';
      res({ alpn: this.negotiatedAlpn, cipherSuite: this.suiteId, tlsVersion: 'TLSv1.2' });
    }
  }

  // Duplex 侧
  _write(chunk, _enc, cb) {
    try {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const MAX = 16384;
      for (let i = 0; i < buf.length; i += MAX) {
        this.rl.writeEncrypted(CT_APPLICATION_DATA, buf.subarray(i, i + MAX));
      }
      cb();
    } catch (e) { cb(e); }
  }
  _read() { /* push 驱动 */ }
  _final(cb) {
    try {
      if (this.rl.sealer) this.rl.writeEncrypted(CT_ALERT, Buffer.from([1, 0]));
      this.sock.end();
      cb();
    } catch (e) { cb(e); }
  }
  _destroy(err, cb) {
    try { this.sock.destroy(err || undefined); } catch (_) {}
    cb(err);
  }
}

// ---- 复位 recvCcs 逻辑：真正装 opener --------------------------------------
//
// 上面 Record12Layer._readOneRecord 用了 this.opener 存在与否来决定加不加密。
// 收到 server CCS 时，我们要装 opener 并从下一条 record 开始解密。
// 为了让代码可读，覆盖 drain 里的 onCCS：
const _origPump = TLS12Client.prototype._pump;
TLS12Client.prototype._pump = function () {
  this.rl.drain({
    onHandshake: (mt, body, full) => this._onHandshake(mt, body, full),
    onApp: (chunk) => { if (this.state === 'app') this.push(chunk); },
    onAlert: (level, desc) => {
      if (desc === 0) { if (this.state === 'app') this.push(null); return; }
      const lv = ALERT_LEVELS[level] || `level=${level}`;
      const ds = ALERT_DESCS[desc] || `desc=${desc}`;
      this._fail(new Error(`TLS 1.2 alert：${lv} ${ds}`));
    },
    onCCS: () => {
      if (!this.rl.opener) {
        this.rl.opener = new TLS12Opener(this.suite, this._sKey, this._sIV);
      }
    },
  });
};

module.exports = { TLS12Client, verifyCertChain, verifyScheme, prf, CIPHER_SUITES };
