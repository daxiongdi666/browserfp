// TLS 1.3 客户端（RFC 8446）—— **原生实现**，只做浏览器指纹伪装场景需要的那一小片。
//
// 设计取舍：
//   1. ClientHello 的字节**不是这里造的**。它由 ../csrc/libbrowserfp.so 按 profile
//      生成，含 GREASE / 扩展置换 / key_share。Node 内置 tls 拿不到"我决定发什么"这一步，
//      所以整个 record 层和握手编排必须自己写；反过来说除了 ClientHello 的**内容**，
//      整条链（record 层、key schedule、AEAD、Encrypted Handshake、证书链、Finished、
//      应用数据）都由本文件承担。
//
//   2. 密钥交换（keygen/derive）走 browserfp 的 kx（复用宿主的 OpenSSL），
//      因为 X25519MLKEM768 在 Node 的 crypto 里没有 —— 生产 UA 里 64.9% 都需要它。
//      X25519 / P-256 / P-384 也顺手都走 kx，避免"三条不同的密钥路径"分头维护。
//
//   3. AEAD / HKDF / 哈希 / 签名校验 全部用 node:crypto。**别再引第二份密码学** ——
//      浏览器指纹伪装最忌"我方拼装的字节和真浏览器不一致"，而所有分歧都藏在实现差异里。
//
//   4. 证书链校验用 X509Certificate + tls.rootCertificates 自己走一遍。Node 内置的
//      checkServerIdentity 只能校主机名，不管链上信任 —— 生产必须闭环。
//
// 不做的部分（scope 明示）：
//   - session ticket / 0-RTT（PSK 需要另一整套 key schedule；本轮不需要）
//   - 客户端证书（TLS_CLIENT_AUTH）
//   - 密钥更新（KeyUpdate 消息；长连接下会需要，先记 TODO）
//   - HRR 完整支持（下面 handleHRR 是最小实现：只在服务端要一个不同组时重发）

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

const HS_CLIENT_HELLO = 1;
const HS_SERVER_HELLO = 2;
const HS_NEW_SESSION_TICKET = 4;
const HS_ENCRYPTED_EXTENSIONS = 8;
const HS_CERTIFICATE = 11;
const HS_CERTIFICATE_REQUEST = 13;
const HS_CERTIFICATE_VERIFY = 15;
const HS_FINISHED = 20;
const HS_KEY_UPDATE = 24;
const HS_COMPRESSED_CERTIFICATE = 25; // RFC 8879

const CERT_COMPRESS_ZLIB = 1;
const CERT_COMPRESS_BROTLI = 2;
const CERT_COMPRESS_ZSTD = 3;

const EXT_SERVER_NAME = 0;
const EXT_SUPPORTED_GROUPS = 10;
const EXT_SIGNATURE_ALGORITHMS = 13;
const EXT_ALPN = 16;
const EXT_SUPPORTED_VERSIONS = 43;
const EXT_KEY_SHARE = 51;

const CS_AES_128_GCM_SHA256 = 0x1301;
const CS_AES_256_GCM_SHA384 = 0x1302;
const CS_CHACHA20_POLY1305_SHA256 = 0x1303;

// HelloRetryRequest 的 server_random 恒定值（RFC 8446 §4.1.3）
const HRR_RANDOM = Buffer.from(
  'CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C',
  'hex'
);

const ALERT_LEVELS = { 1: 'warning', 2: 'fatal' };
const ALERT_DESCS = {
  0: 'close_notify',
  10: 'unexpected_message',
  20: 'bad_record_mac',
  22: 'record_overflow',
  40: 'handshake_failure',
  41: 'no_certificate',
  42: 'bad_certificate',
  43: 'unsupported_certificate',
  44: 'certificate_revoked',
  45: 'certificate_expired',
  46: 'certificate_unknown',
  47: 'illegal_parameter',
  48: 'unknown_ca',
  49: 'access_denied',
  50: 'decode_error',
  51: 'decrypt_error',
  70: 'protocol_version',
  71: 'insufficient_security',
  80: 'internal_error',
  86: 'inappropriate_fallback',
  90: 'user_canceled',
  109: 'missing_extension',
  110: 'unsupported_extension',
  112: 'unrecognized_name',
  113: 'bad_certificate_status_response',
  115: 'unknown_psk_identity',
  116: 'certificate_required',
  120: 'no_application_protocol',
};

// ---- ByteReader / ByteWriter ------------------------------------------------

class Reader {
  constructor(buf, off = 0, end = buf.length) {
    this.buf = buf;
    this.off = off;
    this.end = end;
  }
  remaining() {
    return this.end - this.off;
  }
  bytes(n) {
    if (this.off + n > this.end) throw new Error(`Reader 越界：要 ${n} 剩 ${this.remaining()}`);
    const s = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return s;
  }
  u8() {
    return this.bytes(1)[0];
  }
  u16() {
    return this.bytes(2).readUInt16BE(0);
  }
  u24() {
    const b = this.bytes(3);
    return (b[0] << 16) | (b[1] << 8) | b[2];
  }
  u32() {
    return this.bytes(4).readUInt32BE(0);
  }
  vec(lenBytes) {
    let len;
    if (lenBytes === 1) len = this.u8();
    else if (lenBytes === 2) len = this.u16();
    else if (lenBytes === 3) len = this.u24();
    else throw new Error('vec lenBytes 1/2/3');
    return this.bytes(len);
  }
}

class Writer {
  constructor() {
    this.chunks = [];
    this.n = 0;
  }
  bytes(b) {
    const buf = Buffer.isBuffer(b) ? b : Buffer.from(b);
    this.chunks.push(buf);
    this.n += buf.length;
    return this;
  }
  u8(v) {
    this.chunks.push(Buffer.from([v & 0xff]));
    this.n += 1;
    return this;
  }
  u16(v) {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(v & 0xffff, 0);
    this.chunks.push(b);
    this.n += 2;
    return this;
  }
  u24(v) {
    this.chunks.push(Buffer.from([(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]));
    this.n += 3;
    return this;
  }
  u32(v) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(v >>> 0, 0);
    this.chunks.push(b);
    this.n += 4;
    return this;
  }
  build() {
    return Buffer.concat(this.chunks, this.n);
  }
}

// ---- HKDF / key schedule -----------------------------------------------------

// hash: 'sha256' | 'sha384'
function hashLen(hash) {
  return hash === 'sha384' ? 48 : 32;
}

function transcriptHash(hash, msgs) {
  const h = crypto.createHash(hash);
  for (const m of msgs) h.update(m);
  return h.digest();
}

// HKDF-Extract(salt, IKM) = HMAC(salt, IKM)
function hkdfExtract(hash, salt, ikm) {
  return crypto.createHmac(hash, salt).update(ikm).digest();
}

// HKDF-Expand(PRK, info, L) —— 用手写实现，Node 的 hkdfSync 也可以但接口不便
function hkdfExpand(hash, prk, info, L) {
  const hLen = hashLen(hash);
  const N = Math.ceil(L / hLen);
  if (N > 255) throw new Error('HKDF-Expand L 超上限');
  const T = [Buffer.alloc(0)];
  for (let i = 1; i <= N; i++) {
    const h = crypto.createHmac(hash, prk);
    h.update(T[i - 1]);
    h.update(info);
    h.update(Buffer.from([i]));
    T.push(h.digest());
  }
  return Buffer.concat(T.slice(1)).subarray(0, L);
}

// HKDF-Expand-Label(Secret, Label, Context, Length)
// HkdfLabel = uint16 length | opaque label<7..255> | opaque context<0..255>
// label 前缀 "tls13 "
function hkdfExpandLabel(hash, secret, label, context, L) {
  const fullLabel = 'tls13 ' + label;
  const info = new Writer()
    .u16(L)
    .u8(fullLabel.length)
    .bytes(Buffer.from(fullLabel, 'ascii'))
    .u8(context.length)
    .bytes(context)
    .build();
  return hkdfExpand(hash, secret, info, L);
}

// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
function deriveSecret(hash, secret, label, msgs) {
  return hkdfExpandLabel(hash, secret, label, transcriptHash(hash, msgs), hashLen(hash));
}

// ---- AEAD 支持 --------------------------------------------------------------

function cipherParams(cipherSuite) {
  switch (cipherSuite) {
    case CS_AES_128_GCM_SHA256:
      return { hash: 'sha256', keyLen: 16, ivLen: 12, aead: 'aes-128-gcm', tagLen: 16 };
    case CS_AES_256_GCM_SHA384:
      return { hash: 'sha384', keyLen: 32, ivLen: 12, aead: 'aes-256-gcm', tagLen: 16 };
    case CS_CHACHA20_POLY1305_SHA256:
      return { hash: 'sha256', keyLen: 32, ivLen: 12, aead: 'chacha20-poly1305', tagLen: 16 };
    default:
      throw new Error(`不支持的 cipher suite 0x${cipherSuite.toString(16)}`);
  }
}

// TLS 1.3 nonce = iv XOR seq(8B, big-endian, right-aligned)
function makeNonce(iv, seq) {
  const nonce = Buffer.from(iv);
  // seq 是 JS Number（<2^53），足够握手 + 应用两侧不会溢
  const hi = Math.floor(seq / 0x100000000);
  const lo = seq >>> 0;
  // ⚠ JS 的 `^` 会把两个操作数当成**有符号 32 位**运算，结果也可能是负数
  // （例如 0x80000000 ^ 0 = -2147483648），writeUInt32BE 会拒。用 `>>> 0` 转无符号。
  nonce.writeUInt32BE((nonce.readUInt32BE(nonce.length - 8) ^ hi) >>> 0, nonce.length - 8);
  nonce.writeUInt32BE((nonce.readUInt32BE(nonce.length - 4) ^ lo) >>> 0, nonce.length - 4);
  return nonce;
}

class AeadSealer {
  constructor(params, key, iv) {
    this.params = params;
    this.key = key;
    this.iv = iv;
    this.seq = 0;
  }
  seal(plaintext, aad) {
    const nonce = makeNonce(this.iv, this.seq);
    this.seq++;
    const cipher = crypto.createCipheriv(this.params.aead, this.key, nonce, {
      authTagLength: this.params.tagLen,
    });
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([enc, tag]);
  }
}

class AeadOpener {
  constructor(params, key, iv) {
    this.params = params;
    this.key = key;
    this.iv = iv;
    this.seq = 0;
  }
  open(ciphertext, aad) {
    if (ciphertext.length < this.params.tagLen) throw new Error('AEAD 密文太短');
    const nonce = makeNonce(this.iv, this.seq);
    this.seq++;
    const ct = ciphertext.subarray(0, ciphertext.length - this.params.tagLen);
    const tag = ciphertext.subarray(ciphertext.length - this.params.tagLen);
    const dec = crypto.createDecipheriv(this.params.aead, this.key, nonce, {
      authTagLength: this.params.tagLen,
    });
    dec.setAAD(aad, { plaintextLength: ct.length });
    dec.setAuthTag(tag);
    try {
      return Buffer.concat([dec.update(ct), dec.final()]);
    } catch (e) {
      throw new Error(`AEAD 解密失败（seq=${this.seq - 1}）：${e.message}`);
    }
  }
}

function trafficKeys(params, secret) {
  return {
    key: hkdfExpandLabel(params.hash, secret, 'key', Buffer.alloc(0), params.keyLen),
    iv: hkdfExpandLabel(params.hash, secret, 'iv', Buffer.alloc(0), params.ivLen),
  };
}

// ---- 记录层 ------------------------------------------------------------------

// TLS record: type(1) + version(2) + length(2) + payload
// 加密记录：type 恒为 23，payload 是 AEAD(inner_plaintext + inner_type(1) + zero_padding)
class RecordLayer {
  constructor(socket) {
    this.sock = socket;
    this.recvBuf = Buffer.alloc(0);
    this.sealer = null; // 写方向的 AEAD（握手阶段用 client_handshake，之后切 client_app）
    this.opener = null; // 读方向的 AEAD
    this._pendingHandshake = Buffer.alloc(0); // 加解密后的握手消息缓冲（跨记录）
    this._pendingApp = [];
    this._pendingAppLen = 0;
    this._closed = false;
  }

  // 写一条明文 record（仅 ClientHello 用；之后一切走 sealer）
  writePlain(type, payload) {
    const hdr = Buffer.from([type, 0x03, 0x03, (payload.length >> 8) & 0xff, payload.length & 0xff]);
    this.sock.write(Buffer.concat([hdr, payload]));
  }

  // 写加密 record（type 是**内层**类型：22 握手 / 23 应用 / 21 alert）
  writeEncrypted(innerType, plaintext) {
    if (!this.sealer) throw new Error('sealer 未就绪');
    // inner = plaintext | inner_type(1) | zeroes ； 这里不塞额外 padding
    const inner = Buffer.concat([plaintext, Buffer.from([innerType])]);
    // AEAD 输出 = ciphertext | tag(16)
    const ctLen = inner.length + this.sealer.params.tagLen;
    const hdr = Buffer.from([CT_APPLICATION_DATA, 0x03, 0x03, (ctLen >> 8) & 0xff, ctLen & 0xff]);
    const ct = this.sealer.seal(inner, hdr);
    this.sock.write(Buffer.concat([hdr, ct]));
  }

  ingest(chunk) {
    this.recvBuf = this.recvBuf.length === 0 ? chunk : Buffer.concat([this.recvBuf, chunk]);
  }

  // 每次尝试从 recvBuf 里取一条完整的 record；不完整则返回 null。
  // 加密记录会在这里就地解开，把内层内容分派到 handshake / app / alert 三个缓冲。
  _readOneRecord() {
    if (this.recvBuf.length < 5) return null;
    const type = this.recvBuf[0];
    const len = this.recvBuf.readUInt16BE(3);
    if (this.recvBuf.length < 5 + len) return null;
    const hdr = this.recvBuf.subarray(0, 5);
    const payload = this.recvBuf.subarray(5, 5 + len);
    this.recvBuf = this.recvBuf.subarray(5 + len);

    if (type === CT_CHANGE_CIPHER_SPEC) {
      // TLS 1.3 里 CCS 是**兼容性 payload**，一个字节 0x01，忽略。
      return { kind: 'ccs' };
    }

    if (this.opener && type === CT_APPLICATION_DATA) {
      const inner = this.opener.open(payload, hdr);
      // 去掉尾部 0-padding，最后一个非零字节就是**内层类型**
      let i = inner.length - 1;
      while (i >= 0 && inner[i] === 0) i--;
      if (i < 0) throw new Error('AEAD 内层全零');
      const innerType = inner[i];
      const innerPayload = inner.subarray(0, i);
      return { kind: 'inner', innerType, payload: innerPayload };
    }

    // 明文（只应在 ServerHello / CCS / 部分 alert 上出现）
    return { kind: 'plain', type, payload };
  }

  // 消费所有可用 records，回调式：
  //   onHandshake(msgType, msgBody)  —— 解析后的一条完整握手消息（跨 record 拼合）
  //   onApp(chunk)                    —— 应用数据字节
  //   onAlert(level, desc)
  //   onCCS()                         —— 记录一下即可
  drain(callbacks) {
    for (;;) {
      const rec = this._readOneRecord();
      if (!rec) return;
      if (rec.kind === 'ccs') {
        callbacks.onCCS && callbacks.onCCS();
        continue;
      }
      let type, payload;
      if (rec.kind === 'inner') {
        type = rec.innerType;
        payload = rec.payload;
      } else {
        type = rec.type;
        payload = rec.payload;
      }
      if (type === CT_HANDSHAKE) {
        // 一条 record 可能含 0/1/多条握手消息，且一条握手消息可能跨 record
        this._pendingHandshake = Buffer.concat([this._pendingHandshake, payload]);
        for (;;) {
          if (this._pendingHandshake.length < 4) break;
          const hsLen = (this._pendingHandshake[1] << 16) |
                        (this._pendingHandshake[2] << 8) |
                        this._pendingHandshake[3];
          if (this._pendingHandshake.length < 4 + hsLen) break;
          const msgType = this._pendingHandshake[0];
          const msgBody = this._pendingHandshake.subarray(4, 4 + hsLen);
          const msgFull = this._pendingHandshake.subarray(0, 4 + hsLen); // 含头，转录用
          this._pendingHandshake = this._pendingHandshake.subarray(4 + hsLen);
          callbacks.onHandshake && callbacks.onHandshake(msgType, msgBody, msgFull);
        }
      } else if (type === CT_APPLICATION_DATA) {
        callbacks.onApp && callbacks.onApp(payload);
      } else if (type === CT_ALERT) {
        const level = payload[0];
        const desc = payload[1];
        callbacks.onAlert && callbacks.onAlert(level, desc);
      }
    }
  }
}

// ---- 证书链校验 --------------------------------------------------------------

let _rootCache = null;
// 拿证书的 SPKI（Subject Public Key Info）DER 字节。X509Certificate.publicKey 是
// KeyObject，导出 DER('spki') 即可 —— 用它比公钥比 fingerprint 稳妥：
// 同一个 root 可能在信任库里是自签、上送时是交叉签，指纹不同但公钥同。
function _pubKeyDER(cert) {
  return cert.publicKey.export({ type: 'spki', format: 'der' });
}
function _rootCerts() {
  if (_rootCache) return _rootCache;
  const arr = tls.rootCertificates.map((pem) => new crypto.X509Certificate(pem));
  const bySubject = new Map();
  const byPubKey = new Map(); // pubKey DER (hex) → 该 root（首个）
  for (const c of arr) {
    if (!bySubject.has(c.subject)) bySubject.set(c.subject, []);
    bySubject.get(c.subject).push(c);
    const pk = _pubKeyDER(c).toString('hex');
    if (!byPubKey.has(pk)) byPubKey.set(pk, c);
  }
  _rootCache = { all: arr, bySubject, byPubKey };
  return _rootCache;
}

// 走一遍链：hostname 命中 + 有效期 + 到达可信 anchor 前每层签名有效 + anchor 存在
//
// anchor 定义（顺序）：
//   (a) 链里某一层的指纹能在信任库里匹配到同一根 —— 服务端把根本身也发下来是常见做法
//       （交叉签场景下尤其：链末是 SSL.com ECC Root，其 issuer 是 AAA/Comodo，
//        但 ECC Root 自身**已经**是 Node 信任库里的自签根，指纹匹配就到底了）
//   (b) 链末的 issuer 与信任库里某根的 subject 相同，且用那根的公钥能验签
function verifyCertChain(hostname, derChain) {
  if (derChain.length === 0) throw new Error('cert chain 为空');
  const chain = derChain.map((der) => new crypto.X509Certificate(der));
  const roots = _rootCerts();
  const now = Date.now();

  // 1. hostname（叶子）
  if (!chain[0].checkHost(hostname)) {
    throw new Error(`证书 SAN 不匹配 ${hostname}（subject=${chain[0].subject}）`);
  }

  // 2. 有效期（每层）
  for (const c of chain) {
    if (Date.parse(c.validFrom) > now) throw new Error(`证书 ${c.subject} 尚未生效`);
    if (Date.parse(c.validTo) < now) throw new Error(`证书 ${c.subject} 已过期（${c.validTo}）`);
  }

  // 3. 找 anchor：从叶子往上，第一层的**公钥**能在信任库里匹配到即算到底
  //    比公钥而不比 fingerprint —— 交叉签证书（同一根的不同变体，subject/公钥同、
  //    但 issuer/签名不同，指纹自然不同）能被识别成同一 anchor。
  let anchorIdx = -1;
  for (let i = 0; i < chain.length; i++) {
    const pk = _pubKeyDER(chain[i]).toString('hex');
    if (roots.byPubKey.has(pk)) {
      anchorIdx = i;
      break;
    }
  }

  // 4a. anchor 就在 chain 里：验证 [0..anchorIdx] 每一层被上一层签
  if (anchorIdx >= 0) {
    for (let i = 0; i < anchorIdx; i++) {
      if (!chain[i].verify(chain[i + 1].publicKey)) {
        throw new Error(`证书 ${chain[i].subject} 不能被 ${chain[i + 1].subject} 验证`);
      }
    }
    return chain;
  }

  // 4b. anchor 在 chain 外：链末的 issuer 匹配某个 root，且该 root 能验签链末
  //     然后再验证 [0..last-1] 每一层
  const last = chain[chain.length - 1];
  const cands = roots.bySubject.get(last.issuer) || [];
  let anchor = null;
  for (const r of cands) {
    if (Date.parse(r.validFrom) > now || Date.parse(r.validTo) < now) continue;
    if (last.verify(r.publicKey)) {
      anchor = r;
      break;
    }
  }
  if (!anchor) {
    throw new Error(
      `链末 ${last.subject}（issuer=${last.issuer}）无匹配可信 root（且 chain 里也没有已知 root）`
    );
  }
  for (let i = 0; i < chain.length - 1; i++) {
    if (!chain[i].verify(chain[i + 1].publicKey)) {
      throw new Error(`证书 ${chain[i].subject} 不能被 ${chain[i + 1].subject} 验证`);
    }
  }
  return chain;
}

// 签名方案 → node crypto 签名参数
function verifyScheme(scheme, publicKey, data, sig) {
  switch (scheme) {
    case 0x0403: // ecdsa_secp256r1_sha256
      return crypto.verify('sha256', data, { key: publicKey, dsaEncoding: 'der' }, sig);
    case 0x0503: // ecdsa_secp384r1_sha384
      return crypto.verify('sha384', data, { key: publicKey, dsaEncoding: 'der' }, sig);
    case 0x0603: // ecdsa_secp521r1_sha512
      return crypto.verify('sha512', data, { key: publicKey, dsaEncoding: 'der' }, sig);
    case 0x0804: // rsa_pss_rsae_sha256
      return crypto.verify('sha256', data, {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      }, sig);
    case 0x0805:
      return crypto.verify('sha384', data, {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 48,
      }, sig);
    case 0x0806:
      return crypto.verify('sha512', data, {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 64,
      }, sig);
    case 0x0807: // ed25519
      return crypto.verify(null, data, publicKey, sig);
    case 0x0808: // ed448
      return crypto.verify(null, data, publicKey, sig);
    case 0x0809:
    case 0x080a:
    case 0x080b:
      // rsa_pss_pss_*：把 padding 参数换成 PSS 即可
      return crypto.verify(
        scheme === 0x0809 ? 'sha256' : scheme === 0x080a ? 'sha384' : 'sha512',
        data,
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: -1 },
        sig
      );
    case 0x0401:
    case 0x0501:
    case 0x0601:
      // rsa_pkcs1_sha256/384/512  RFC 8446 明说**不允许**在 CertificateVerify 里用
      throw new Error(`签名方案 0x${scheme.toString(16)} 在 TLS 1.3 CertificateVerify 中禁用`);
    default:
      throw new Error(`未知签名方案 0x${scheme.toString(16)}`);
  }
}

// CertificateVerify 的签名内容：64B 0x20 || label || 0x00 || Transcript-Hash
function certVerifyContent(hash, transcriptHashValue, isServer) {
  const label = isServer
    ? 'TLS 1.3, server CertificateVerify'
    : 'TLS 1.3, client CertificateVerify';
  return Buffer.concat([
    Buffer.alloc(64, 0x20),
    Buffer.from(label, 'ascii'),
    Buffer.from([0x00]),
    transcriptHashValue,
  ]);
}

// ---- 客户端握手 --------------------------------------------------------------

/**
 * TLS 1.3 客户端。
 *
 * 用法：
 *   const client = new TLS13Client({ socket, sni, clientHelloRecord, keys });
 *   await client.handshake();
 *   client.write(reqBytes);
 *   client.on('data', chunk => ...);
 *
 * clientHelloRecord: 完整 TLS record（含 5 字节头），由 browserfp 生成
 * keys:              browserfp.Keys 对象（含所有 key_share 组的私钥）
 * sni:               主机名（要与 record 里 SNI 一致；这里只做证书校验用）
 *
 * 返回的 client 是一个 Duplex 流：写入即被加密送出，读出即为服务端应用数据。
 */
class TLS13Client extends Duplex {
  constructor(opts) {
    super({ allowHalfOpen: false });
    this.sock = opts.socket;
    this.sni = opts.sni;
    this.clientHelloRecord = opts.clientHelloRecord;
    this.keys = opts.keys;
    this.alpn = opts.alpn || null; // 期望的 ALPN 单值；服务端选中的会写到 this.negotiatedAlpn
    this.negotiatedAlpn = null;

    this.rl = new RecordLayer(this.sock);
    this.state = 'init'; // init → wait_sh → wait_encrypted → done → app
    this._handshakeDone = null; // Promise 兑现器
    this._earlyAppData = []; // 握手结束前从对端来的（不该有，兜底）

    this.transcript = []; // 未加密握手消息 body（含 4B 头）串起来做 Transcript-Hash
    this.serverPubKey = null;
    this.serverCerts = [];

    // 从 clientHelloRecord 里抠出内层 ClientHello 消息（去掉 5B record header）
    // 用于把它加进 transcript
    const chBody = this.clientHelloRecord.subarray(5); // handshake_msg = type(1)+len(3)+body
    this.transcript.push(chBody);

    // 支持"CH 已经在外部写出、且部分回包已经预读"的场景（连接层需要 peek ServerHello
    // 才能决定分流到 TLS12 还是 TLS13）：pendingBuf 会在 handshake() 里被灌进 record 层。
    this._pendingBuf = opts.pendingBuf || null;
    // clientHelloAlreadySent：外层已 write 出去，handshake() 里就不能再写一次
    this._clientHelloAlreadySent = !!opts.clientHelloAlreadySent;

    this.sock.on('data', (chunk) => {
      try {
        this.rl.ingest(chunk);
        this._pump();
      } catch (e) {
        this._fail(e);
      }
    });
    this.sock.on('error', (e) => this._fail(e));
    this.sock.on('close', () => {
      if (this.state !== 'app' && this.state !== 'done') {
        this._fail(new Error('socket 早关（握手未完）'));
      } else {
        this.push(null);
      }
    });
  }

  handshake() {
    if (this._handshakeDone) return this._handshakeDone;
    this._handshakeDone = new Promise((resolve, reject) => {
      this._hsResolve = resolve;
      this._hsReject = reject;
    });
    if (!this._clientHelloAlreadySent) {
      // 送 ClientHello（完整 record，已含 header，直写 socket）
      this.sock.write(this.clientHelloRecord);
    }
    this.state = 'wait_sh';
    // 若外层已预读部分回包（分流场景），先塞进 record 层再驱动一次
    if (this._pendingBuf && this._pendingBuf.length > 0) {
      const b = this._pendingBuf;
      this._pendingBuf = null;
      setImmediate(() => {
        try { this.rl.ingest(b); this._pump(); } catch (e) { this._fail(e); }
      });
    }
    return this._handshakeDone;
  }

  _fail(e) {
    if (this._hsReject && (this.state !== 'app' && this.state !== 'done')) {
      const rej = this._hsReject;
      this._hsReject = null;
      this._hsResolve = null;
      rej(e);
    }
    this.destroy(e);
  }

  _pump() {
    this.rl.drain({
      onHandshake: (mt, body, full) => this._onHandshake(mt, body, full),
      onApp: (chunk) => {
        if (this.state === 'app') this.push(chunk);
        else this._earlyAppData.push(chunk);
      },
      onAlert: (level, desc) => {
        const lv = ALERT_LEVELS[level] || `level=${level}`;
        const ds = ALERT_DESCS[desc] || `desc=${desc}`;
        // close_notify 是正常关闭
        if (desc === 0) {
          if (this.state === 'app') this.push(null);
          return;
        }
        this._fail(new Error(`TLS alert：${lv} ${ds}`));
      },
      onCCS: () => {
        /* 兼容性 CCS 一律忽略 */
      },
    });
  }

  _onHandshake(msgType, body, full) {
    if (this.state === 'wait_sh') {
      if (msgType !== HS_SERVER_HELLO) {
        throw new Error(`期待 ServerHello，收到 msgType=${msgType}`);
      }
      this._processServerHello(body, full);
      return;
    }
    if (this.state === 'wait_encrypted') {
      // 已切到握手加密流；按类型分派
      switch (msgType) {
        case HS_ENCRYPTED_EXTENSIONS:
          this._processEncryptedExtensions(body, full);
          break;
        case HS_CERTIFICATE:
          this._processCertificate(body, full);
          break;
        case HS_COMPRESSED_CERTIFICATE:
          this._processCompressedCertificate(body, full);
          break;
        case HS_CERTIFICATE_REQUEST:
          throw new Error('本客户端不支持 client-auth（收到 CertificateRequest）');
        case HS_CERTIFICATE_VERIFY:
          this._processCertificateVerify(body, full);
          break;
        case HS_FINISHED:
          this._processServerFinished(body, full);
          break;
        default:
          // NewSessionTicket 等会在 done 状态出现，wait_encrypted 里不该有
          throw new Error(`加密握手阶段意外消息 type=${msgType}`);
      }
      return;
    }
    if (this.state === 'app' || this.state === 'done') {
      // 握手后：NewSessionTicket / KeyUpdate 允许
      if (msgType === HS_NEW_SESSION_TICKET) return; // 我们不做 resumption，丢弃
      if (msgType === HS_KEY_UPDATE) {
        // 服务端要求更新 traffic key。最小实现：抛错并断开。
        this._fail(new Error('收到 KeyUpdate 但本客户端未实现'));
        return;
      }
      throw new Error(`握手后意外握手消息 type=${msgType}`);
    }
  }

  _processServerHello(body, full) {
    // ServerHello:
    //   ProtocolVersion legacy_version(2) = 0x0303
    //   Random random(32)
    //   opaque legacy_session_id_echo<0..32>
    //   CipherSuite cipher_suite(2)
    //   uint8 legacy_compression_method = 0
    //   Extension extensions<6..2^16-1>
    const r = new Reader(body);
    r.u16(); // legacy_version
    const random = r.bytes(32);
    r.vec(1); // session_id echo（不校验）
    const cipherSuite = r.u16();
    r.u8(); // legacy_compression_method
    const extsRaw = r.vec(2);

    // HRR？
    if (Buffer.compare(random, HRR_RANDOM) === 0) {
      throw new Error(
        'HelloRetryRequest：服务端拒绝我方的 key_share 组。' +
          '本客户端暂未实现 HRR 重发（TODO：调 browserfp_rebuild_hrr）'
      );
    }

    // 解扩展：拿 server key_share + supported_versions
    let serverGroup = null;
    let serverPubBytes = null;
    let supportedVersion = null;
    const er = new Reader(extsRaw);
    while (er.remaining() > 0) {
      const t = er.u16();
      const d = er.vec(2);
      if (t === EXT_SUPPORTED_VERSIONS) {
        supportedVersion = new Reader(d).u16();
      } else if (t === EXT_KEY_SHARE) {
        const kr = new Reader(d);
        serverGroup = kr.u16();
        serverPubBytes = kr.vec(2);
      }
    }
    if (supportedVersion !== 0x0304) {
      throw new Error(`服务端不是 TLS 1.3（supported_versions=0x${(supportedVersion || 0).toString(16)}）`);
    }
    if (serverGroup === null) {
      throw new Error('ServerHello 缺 key_share 扩展');
    }

    this.cipherSuite = cipherSuite;
    this.params = cipherParams(cipherSuite);
    this.serverGroup = serverGroup;

    // 累进转录（用带 4B header 的整条消息）
    this.transcript.push(full);

    // 算共享密钥
    const shared = this.keys.derive(serverGroup, serverPubBytes);

    // TLS 1.3 key schedule §7.1
    const zero = Buffer.alloc(hashLen(this.params.hash));
    const early = hkdfExtract(this.params.hash, zero, zero);
    const derived1 = hkdfExpandLabel(this.params.hash, early, 'derived',
      transcriptHash(this.params.hash, []), hashLen(this.params.hash));
    const handshakeSecret = hkdfExtract(this.params.hash, derived1, shared);

    const chSh = this.transcript; // [ClientHello, ServerHello]
    const cHS = deriveSecret(this.params.hash, handshakeSecret, 'c hs traffic', chSh);
    const sHS = deriveSecret(this.params.hash, handshakeSecret, 's hs traffic', chSh);

    const cHSK = trafficKeys(this.params, cHS);
    const sHSK = trafficKeys(this.params, sHS);

    this.rl.sealer = new AeadSealer(this.params, cHSK.key, cHSK.iv);
    this.rl.opener = new AeadOpener(this.params, sHSK.key, sHSK.iv);

    // 存起来算 app 密钥用
    this.handshakeSecret = handshakeSecret;
    this.cHS = cHS;
    this.sHS = sHS;

    this.state = 'wait_encrypted';
    // 有些实现（BoringSSL/Golang）会在 ServerHello 之后紧跟一条 CCS（内容 0x01），
    // 兼容性 payload，_readOneRecord 已处理为 kind:'ccs' 忽略。
    this._pump();
  }

  _processEncryptedExtensions(body, full) {
    // 只从中拿 ALPN。其它扩展先不处理。
    const r = new Reader(body);
    const extsRaw = r.vec(2);
    const er = new Reader(extsRaw);
    while (er.remaining() > 0) {
      const t = er.u16();
      const d = er.vec(2);
      if (t === EXT_ALPN) {
        // ALPN vec<1>{ vec<1>{ protocol_name } }
        const ar = new Reader(d);
        const listRaw = ar.vec(2);
        const lr = new Reader(listRaw);
        const nameLen = lr.u8();
        const name = lr.bytes(nameLen).toString('ascii');
        this.negotiatedAlpn = name;
      }
    }
    this.transcript.push(full);
  }

  // RFC 8879 §4
  //   struct {
  //     CertificateCompressionAlgorithm algorithm;   /* uint16 */
  //     uint24 uncompressed_length;
  //     opaque compressed_certificate_message<1..2^24-1>;
  //   } CompressedCertificate;
  // 转录用**收到的 CompressedCertificate 原文**（§5），不是解压后的 Certificate。
  _processCompressedCertificate(body, full) {
    const r = new Reader(body);
    const algo = r.u16();
    const uncompLen = r.u24();
    const compressed = r.vec(3);
    let plain;
    if (algo === CERT_COMPRESS_ZLIB) {
      plain = zlib.inflateSync(compressed);
    } else if (algo === CERT_COMPRESS_BROTLI) {
      plain = zlib.brotliDecompressSync(compressed);
    } else if (algo === CERT_COMPRESS_ZSTD) {
      if (typeof zlib.zstdDecompressSync !== 'function') {
        throw new Error('服务端选了 zstd 压缩证书，但当前 Node 版本无 zlib.zstdDecompressSync');
      }
      plain = zlib.zstdDecompressSync(compressed);
    } else {
      throw new Error(`未知证书压缩算法 ${algo}`);
    }
    if (plain.length !== uncompLen) {
      throw new Error(
        `证书解压长度不符：声明 ${uncompLen}，实际 ${plain.length}`
      );
    }
    // 直接把解压后的 body 当作 Certificate body 处理，但 transcript 用 `full`（压缩原文）
    this._processCertificate(plain, full, /*alreadyPushed=*/ false);
  }

  _processCertificate(body, full, opts = false) {
    // Certificate:
    //   opaque certificate_request_context<0..255>;
    //   CertificateEntry certificate_list<0..2^24-1>;
    // CertificateEntry:
    //   opaque cert_data<1..2^24-1>;
    //   Extension extensions<0..2^16-1>;
    const r = new Reader(body);
    r.vec(1); // ctx (server 端为空)
    const listRaw = r.vec(3);
    const lr = new Reader(listRaw);
    const certs = [];
    while (lr.remaining() > 0) {
      const der = lr.vec(3);
      certs.push(Buffer.from(der)); // 复制一份，脱离 recvBuf 生命周期
      lr.vec(2); // extensions，忽略
    }
    if (certs.length === 0) throw new Error('Certificate 空');
    this.serverCerts = certs;
    this.serverX509 = verifyCertChain(this.sni, certs);
    this.serverPubKey = this.serverX509[0].publicKey;

    this.transcript.push(full);
  }

  _processCertificateVerify(body, full) {
    // CertificateVerify: scheme(2) + signature<2>
    const r = new Reader(body);
    const scheme = r.u16();
    const sig = r.vec(2);

    // 转录里**不包含** CertificateVerify 自身
    const th = transcriptHash(this.params.hash, this.transcript);
    const content = certVerifyContent(this.params.hash, th, true);
    if (!verifyScheme(scheme, this.serverPubKey, content, sig)) {
      throw new Error(`CertificateVerify 签名校验失败（scheme=0x${scheme.toString(16)}）`);
    }

    this.transcript.push(full);
  }

  _processServerFinished(body, full) {
    // Finished: verify_data (Hash.length)
    // finished_key = HKDF-Expand-Label(sHS, "finished", "", Hash.length)
    // verify_data = HMAC(finished_key, Transcript-Hash(CH..CertificateVerify))
    const finishedKey = hkdfExpandLabel(this.params.hash, this.sHS, 'finished',
      Buffer.alloc(0), hashLen(this.params.hash));
    const th = transcriptHash(this.params.hash, this.transcript);
    const expected = crypto.createHmac(this.params.hash, finishedKey).update(th).digest();
    if (Buffer.compare(body, expected) !== 0) {
      throw new Error('server Finished verify_data 不符');
    }

    // 转录追加 server Finished，为计算 app secrets 用
    this.transcript.push(full);

    // 送客户端 Finished：先算 verify_data
    const cFinKey = hkdfExpandLabel(this.params.hash, this.cHS, 'finished',
      Buffer.alloc(0), hashLen(this.params.hash));
    const cTh = transcriptHash(this.params.hash, this.transcript);
    const cVerify = crypto.createHmac(this.params.hash, cFinKey).update(cTh).digest();
    const cFinishedMsg = new Writer()
      .u8(HS_FINISHED)
      .u24(cVerify.length)
      .bytes(cVerify)
      .build();

    // 中间兼容性 CCS —— 一些中间盒会因为看不到明文 CCS 而抛掉后续；发一条无害
    this.rl.writePlain(CT_CHANGE_CIPHER_SPEC, Buffer.from([0x01]));
    // 客户端 Finished 仍走当前 client_handshake sealer
    this.rl.writeEncrypted(CT_HANDSHAKE, cFinishedMsg);
    this.transcript.push(cFinishedMsg);

    // 切到 application traffic
    const zero = Buffer.alloc(hashLen(this.params.hash));
    const derived2 = hkdfExpandLabel(this.params.hash, this.handshakeSecret, 'derived',
      transcriptHash(this.params.hash, []), hashLen(this.params.hash));
    const masterSecret = hkdfExtract(this.params.hash, derived2, zero);
    // c ap traffic / s ap traffic 用**server Finished 之前**的转录（RFC 8446 §7.1）
    const chSF = this.transcript.slice(0, this.transcript.length - 1); // 剔掉刚追加的 client Finished
    const cAP = deriveSecret(this.params.hash, masterSecret, 'c ap traffic', chSF);
    const sAP = deriveSecret(this.params.hash, masterSecret, 's ap traffic', chSF);
    const cAPK = trafficKeys(this.params, cAP);
    const sAPK = trafficKeys(this.params, sAP);
    this.rl.sealer = new AeadSealer(this.params, cAPK.key, cAPK.iv);
    this.rl.opener = new AeadOpener(this.params, sAPK.key, sAPK.iv);

    this.state = 'app';
    // 兑现 handshake()
    if (this._hsResolve) {
      const res = this._hsResolve;
      this._hsResolve = null;
      this._hsReject = null;
      res({ alpn: this.negotiatedAlpn, cipherSuite: this.cipherSuite });
    }
    // 若有握手阶段错帧的应用数据（不该出现），先吐出
    for (const c of this._earlyAppData) this.push(c);
    this._earlyAppData.length = 0;
  }

  // Duplex 侧
  _write(chunk, _enc, cb) {
    try {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      // 单条 record 最大 2^14 + tag —— 拆分
      const MAX = 16384;
      for (let i = 0; i < buf.length; i += MAX) {
        this.rl.writeEncrypted(CT_APPLICATION_DATA, buf.subarray(i, i + MAX));
      }
      cb();
    } catch (e) {
      cb(e);
    }
  }

  _read() {
    /* push 驱动 */
  }

  _final(cb) {
    try {
      // 发 close_notify
      if (this.rl.sealer) this.rl.writeEncrypted(CT_ALERT, Buffer.from([1, 0]));
      this.sock.end();
      cb();
    } catch (e) {
      cb(e);
    }
  }

  _destroy(err, cb) {
    try { this.sock.destroy(err || undefined); } catch (_) {}
    cb(err);
  }
}

// ---- 分流：读 ServerHello 决定 TLS 1.2 还是 1.3 ---------------------------
//
// 连接开建 → 送 ClientHello → 读第一条 record（应为 ServerHello）→ 看 legacy_version +
// supported_versions 扩展 → 1.3 走 TLS13Client；1.2 走 TLS12Client（都收下已预读的 bytes）。
// 服务端如果不发 ServerHello（发 alert 之类）由具体 client 抛错。
async function _peekServerHelloVersion(sock, timeout) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const to = setTimeout(() => { cleanup(); reject(new Error('peek ServerHello 超时')); }, timeout);
    function cleanup() {
      clearTimeout(to);
      sock.off('data', onData);
      sock.off('error', onErr);
      sock.off('end', onEnd);
    }
    function onData(c) {
      buf = buf.length === 0 ? c : Buffer.concat([buf, c]);
      if (buf.length < 5) return;
      if (buf[0] === CT_ALERT) {
        cleanup();
        return reject(new Error(`ServerHello 前收到 alert level=${buf[5] || '?'} desc=${buf[6] || '?'}`));
      }
      if (buf[0] !== CT_HANDSHAKE) {
        cleanup();
        return reject(new Error(`期待 handshake record，收到 type=${buf[0]}`));
      }
      const recLen = buf.readUInt16BE(3);
      if (buf.length < 5 + recLen) return;
      const payload = buf.subarray(5, 5 + recLen);
      if (payload.length < 4) { cleanup(); return reject(new Error('handshake msg header 不完整')); }
      const mt = payload[0];
      const mlen = (payload[1] << 16) | (payload[2] << 8) | payload[3];
      if (mt !== 2 /* ServerHello */) {
        cleanup();
        return reject(new Error(`期待 ServerHello，msg_type=${mt}`));
      }
      // ServerHello 通常一条 record 就够（几百字节）；rare 时跨 record 就多等一轮
      if (payload.length < 4 + mlen) return;
      const shBody = payload.subarray(4, 4 + mlen);
      let tlsVersion = 'TLS 1.2'; // 默认 1.2；有 supported_versions=0x0304 才是 1.3
      try {
        const r = new Reader(shBody);
        r.u16();          // legacy_version
        r.bytes(32);      // random
        r.vec(1);         // session_id
        r.u16();          // cipher_suite
        r.u8();           // legacy_compression_method
        if (r.remaining() > 0) {
          const extsRaw = r.vec(2);
          const er = new Reader(extsRaw);
          while (er.remaining() > 0) {
            const t = er.u16();
            const d = er.vec(2);
            if (t === 43 /* supported_versions */) {
              const sv = new Reader(d).u16();
              if (sv === 0x0304) tlsVersion = 'TLS 1.3';
            }
          }
        }
      } catch (e) {
        cleanup();
        return reject(new Error(`解析 ServerHello 失败：${e.message}`));
      }
      cleanup();
      resolve({ tlsVersion, pendingBuf: buf });
    }
    function onErr(e) { cleanup(); reject(e); }
    function onEnd() { cleanup(); reject(new Error('对端在 ServerHello 前关闭')); }
    sock.on('data', onData);
    sock.once('error', onErr);
    sock.once('end', onEnd);
  });
}

// ---- proxy 支持（HTTP CONNECT + SOCKS5） -----------------------------------
//
// 支持三种 scheme：
//   http://        HTTP CONNECT，含 Basic auth
//   https://       同上（proxy 侧仍按明文 CONNECT，供应商写法有些不一致）
//   socks5://      SOCKS5，含 username/password auth (RFC 1928 / RFC 1929)
//   socket://      outlook_automation 内部约定的 socks5 别名
//
// 传入其它 scheme 抛错，绝不静默降级直连。

function _basicAuth(user, pass) {
  return 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
}

// 通用入口：按 scheme 分派
async function _openViaProxy(proxyUrl, targetHost, targetPort, timeout) {
  const u = new URL(proxyUrl);
  const scheme = u.protocol.replace(/:$/, '');
  if (scheme === 'http' || scheme === 'https') {
    return _openViaHttpProxy(u, targetHost, targetPort, timeout);
  }
  if (scheme === 'socks5' || scheme === 'socks' || scheme === 'socket') {
    return _openViaSocks5(u, targetHost, targetPort, timeout);
  }
  throw new Error(`不支持的 proxy scheme：${scheme}（支持 http/https/socks5/socket）`);
}

async function _openViaHttpProxy(u, targetHost, targetPort, timeout) {
  const proxyHost = u.hostname;
  const proxyPort = u.port ? parseInt(u.port, 10) : (u.protocol === 'https:' ? 443 : 8080);
  // proxy 侧 TLS（HTTPS proxy）我们**不做** —— 生产场景绝大多数是明文 HTTP proxy 走内网到住宅出口
  if (u.protocol === 'https:') {
    // 允许 https:// 前缀作为语义标注，但仍按明文连接（很多供应商这么写）
    // 若需真 HTTPS-to-proxy，请开 issue
  }
  const sock = net.createConnection({ host: proxyHost, port: proxyPort });
  sock.setNoDelay(true);
  await new Promise((res, rej) => {
    const to = setTimeout(() => rej(new Error(`connect proxy ${proxyHost}:${proxyPort} 超时`)), timeout);
    sock.once('connect', () => { clearTimeout(to); res(); });
    sock.once('error', (e) => { clearTimeout(to); rej(e); });
  });

  const hdrLines = [
    `CONNECT ${targetHost}:${targetPort} HTTP/1.1`,
    `Host: ${targetHost}:${targetPort}`,
    'Proxy-Connection: keep-alive',
  ];
  if (u.username || u.password) {
    const user = decodeURIComponent(u.username || '');
    const pass = decodeURIComponent(u.password || '');
    hdrLines.push(`Proxy-Authorization: ${_basicAuth(user, pass)}`);
  }
  const req = Buffer.from(hdrLines.join('\r\n') + '\r\n\r\n', 'ascii');
  sock.write(req);

  // 读 CONNECT 响应到 \r\n\r\n
  const status = await new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const to = setTimeout(() => { cleanup(); reject(new Error('CONNECT 响应超时')); }, timeout);
    function cleanup() {
      clearTimeout(to);
      sock.off('data', onData);
      sock.off('error', onErr);
      sock.off('end', onEnd);
    }
    function onData(c) {
      buf = buf.length === 0 ? c : Buffer.concat([buf, c]);
      const idx = buf.indexOf('\r\n\r\n');
      if (idx < 0) return;
      const head = buf.slice(0, idx).toString('ascii');
      const rest = buf.slice(idx + 4);
      cleanup();
      const m = /^HTTP\/1\.[01]\s+(\d{3})\s*(.*)$/m.exec(head.split('\r\n')[0]);
      if (!m) return reject(new Error(`CONNECT status line 解析失败：${head.slice(0,120)}`));
      resolve({ code: parseInt(m[1], 10), text: m[2], head, rest });
    }
    function onErr(e) { cleanup(); reject(e); }
    function onEnd() { cleanup(); reject(new Error('proxy 在 CONNECT 响应完整前关闭')); }
    sock.on('data', onData);
    sock.once('error', onErr);
    sock.once('end', onEnd);
  });
  if (status.code < 200 || status.code >= 300) {
    sock.destroy();
    throw new Error(`proxy 拒绝 CONNECT：${status.code} ${status.text}`);
  }
  if (status.rest.length > 0) {
    // 极罕见：proxy 在 200 之后同一段 TCP 里塞了额外字节。CONNECT 语义上不该有，
    // 但若有必须回喂给下一层 —— 用 unshift 回到 socket 读缓冲。
    sock.unshift(status.rest);
  }
  return sock;
}

// SOCKS5（RFC 1928 + RFC 1929 用户名密码认证）
async function _openViaSocks5(u, targetHost, targetPort, timeout) {
  const proxyHost = u.hostname;
  const proxyPort = u.port ? parseInt(u.port, 10) : 1080;
  const user = u.username ? decodeURIComponent(u.username) : '';
  const pass = u.password ? decodeURIComponent(u.password) : '';

  const sock = net.createConnection({ host: proxyHost, port: proxyPort });
  sock.setNoDelay(true);
  await new Promise((res, rej) => {
    const to = setTimeout(() => rej(new Error(`connect SOCKS5 ${proxyHost}:${proxyPort} 超时`)), timeout);
    sock.once('connect', () => { clearTimeout(to); res(); });
    sock.once('error', (e) => { clearTimeout(to); rej(e); });
  });

  // 单 listener + waiter 模式：每次 readExact 只登记一个 { n, resolve, reject }，
  // data 事件按需喂饱当前 waiter。一开始就挂唯一一份 onData，跑完 SOCKS5 交接前
  // 移除，把 buf 剩余字节 unshift 回去（handshake 与 SOCKS5 响应可能在同一个 TCP 段）。
  // 这样避免了「一次一个 handler + 反复 attach/detach」在 unshift 场景下的重复触发。
  let buf = Buffer.alloc(0);
  let waiter = null;
  function tryFeed() {
    if (waiter && buf.length >= waiter.n) {
      const out = buf.subarray(0, waiter.n);
      buf = buf.subarray(waiter.n);
      const w = waiter;
      waiter = null;
      w.resolve(out);
    }
  }
  const onData = (c) => { buf = Buffer.concat([buf, c]); tryFeed(); };
  const onErr = (e) => { if (waiter) { const w = waiter; waiter = null; w.reject(e); } };
  const onEnd = () => { if (waiter) { const w = waiter; waiter = null; w.reject(new Error('SOCKS5 proxy 在响应前关闭')); } };
  sock.on('data', onData);
  sock.once('error', onErr);
  sock.once('end', onEnd);
  const toTimer = setTimeout(() => {
    if (waiter) { const w = waiter; waiter = null; w.reject(new Error('SOCKS5 读超时')); }
  }, timeout);

  function readExact(n) {
    return new Promise((resolve, reject) => {
      if (waiter) return reject(new Error('SOCKS5 内部错误：并发 readExact'));
      if (buf.length >= n) {
        const out = buf.subarray(0, n);
        buf = buf.subarray(n);
        return resolve(out);
      }
      waiter = { n, resolve, reject };
    });
  }

  function cleanupListeners() {
    clearTimeout(toTimer);
    sock.off('data', onData);
    sock.off('error', onErr);
    sock.off('end', onEnd);
    if (buf.length > 0) sock.unshift(buf); // 交接握手数据回给下一层
  }

  try {
    // 阶段 1：greeting（宣告支持的 auth 方法）
    //   VER=0x05, NAUTH=2 (no-auth + user/pass) —— 有账号也宣告 no-auth，兼容不校验的 proxy
    const authMethods = [0x00]; // no-auth
    if (user || pass) authMethods.push(0x02); // user/pass
    sock.write(Buffer.from([0x05, authMethods.length, ...authMethods]));
    const greetResp = await readExact(2);
    if (greetResp[0] !== 0x05) throw new Error(`SOCKS5 版本不符（收到 ${greetResp[0]}）`);
    const selectedMethod = greetResp[1];
    if (selectedMethod === 0xff) throw new Error('SOCKS5 proxy 拒绝所有 auth 方法');

    // 阶段 2：auth（若需要）
    if (selectedMethod === 0x02) {
      if (!user) throw new Error('SOCKS5 proxy 要求 user/pass 但 proxyUrl 未带凭据');
      const uBuf = Buffer.from(user, 'utf8');
      const pBuf = Buffer.from(pass, 'utf8');
      if (uBuf.length > 255 || pBuf.length > 255) {
        throw new Error('SOCKS5 user/pass 单个不能超过 255 字节');
      }
      const authReq = Buffer.concat([
        Buffer.from([0x01, uBuf.length]), uBuf,
        Buffer.from([pBuf.length]), pBuf,
      ]);
      sock.write(authReq);
      const authResp = await readExact(2);
      if (authResp[0] !== 0x01 || authResp[1] !== 0x00) {
        throw new Error(`SOCKS5 user/pass 认证失败（status=${authResp[1]}）`);
      }
    } else if (selectedMethod !== 0x00) {
      throw new Error(`SOCKS5 proxy 选了不支持的方法 0x${selectedMethod.toString(16)}`);
    }

    // 阶段 3：CONNECT 请求 —— 目标一律用 domain（0x03）避免我方 DNS 泄露
    const hostBuf = Buffer.from(targetHost, 'utf8');
    if (hostBuf.length > 255) throw new Error('SOCKS5 目标 host 超 255 字节');
    const req = Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
      hostBuf,
      Buffer.from([(targetPort >> 8) & 0xff, targetPort & 0xff]),
    ]);
    sock.write(req);

    // 响应头 4 字节：VER, REP, RSV, ATYP
    const head = await readExact(4);
    if (head[0] !== 0x05) throw new Error(`SOCKS5 响应版本不符 (${head[0]})`);
    const rep = head[1];
    if (rep !== 0x00) {
      const map = {
        1: 'general SOCKS server failure', 2: 'connection not allowed by ruleset',
        3: 'network unreachable', 4: 'host unreachable', 5: 'connection refused',
        6: 'TTL expired', 7: 'command not supported', 8: 'address type not supported',
      };
      throw new Error(`SOCKS5 CONNECT 失败：REP=${rep} (${map[rep] || 'unknown'})`);
    }
    const atyp = head[3];
    let addrLen;
    if (atyp === 0x01) addrLen = 4;
    else if (atyp === 0x04) addrLen = 16;
    else if (atyp === 0x03) {
      const lenBuf = await readExact(1);
      addrLen = lenBuf[0];
    } else {
      throw new Error(`SOCKS5 未知 ATYP ${atyp}`);
    }
    await readExact(addrLen + 2); // 消费 BND.ADDR + BND.PORT
  } catch (e) {
    cleanupListeners();
    try { sock.destroy(); } catch (_) {}
    throw e;
  }
  cleanupListeners();
  return sock;
}

// ---- 门面：一站式拨号 + 握手 -----------------------------------------------

/**
 * 用 browserfp profile 建一条 TLS 连接（1.2 / 1.3 自动分流）。
 *
 * opts:
 *   host      目标主机名（也当 SNI + cert 校验主机）
 *   port      端口（默认 443）
 *   profile   browserfp.Profile
 *   alpn      希望的 ALPN 单值（可选；实际协商结果在返回对象 .alpn 上）
 *   proxy     可选。HTTP CONNECT proxy URL，形如 `http://user:pass@proxy:8080`
 *   timeout   毫秒（socket 连接 + 握手总超时；默认 15000）
 *
 * 返回一个已握好手的 Duplex + 元数据：
 *   { stream, alpn, cipherSuite, tlsVersion, close() }
 */
async function connect(opts) {
  const port = opts.port || 443;
  const timeout = opts.timeout || 15000;
  const profile = opts.profile;
  if (!profile) throw new Error('缺 profile');

  let sock;
  if (opts.proxy) {
    sock = await _openViaProxy(opts.proxy, opts.host, port, timeout);
  } else {
    sock = net.createConnection({ host: opts.host, port });
    sock.setNoDelay(true);
    await new Promise((res, rej) => {
      const to = setTimeout(() => rej(new Error(`connect ${opts.host}:${port} 超时`)), timeout);
      sock.once('connect', () => { clearTimeout(to); res(); });
      sock.once('error', (e) => { clearTimeout(to); rej(e); });
    });
  }

  const keys = profile.keygen();
  let hello;
  try {
    hello = profile.clientHello(opts.host, keys);
  } catch (e) {
    keys.close();
    sock.destroy();
    throw e;
  }
  // 送 ClientHello（record 含 5B 头）
  sock.write(hello);

  // Peek 到 ServerHello 判断协议版本
  let peekRes;
  try {
    peekRes = await _peekServerHelloVersion(sock, timeout);
  } catch (e) {
    keys.close();
    sock.destroy();
    throw e;
  }

  let client;
  let info;
  if (peekRes.tlsVersion === 'TLS 1.3') {
    client = new TLS13Client({
      socket: sock,
      sni: opts.host,
      clientHelloRecord: hello,
      keys,
      alpn: opts.alpn,
      pendingBuf: peekRes.pendingBuf,
      clientHelloAlreadySent: true,
    });
    client.once('close', () => keys.close());
    client.once('error', () => keys.close());
    info = await Promise.race([
      client.handshake(),
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error(`handshake ${opts.host} 超时`)), timeout)
      ),
    ]);
    keys.close();
    info.tlsVersion = 'TLSv1.3';
  } else {
    // TLS 1.2：另起 client。ClientHello 已经送出去了；把它的转录 body 和 client_random 传过去。
    const { TLS12Client } = require('./tls12.js');
    const browserfp = require('./browserfp.js');
    // random(32B) 在 ClientHello 里的偏移 = recordHdr(5) + hsType(1) + hsLen(3) + legacy_ver(2) = 11
    const clientRandom = Buffer.from(hello.subarray(11, 43));
    const clientHelloBody = Buffer.from(hello.subarray(5));
    client = new TLS12Client({
      socket: sock,
      sni: opts.host,
      clientHelloBody,
      clientRandom,
      pendingBuf: peekRes.pendingBuf,
      kxKeygen: (group) => browserfp.kxKeygenGroup(group),
      kxDerive: (ctx, group, peer) => browserfp.kxDeriveGroup(ctx, group, peer),
      kxFree: (ctx) => browserfp.kxFreeCtx(ctx),
    });
    // TLS 1.2 的 keys（profile.keygen 那批）用不上，立即释放
    keys.close();
    client.once('close', () => {});
    info = await Promise.race([
      client.handshake(),
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error(`handshake ${opts.host} 超时`)), timeout)
      ),
    ]);
    info.tlsVersion = info.tlsVersion || 'TLSv1.2';
  }

  return {
    stream: client,
    alpn: info.alpn,
    cipherSuite: info.cipherSuite,
    tlsVersion: info.tlsVersion,
    close() { client.end(); },
  };
}

module.exports = {
  connect,
  TLS13Client,
  // 内部件也导出一些，便于测试与二次实现
  _internal: {
    RecordLayer,
    hkdfExpandLabel,
    deriveSecret,
    transcriptHash,
    trafficKeys,
    AeadSealer,
    AeadOpener,
    verifyCertChain,
    verifyScheme,
    Reader,
    Writer,
  },
};
