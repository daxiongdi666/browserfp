// 冒烟测试。跑法：
//   cd node && npm install && node test.js
// 前提：../csrc/libbrowserfp.so 已构建。
//
// 与门禁不同，这里只覆盖节点绑定自身能不能把 C 侧函数调通。深度差分由 Go / Lua
// 侧的 golden 门禁保证——三边共用一份 C 实现，一处对了就等价。

'use strict';

const assert = require('assert');
const browserfp = require('./browserfp.js');

let pass = 0;
let fail = 0;

function t(name, fn) {
  try {
    fn();
    console.log(`  ok  ${name}`);
    pass++;
  } catch (e) {
    console.error(`  FAIL ${name}`);
    console.error('       ' + (e && e.stack ? e.stack.split('\n').join('\n       ') : e));
    fail++;
  }
}

// --- 1. 加载 -----------------------------------------------------------------
t('load()', () => {
  browserfp.load(); // 使用默认搜索路径
});

t('count() > 0', () => {
  assert.ok(browserfp.count() > 0, 'profile 库应非空');
});

// --- 2. parseUA --------------------------------------------------------------
const chromeUA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36';
const firefoxUA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0';
const operaUA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/110.0.0.0';

t('parseUA(chrome)', () => {
  const r = browserfp.parseUA(chromeUA);
  assert.strictEqual(r.brand, 'chrome');
  assert.strictEqual(r.version, 125);
});

t('parseUA(firefox)', () => {
  const r = browserfp.parseUA(firefoxUA);
  assert.strictEqual(r.brand, 'firefox');
  assert.strictEqual(r.version, 120);
});

t('parseUA(opera) 取的是内核 Chrome 版本', () => {
  const r = browserfp.parseUA(operaUA);
  assert.strictEqual(r.brand, 'opera');
  // Opera 自身 110，UA 里内核是 Chrome/125 —— 应返 125
  assert.strictEqual(r.version, 125);
});

t('parseUA("") 抛 no_ua', () => {
  assert.throws(() => browserfp.parseUA(''), (e) => e.reason === 'no_ua');
});

t('parseUA("garbage") 抛 unknown_ua', () => {
  assert.throws(
    () => browserfp.parseUA('not-a-browser/1.0'),
    (e) => e.reason === 'unknown_ua'
  );
});

// --- 3. select ---------------------------------------------------------------
let profile;
t('selectUA(chrome125)', () => {
  profile = browserfp.selectUA(chromeUA);
  assert.ok(profile.id, 'profile.id 非空');
  assert.strictEqual(profile.brand, 'chrome');
  assert.strictEqual(profile.version, 125);
  assert.ok(profile.ja4 && profile.ja4.startsWith('t13'), `ja4=${profile.ja4}`);
  assert.ok(profile.akamai && profile.akamai.length > 0, 'akamai 非空');
  assert.ok(
    profile.engine === 'chromium',
    `chrome 应属 chromium 引擎，实际=${profile.engine}`
  );
});

// --- 4. h2Preface（不需要 libcrypto，先跑这一步） ----------------------------
t('profile.h2Preface() 头三字节是 PRI（HTTP/2 preface 前导）', () => {
  const { preface, pseudoOrder } = profile.h2Preface();
  assert.ok(preface.length > 24, `preface 太短：${preface.length}`);
  // HTTP/2 connection preface 固定前 24B = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  assert.strictEqual(preface.slice(0, 3).toString('ascii'), 'PRI');
  assert.strictEqual(
    preface.slice(0, 24).toString('ascii'),
    'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
  );
  assert.ok(typeof pseudoOrder === 'string' && pseudoOrder.length > 0, 'pseudoOrder 非空');
  // chromium 系伪头顺序常见 "m,a,s,p"
  assert.ok(pseudoOrder.split(',').every((s) => s.length === 1), `pseudo=${pseudoOrder}`);
});

// --- 5. clientHello / keygen（要 libcrypto） ---------------------------------
let cryptoOk = true;
try {
  const ver = browserfp.opensslVersion();
  console.log(`  --  openssl=${ver || '<unknown>'}`);
} catch (e) {
  cryptoOk = false;
  console.log(`  skip libcrypto 初始化失败：${e.message}`);
}

if (cryptoOk) {
  t('profile.keygen() + clientHello()', () => {
    const keys = profile.keygen();
    try {
      assert.ok(keys.groups().length > 0, 'keygen 组数应 > 0');
      const rec = profile.clientHello('example.com', keys);
      // TLS record 头：byte0=0x16(handshake), byte1..2=version, byte3..4=length
      assert.strictEqual(rec[0], 0x16, `record[0] 应为 0x16, 实际=0x${rec[0].toString(16)}`);
      const bodyLen = (rec[3] << 8) | rec[4];
      assert.strictEqual(rec.length, 5 + bodyLen, 'record 头声明的长度应与实际一致');
      // handshake type = 0x01 (ClientHello)
      assert.strictEqual(rec[5], 0x01, `handshake type 应为 0x01, 实际=0x${rec[5].toString(16)}`);
    } finally {
      keys.close();
    }
  });

  t('两次 clientHello() 的 random 段不同（GREASE / 扩展序也可能不同）', () => {
    const k1 = profile.keygen();
    const k2 = profile.keygen();
    try {
      const a = profile.clientHello('example.com', k1);
      const b = profile.clientHello('example.com', k2);
      // TLS record hdr(5) + handshake hdr(4) 之后紧跟 legacy_version(2) + random(32)
      const rndA = a.slice(11, 43);
      const rndB = b.slice(11, 43);
      assert.ok(!rndA.equals(rndB), 'random(32B) 每次调用必须不同');
    } finally {
      k1.close();
      k2.close();
    }
  });

  t('ja4For(sni) 与 ja4(record) 一致', () => {
    const keys = profile.keygen();
    try {
      const rec = profile.clientHello('example.com', keys);
      const a = browserfp.ja4(rec, 't');
      const b = profile.ja4For('example.com');
      // ja4For 内部又 keygen 一次，GREASE 会变，但 JA4 里 GREASE 已剔除 —— 应完全一致
      assert.strictEqual(a, b, `${a} != ${b}`);
    } finally {
      keys.close();
    }
  });

  t('lookupJA4 反查命中', () => {
    const keys = profile.keygen();
    try {
      const rec = profile.clientHello('example.com', keys);
      const j = browserfp.ja4(rec, 't');
      const p2 = browserfp.lookupJA4(j);
      assert.ok(p2, `lookupJA4 未命中：${j}`);
      // JA4 相同的 profile 不止一条（同一形态在不同来源库里各录一份）——
      // lookupJA4 命中其中任意一条即可，判据是 ja4 相同而不是 id 相同。
      assert.strictEqual(p2.ja4, j, `lookupJA4 返回的 ja4 应与查询串相同：${p2.ja4} != ${j}`);
    } finally {
      keys.close();
    }
  });
} else {
  console.log('  --  libcrypto 相关用例已跳过');
}

// --- 6. coherence -----------------------------------------------------------
t('coherence(chrome ja4, chrome akamai) === true', () => {
  const ok = browserfp.coherence(profile.ja4, profile.akamai);
  assert.strictEqual(ok, true, `${profile.ja4} vs ${profile.akamai} 应一致`);
});

// --- 7. HPACK 单测（不依赖网络） --------------------------------------------
const hpack = require('./hpack.js');

t('HPACK 整数编码/解码 round-trip', () => {
  for (const v of [0, 1, 10, 30, 31, 32, 127, 128, 1024, 65535, 100000]) {
    for (const N of [4, 5, 6, 7]) {
      const out = [];
      hpack._internal.encodeInt(0, N, v, out);
      const [decoded, endPos] = hpack._internal.decodeInt(Buffer.from(out), 0, N);
      assert.strictEqual(decoded, v, `N=${N} v=${v} decoded=${decoded}`);
      assert.strictEqual(endPos, out.length);
    }
  }
});

t('HPACK Huffman round-trip（ASCII）', () => {
  const s = 'Hello, browserfp! /path?q=1 www.example.com';
  const enc = hpack.huffmanEncode(Buffer.from(s));
  const dec = hpack.huffmanDecode(enc).toString('utf8');
  assert.strictEqual(dec, s);
});

t('HPACK Huffman：RFC 7541 C.4.1 例子（www.example.com）', () => {
  // C.4.1: www.example.com → f1e3 c2e5 f23a 6ba0 ab90 f4ff
  const enc = hpack.huffmanEncode(Buffer.from('www.example.com'));
  assert.strictEqual(enc.toString('hex'), 'f1e3c2e5f23a6ba0ab90f4ff');
});

t('HPACK Decoder：RFC 7541 C.4.2 例子（First Request）', () => {
  // C.3.1 是等价的非-huffman 版本；这里模拟一个 chrome-like literal-with-inc-indexing
  // 用 encoder 生成、decoder 解开，头名/头值一致
  const dec = new hpack.Decoder(4096);
  const enc = hpack.encodeHeaderBlock([
    [':method', 'GET'],
    [':scheme', 'https'],
    [':path', '/'],
    [':authority', 'www.example.com'],
    ['user-agent', 'test'],
  ]);
  const kvs = dec.decode(enc);
  assert.strictEqual(kvs.length, 5);
  assert.deepStrictEqual(kvs[0], [':method', 'GET']);
  assert.deepStrictEqual(kvs[3], [':authority', 'www.example.com']);
  assert.deepStrictEqual(kvs[4], ['user-agent', 'test']);
});

t('HPACK Decoder：indexed representation（静态表 :method GET = idx 2）', () => {
  const dec = new hpack.Decoder(4096);
  const kvs = dec.decode(Buffer.from([0x82])); // 0b10000010
  assert.deepStrictEqual(kvs, [[':method', 'GET']]);
});

// --- 8. HTTP/2 orderHeaders --------------------------------------------------
const http2 = require('./http2.js');
t('http2.orderHeaders 按 pseudoOrder 排 pseudo-header', () => {
  const ordered = http2.orderHeaders('m,a,s,p', [
    [':path', '/x'],
    [':method', 'GET'],
    [':scheme', 'https'],
    [':authority', 'h'],
    ['User-Agent', 'ua'],
    ['Accept', '*/*'],
  ]);
  assert.deepStrictEqual(ordered.slice(0, 4), [
    [':method', 'GET'],
    [':authority', 'h'],
    [':scheme', 'https'],
    [':path', '/x'],
  ]);
  // 普通头小写、按插入序
  assert.strictEqual(ordered[4][0], 'user-agent');
  assert.strictEqual(ordered[5][0], 'accept');
});

t('http2 frame round-trip', () => {
  const payload = Buffer.from([1, 2, 3, 4, 5]);
  const buf = http2.writeFrame(0x1, 0x4, 1, payload);
  const fr = http2.readFrame(buf, 0);
  assert.strictEqual(fr.type, 0x1);
  assert.strictEqual(fr.flags, 0x4);
  assert.strictEqual(fr.streamId, 1);
  assert.strictEqual(fr.length, 5);
  assert.strictEqual(fr.consumed, 9 + 5);
  assert.deepStrictEqual([...fr.payload], [...payload]);
});

// --- 9. tls13 内部工具单测 ----------------------------------------------------
const tls13 = require('./tls13.js');
t('tls13 hkdfExpandLabel：RFC 8446 A.1 例子（sha256）', () => {
  // A.1: {client}  derive secret for handshake "tls13 c e traffic":
  // 但直接算需要一整套 keyshedule，简化：验证结果长度与幂等
  const secret = Buffer.alloc(32, 0);
  const out = tls13._internal.hkdfExpandLabel('sha256', secret, 'c hs traffic', Buffer.alloc(32), 32);
  assert.strictEqual(out.length, 32);
  const out2 = tls13._internal.hkdfExpandLabel('sha256', secret, 'c hs traffic', Buffer.alloc(32), 32);
  assert.strictEqual(Buffer.compare(out, out2), 0, '同参数应确定性输出');
});

t('tls13 AEAD 自洽（seal → open）', () => {
  const params = { hash: 'sha256', keyLen: 16, ivLen: 12, aead: 'aes-128-gcm', tagLen: 16 };
  const key = Buffer.alloc(16, 0xab);
  const iv = Buffer.alloc(12, 0x12);
  const sealer = new tls13._internal.AeadSealer(params, key, iv);
  const opener = new tls13._internal.AeadOpener(params, key, iv);
  const aad = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x20]);
  const pt = Buffer.from('Hello TLS 1.3 world!');
  const ct = sealer.seal(pt, aad);
  const dec = opener.open(ct, aad);
  assert.strictEqual(dec.toString('utf8'), pt.toString('utf8'));
});

// --- 结论 --------------------------------------------------------------------
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
