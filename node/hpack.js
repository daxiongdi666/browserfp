// HPACK (RFC 7541) —— HTTP/2 头压缩。
//
// 客户端场景需要完整解码（服务端可能用任意合法形式回给我们），但**编码端**只用
// 最简单的表示：`literal with incremental indexing`（0x40 引导）+ 已知头名索引静态表，
// 值原文明文（不 Huffman）。够用、可读、且服务端解码总能过。
//
// 伪装角度：HPACK 字节不出现在 Akamai/JA4 指纹里 —— 指纹取 SETTINGS/WINDOW_UPDATE/
// PRIORITY 三帧、外加 pseudo-header 顺序。头名怎么编，服务端看到的还是那几个头。

'use strict';

// ---- 静态表（RFC 7541 Appendix A） -----------------------------------------

const STATIC_TABLE = [
  null, // 索引从 1 起
  [':authority', ''],
  [':method', 'GET'],
  [':method', 'POST'],
  [':path', '/'],
  [':path', '/index.html'],
  [':scheme', 'http'],
  [':scheme', 'https'],
  [':status', '200'],
  [':status', '204'],
  [':status', '206'],
  [':status', '304'],
  [':status', '400'],
  [':status', '404'],
  [':status', '500'],
  ['accept-charset', ''],
  ['accept-encoding', 'gzip, deflate'],
  ['accept-language', ''],
  ['accept-ranges', ''],
  ['accept', ''],
  ['access-control-allow-origin', ''],
  ['age', ''],
  ['allow', ''],
  ['authorization', ''],
  ['cache-control', ''],
  ['content-disposition', ''],
  ['content-encoding', ''],
  ['content-language', ''],
  ['content-length', ''],
  ['content-location', ''],
  ['content-range', ''],
  ['content-type', ''],
  ['cookie', ''],
  ['date', ''],
  ['etag', ''],
  ['expect', ''],
  ['expires', ''],
  ['from', ''],
  ['host', ''],
  ['if-match', ''],
  ['if-modified-since', ''],
  ['if-none-match', ''],
  ['if-range', ''],
  ['if-unmodified-since', ''],
  ['last-modified', ''],
  ['link', ''],
  ['location', ''],
  ['max-forwards', ''],
  ['proxy-authenticate', ''],
  ['proxy-authorization', ''],
  ['range', ''],
  ['referer', ''],
  ['refresh', ''],
  ['retry-after', ''],
  ['server', ''],
  ['set-cookie', ''],
  ['strict-transport-security', ''],
  ['transfer-encoding', ''],
  ['user-agent', ''],
  ['vary', ''],
  ['via', ''],
  ['www-authenticate', ''],
];
const STATIC_LEN = STATIC_TABLE.length - 1;

// 名→静态索引（第一个匹配项；用于编码时挑名索引）
const STATIC_NAME_INDEX = new Map();
for (let i = 1; i <= STATIC_LEN; i++) {
  if (!STATIC_NAME_INDEX.has(STATIC_TABLE[i][0])) {
    STATIC_NAME_INDEX.set(STATIC_TABLE[i][0], i);
  }
}

// ---- Huffman 表（RFC 7541 Appendix B） --------------------------------------
// (符号 → [code, bitLen]) —— 生成解码树时用
const HUFFMAN_TABLE = [
/*   0 */ [0x1ff8, 13], [0x7fffd8, 23], [0xfffffe2, 28], [0xfffffe3, 28],
/*   4 */ [0xfffffe4, 28], [0xfffffe5, 28], [0xfffffe6, 28], [0xfffffe7, 28],
/*   8 */ [0xfffffe8, 28], [0xffffea, 24], [0x3ffffffc, 30], [0xfffffe9, 28],
/*  12 */ [0xfffffea, 28], [0x3ffffffd, 30], [0xfffffeb, 28], [0xfffffec, 28],
/*  16 */ [0xfffffed, 28], [0xfffffee, 28], [0xfffffef, 28], [0xffffff0, 28],
/*  20 */ [0xffffff1, 28], [0xffffff2, 28], [0x3ffffffe, 30], [0xffffff3, 28],
/*  24 */ [0xffffff4, 28], [0xffffff5, 28], [0xffffff6, 28], [0xffffff7, 28],
/*  28 */ [0xffffff8, 28], [0xffffff9, 28], [0xffffffa, 28], [0xffffffb, 28],
/*  32 */ [0x14, 6], [0x3f8, 10], [0x3f9, 10], [0xffa, 12],
/*  36 */ [0x1ff9, 13], [0x15, 6], [0xf8, 8], [0x7fa, 11],
/*  40 */ [0x3fa, 10], [0x3fb, 10], [0xf9, 8], [0x7fb, 11],
/*  44 */ [0xfa, 8], [0x16, 6], [0x17, 6], [0x18, 6],
/*  48 */ [0x0, 5], [0x1, 5], [0x2, 5], [0x19, 6],
/*  52 */ [0x1a, 6], [0x1b, 6], [0x1c, 6], [0x1d, 6],
/*  56 */ [0x1e, 6], [0x1f, 6], [0x5c, 7], [0xfb, 8],
/*  60 */ [0x7ffc, 15], [0x20, 6], [0xffb, 12], [0x3fc, 10],
/*  64 */ [0x1ffa, 13], [0x21, 6], [0x5d, 7], [0x5e, 7],
/*  68 */ [0x5f, 7], [0x60, 7], [0x61, 7], [0x62, 7],
/*  72 */ [0x63, 7], [0x64, 7], [0x65, 7], [0x66, 7],
/*  76 */ [0x67, 7], [0x68, 7], [0x69, 7], [0x6a, 7],
/*  80 */ [0x6b, 7], [0x6c, 7], [0x6d, 7], [0x6e, 7],
/*  84 */ [0x6f, 7], [0x70, 7], [0x71, 7], [0x72, 7],
/*  88 */ [0xfc, 8], [0x73, 7], [0xfd, 8], [0x1ffb, 13],
/*  92 */ [0x7fff0, 19], [0x1ffc, 13], [0x3ffc, 14], [0x22, 6],
/*  96 */ [0x7ffd, 15], [0x3, 5], [0x23, 6], [0x4, 5],
/* 100 */ [0x24, 6], [0x5, 5], [0x25, 6], [0x26, 6],
/* 104 */ [0x27, 6], [0x6, 5], [0x74, 7], [0x75, 7],
/* 108 */ [0x28, 6], [0x29, 6], [0x2a, 6], [0x7, 5],
/* 112 */ [0x2b, 6], [0x76, 7], [0x2c, 6], [0x8, 5],
/* 116 */ [0x9, 5], [0x2d, 6], [0x77, 7], [0x78, 7],
/* 120 */ [0x79, 7], [0x7a, 7], [0x7b, 7], [0x7ffe, 15],
/* 124 */ [0x7fc, 11], [0x3ffd, 14], [0x1ffd, 13], [0xffffffc, 28],
/* 128 */ [0xfffe6, 20], [0x3fffd2, 22], [0xfffe7, 20], [0xfffe8, 20],
/* 132 */ [0x3fffd3, 22], [0x3fffd4, 22], [0x3fffd5, 22], [0x7fffd9, 23],
/* 136 */ [0x3fffd6, 22], [0x7fffda, 23], [0x7fffdb, 23], [0x7fffdc, 23],
/* 140 */ [0x7fffdd, 23], [0x7fffde, 23], [0xffffeb, 24], [0x7fffdf, 23],
/* 144 */ [0xffffec, 24], [0xffffed, 24], [0x3fffd7, 22], [0x7fffe0, 23],
/* 148 */ [0xffffee, 24], [0x7fffe1, 23], [0x7fffe2, 23], [0x7fffe3, 23],
/* 152 */ [0x7fffe4, 23], [0x1fffdc, 21], [0x3fffd8, 22], [0x7fffe5, 23],
/* 156 */ [0x3fffd9, 22], [0x7fffe6, 23], [0x7fffe7, 23], [0xffffef, 24],
/* 160 */ [0x3fffda, 22], [0x1fffdd, 21], [0xfffe9, 20], [0x3fffdb, 22],
/* 164 */ [0x3fffdc, 22], [0x7fffe8, 23], [0x7fffe9, 23], [0x1fffde, 21],
/* 168 */ [0x7fffea, 23], [0x3fffdd, 22], [0x3fffde, 22], [0xfffff0, 24],
/* 172 */ [0x1fffdf, 21], [0x3fffdf, 22], [0x7fffeb, 23], [0x7fffec, 23],
/* 176 */ [0x1fffe0, 21], [0x1fffe1, 21], [0x3fffe0, 22], [0x1fffe2, 21],
/* 180 */ [0x7fffed, 23], [0x3fffe1, 22], [0x7fffee, 23], [0x7fffef, 23],
/* 184 */ [0xfffea, 20], [0x3fffe2, 22], [0x3fffe3, 22], [0x3fffe4, 22],
/* 188 */ [0x7ffff0, 23], [0x3fffe5, 22], [0x3fffe6, 22], [0x7ffff1, 23],
/* 192 */ [0x3ffffe0, 26], [0x3ffffe1, 26], [0xfffeb, 20], [0x7fff1, 19],
/* 196 */ [0x3fffe7, 22], [0x7ffff2, 23], [0x3fffe8, 22], [0x1ffffec, 25],
/* 200 */ [0x3ffffe2, 26], [0x3ffffe3, 26], [0x3ffffe4, 26], [0x7ffffde, 27],
/* 204 */ [0x7ffffdf, 27], [0x3ffffe5, 26], [0xfffff1, 24], [0x1ffffed, 25],
/* 208 */ [0x7fff2, 19], [0x1fffe3, 21], [0x3ffffe6, 26], [0x7ffffe0, 27],
/* 212 */ [0x7ffffe1, 27], [0x3ffffe7, 26], [0x7ffffe2, 27], [0xfffff2, 24],
/* 216 */ [0x1fffe4, 21], [0x1fffe5, 21], [0x3ffffe8, 26], [0x3ffffe9, 26],
/* 220 */ [0xffffffd, 28], [0x7ffffe3, 27], [0x7ffffe4, 27], [0x7ffffe5, 27],
/* 224 */ [0xfffec, 20], [0xfffff3, 24], [0xfffed, 20], [0x1fffe6, 21],
/* 228 */ [0x3fffe9, 22], [0x1fffe7, 21], [0x1fffe8, 21], [0x7ffff3, 23],
/* 232 */ [0x3fffea, 22], [0x3fffeb, 22], [0x1ffffee, 25], [0x1ffffef, 25],
/* 236 */ [0xfffff4, 24], [0xfffff5, 24], [0x3ffffea, 26], [0x7ffff4, 23],
/* 240 */ [0x3ffffeb, 26], [0x7ffffe6, 27], [0x3ffffec, 26], [0x3ffffed, 26],
/* 244 */ [0x7ffffe7, 27], [0x7ffffe8, 27], [0x7ffffe9, 27], [0x7ffffea, 27],
/* 248 */ [0x7ffffeb, 27], [0xffffffe, 28], [0x7ffffec, 27], [0x7ffffed, 27],
/* 252 */ [0x7ffffee, 27], [0x7ffffef, 27], [0x7fffff0, 27], [0x3ffffee, 26],
/* EOS */ [0x3fffffff, 30],
];

// 建 Huffman 解码树（比特位从 MSB 走）
function _buildHuffmanTree() {
  const root = { l: null, r: null, sym: -1 };
  for (let sym = 0; sym < 256; sym++) {
    const [code, len] = HUFFMAN_TABLE[sym];
    let node = root;
    for (let i = len - 1; i >= 0; i--) {
      const bit = (code >>> i) & 1;
      const key = bit ? 'r' : 'l';
      if (!node[key]) node[key] = { l: null, r: null, sym: -1 };
      node = node[key];
    }
    node.sym = sym;
  }
  return root;
}
const HUFFMAN_TREE = _buildHuffmanTree();

function huffmanDecode(input) {
  const out = [];
  let node = HUFFMAN_TREE;
  for (let i = 0; i < input.length; i++) {
    const b = input[i];
    for (let bit = 7; bit >= 0; bit--) {
      const one = (b >> bit) & 1;
      node = one ? node.r : node.l;
      if (!node) throw new Error('Huffman decode 走空');
      if (node.sym >= 0) {
        out.push(node.sym);
        node = HUFFMAN_TREE;
      }
    }
  }
  // 结尾未走完的位是 EOS 前缀填充，忽略
  return Buffer.from(out);
}

// 编码时也提供，尽管当前用不上（客户端全走明文）
function huffmanEncode(input) {
  const bits = [];
  for (const c of input) {
    const [code, len] = HUFFMAN_TABLE[c];
    for (let i = len - 1; i >= 0; i--) bits.push((code >>> i) & 1);
  }
  // 结尾用 EOS 前缀（全 1）填齐字节
  const pad = (8 - (bits.length % 8)) % 8;
  for (let i = 0; i < pad; i++) bits.push(1);
  const out = Buffer.alloc(bits.length / 8);
  for (let i = 0; i < out.length; i++) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
    out[i] = b;
  }
  return out;
}

// ---- 整数与字符串编解码 ----------------------------------------------------

// N-bit prefix integer（RFC 7541 §5.1）。返回 [value, newPos]
function decodeInt(buf, pos, N) {
  const mask = (1 << N) - 1;
  let value = buf[pos] & mask;
  pos++;
  if (value < mask) return [value, pos];
  let m = 0;
  for (;;) {
    if (pos >= buf.length) throw new Error('HPACK 整数越界');
    const b = buf[pos++];
    value += (b & 0x7f) * Math.pow(2, m);
    m += 7;
    if (!(b & 0x80)) break;
    if (m > 42) throw new Error('HPACK 整数太长');
  }
  return [value, pos];
}

// 写入 N-bit prefix 整数；prefix 是首字节高 (8-N) 位的固定值
function encodeInt(prefix, N, value, out) {
  const mask = (1 << N) - 1;
  if (value < mask) {
    out.push(prefix | value);
    return;
  }
  out.push(prefix | mask);
  value -= mask;
  while (value >= 128) {
    out.push((value & 0x7f) | 0x80);
    value = Math.floor(value / 128);
  }
  out.push(value);
}

function decodeString(buf, pos) {
  if (pos >= buf.length) throw new Error('HPACK 字符串越界');
  const huff = (buf[pos] & 0x80) !== 0;
  const [len, p1] = decodeInt(buf, pos, 7);
  if (p1 + len > buf.length) throw new Error(`HPACK 字符串长度越界 (${len})`);
  const raw = buf.subarray(p1, p1 + len);
  const val = huff ? huffmanDecode(raw) : Buffer.from(raw);
  return [val.toString('utf8'), p1 + len];
}

function encodeString(str, useHuffman, out) {
  const raw = Buffer.from(str, 'utf8');
  if (useHuffman) {
    const enc = huffmanEncode(raw);
    encodeInt(0x80, 7, enc.length, out);
    for (const b of enc) out.push(b);
  } else {
    encodeInt(0x00, 7, raw.length, out);
    for (const b of raw) out.push(b);
  }
}

// ---- 动态表 ----------------------------------------------------------------

class DynamicTable {
  constructor(maxSize) {
    this.entries = []; // [name, value, size]
    this.size = 0;
    this.maxSize = maxSize;
  }
  push(name, value) {
    const s = name.length + value.length + 32;
    if (s > this.maxSize) {
      // 单条超过 maxSize：整个表清空，条目不入表（RFC 7541 §4.4）
      this.entries.length = 0;
      this.size = 0;
      return;
    }
    while (this.size + s > this.maxSize && this.entries.length > 0) {
      const [, , es] = this.entries.pop();
      this.size -= es;
    }
    this.entries.unshift([name, value, s]);
    this.size += s;
  }
  resize(newMax) {
    this.maxSize = newMax;
    while (this.size > this.maxSize && this.entries.length > 0) {
      const [, , es] = this.entries.pop();
      this.size -= es;
    }
  }
  // dynamic 索引从 STATIC_LEN+1 起，最新的最小
  lookup(idx) {
    if (idx <= STATIC_LEN) return STATIC_TABLE[idx];
    const di = idx - STATIC_LEN - 1;
    if (di < 0 || di >= this.entries.length) {
      throw new Error(`HPACK 索引越界 idx=${idx}（static=${STATIC_LEN}, dyn=${this.entries.length}）`);
    }
    const [n, v] = this.entries[di];
    return [n, v];
  }
}

// ---- 解码器 ----------------------------------------------------------------

class Decoder {
  constructor(maxTableSize = 4096) {
    this.dyn = new DynamicTable(maxTableSize);
    this.maxAllowed = maxTableSize;
  }
  setMaxTableSize(max) {
    this.maxAllowed = max;
    if (this.dyn.maxSize > max) this.dyn.resize(max);
  }
  decode(block) {
    const out = [];
    let pos = 0;
    while (pos < block.length) {
      const b = block[pos];
      if (b & 0x80) {
        // 6.1 Indexed Header Field
        const [idx, p] = decodeInt(block, pos, 7);
        if (idx === 0) throw new Error('HPACK indexed 0 非法');
        out.push(this.dyn.lookup(idx));
        pos = p;
      } else if ((b & 0xc0) === 0x40) {
        // 6.2.1 Literal Header Field with Incremental Indexing
        const [idx, p1] = decodeInt(block, pos, 6);
        let name;
        let p = p1;
        if (idx === 0) {
          [name, p] = decodeString(block, p1);
        } else {
          name = this.dyn.lookup(idx)[0];
        }
        const [value, p2] = decodeString(block, p);
        this.dyn.push(name, value);
        out.push([name, value]);
        pos = p2;
      } else if ((b & 0xe0) === 0x20) {
        // 6.3 Dynamic Table Size Update
        const [newSize, p] = decodeInt(block, pos, 5);
        if (newSize > this.maxAllowed) {
          throw new Error(`HPACK 表 resize 超过允许上限 ${newSize} > ${this.maxAllowed}`);
        }
        this.dyn.resize(newSize);
        pos = p;
      } else {
        // 6.2.2 Literal without indexing / 6.2.3 Never indexed —— 二者对解码方等价
        const [idx, p1] = decodeInt(block, pos, 4);
        let name;
        let p = p1;
        if (idx === 0) {
          [name, p] = decodeString(block, p1);
        } else {
          name = this.dyn.lookup(idx)[0];
        }
        const [value, p2] = decodeString(block, p);
        out.push([name, value]);
        pos = p2;
      }
    }
    return out;
  }
}

// ---- 编码器 -----------------------------------------------------------------
//
// 客户端只用 6.2.1（literal with incremental indexing）：
//   - 头名在静态表里：`01 + name_index(6)` + value_string
//   - 头名不在静态表：`0x40` + name_string + value_string
// 值一律不 Huffman；服务端解码总能过。这样也不用维护发送端动态表 —— 用了
// `incremental indexing` 但**服务端**是否入表由服务端决定，我们发送端不需要跟踪。

function encodeHeaderBlock(headers) {
  const out = [];
  for (const [name, value] of headers) {
    const lc = name.toLowerCase();
    const nameIdx = STATIC_NAME_INDEX.get(lc) || 0;
    // literal with incremental indexing：首字节高 2 位 01
    encodeInt(0x40, 6, nameIdx, out);
    if (nameIdx === 0) {
      encodeString(lc, false, out);
    }
    encodeString(String(value), false, out);
  }
  return Buffer.from(out);
}

module.exports = {
  Decoder,
  encodeHeaderBlock,
  huffmanDecode,
  huffmanEncode,
  STATIC_TABLE,
  STATIC_NAME_INDEX,
  // 供单测
  _internal: { decodeInt, encodeInt, decodeString, encodeString, DynamicTable },
};
