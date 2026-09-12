// WHATWG fetch 兼容层。
//
// 与浏览器 fetch 的差异（都是有意的）：
//   1. 多出一个 `ua` / `profile` 选项：伪装成谁。不给的话默认最新 Chrome 桌面。
//   2. Response.body 是 Node Buffer / Node ReadableStream，不是 WhatWG ReadableStream。
//      提供的 `.text()` `.json()` `.arrayBuffer()` `.buffer()` 与浏览器等价。
//   3. Cookie 不自动管：伪装场景更常见的是"外部塞 cookie"而不是 store。
//   4. 自动跟随重定向（默认 20 次上限）；`redirect: 'manual'` 关掉。

'use strict';

const url = require('url');
const zlib = require('zlib');
const browserfp = require('./browserfp.js');
const tls13 = require('./tls13.js');
const http1 = require('./http1.js');
const http2 = require('./http2.js');

const DEFAULT_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36';

// ----- Headers（大小写不敏感、可迭代） --------------------------------------

class Headers {
  constructor(init) {
    this._entries = []; // [[origName, value], ...]  按插入序
    if (init) {
      if (init instanceof Headers) {
        for (const [k, v] of init._entries) this.append(k, v);
      } else if (Array.isArray(init)) {
        for (const [k, v] of init) this.append(k, v);
      } else if (init && typeof init === 'object') {
        for (const k of Object.keys(init)) this.append(k, init[k]);
      }
    }
  }
  append(k, v) {
    this._entries.push([String(k), String(v)]);
  }
  set(k, v) {
    const lc = String(k).toLowerCase();
    let done = false;
    this._entries = this._entries.filter(([kk]) => {
      if (kk.toLowerCase() === lc) {
        if (!done) {
          done = true;
          return true; // 保留第一个，稍后改
        }
        return false;
      }
      return true;
    });
    for (const e of this._entries) {
      if (e[0].toLowerCase() === lc) {
        e[1] = String(v);
        return;
      }
    }
    this.append(k, v);
  }
  get(k) {
    const lc = String(k).toLowerCase();
    const vals = this._entries.filter(([kk]) => kk.toLowerCase() === lc).map(([, v]) => v);
    return vals.length === 0 ? null : vals.join(', ');
  }
  has(k) {
    const lc = String(k).toLowerCase();
    return this._entries.some(([kk]) => kk.toLowerCase() === lc);
  }
  delete(k) {
    const lc = String(k).toLowerCase();
    this._entries = this._entries.filter(([kk]) => kk.toLowerCase() !== lc);
  }
  entries() {
    return this._entries[Symbol.iterator]();
  }
  keys() {
    return this._entries.map(([k]) => k)[Symbol.iterator]();
  }
  values() {
    return this._entries.map(([, v]) => v)[Symbol.iterator]();
  }
  [Symbol.iterator]() {
    return this.entries();
  }
  raw() {
    return this._entries.slice();
  }
}

// ----- Response 对象 --------------------------------------------------------

class Response {
  constructor(body, init = {}) {
    this._body = body instanceof Buffer ? body : Buffer.from(body || '');
    this.status = init.status ?? 200;
    this.statusText = init.statusText || '';
    this.headers = init.headers instanceof Headers ? init.headers : new Headers(init.headers);
    this.url = init.url || '';
    this.redirected = init.redirected || false;
    this.ok = this.status >= 200 && this.status < 300;
    this.type = 'default';
    this._consumed = false;
  }
  _consume() {
    if (this._consumed) throw new Error('Response body 已消费');
    this._consumed = true;
    return this._body;
  }
  buffer() {
    return Promise.resolve(this._consume());
  }
  arrayBuffer() {
    const b = this._consume();
    return Promise.resolve(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
  }
  async text() {
    return this._consume().toString('utf8');
  }
  async json() {
    return JSON.parse(this._consume().toString('utf8'));
  }
}

// ----- 内容解压（Content-Encoding） -----------------------------------------

function decompress(headers, body) {
  const ce = (headers.get('content-encoding') || '').toLowerCase();
  if (!ce || ce === 'identity') return body;
  try {
    if (ce === 'gzip') return zlib.gunzipSync(body);
    if (ce === 'deflate') return zlib.inflateSync(body);
    if (ce === 'br') return zlib.brotliDecompressSync(body);
    if (ce === 'zstd' && typeof zlib.zstdDecompressSync === 'function') {
      return zlib.zstdDecompressSync(body);
    }
  } catch (e) {
    // 有些 server 声明 gzip 但发 raw deflate；宽容处理
    if (ce === 'gzip' || ce === 'deflate') {
      try { return zlib.inflateRawSync(body); } catch (_) {}
    }
  }
  return body; // 未知编码 —— 原样返回，调用方自己决定
}

// ----- 主 fetch 函数 ---------------------------------------------------------

/**
 * fetch(url, init)
 *
 * init:
 *   method                默认 'GET'
 *   headers               object | Headers | [[k,v],...]  —— 保序
 *   body                  Buffer | string | undefined
 *   ua                    伪装谁的 UA；不给默认 DEFAULT_UA
 *   profile               直接给 Profile 对象（比 ua 优先）
 *   redirect              'follow'（默认） | 'manual' | 'error'
 *   maxRedirects          默认 20
 *   timeout               整个请求超时 ms（默认 30000）
 *   decompress            默认 true —— 自动解 gzip/br
 *   verify                默认 true —— 关掉证书链校验（诊断用；生产不要）
 *
 * 返回 Response。
 */
async function fetch(urlStr, init = {}) {
  browserfp.load();
  const ua = init.ua || DEFAULT_UA;
  const profile = init.profile || browserfp.selectUA(ua);
  const method = (init.method || 'GET').toUpperCase();
  const redirect = init.redirect || 'follow';
  const maxRedirects = init.maxRedirects ?? 20;
  const timeout = init.timeout ?? 30000;
  const decompressResp = init.decompress !== false;

  let current = urlStr;
  let redirected = false;
  let hops = 0;
  const bodyBuf = init.body === undefined ? undefined :
    Buffer.isBuffer(init.body) ? init.body : Buffer.from(init.body);

  // 头合并：ua 自动注入（除非调用方覆盖）
  const userHeaders = new Headers(init.headers);
  if (!userHeaders.has('user-agent')) userHeaders.append('user-agent', ua);
  if (!userHeaders.has('accept')) userHeaders.append('accept', '*/*');
  if (!userHeaders.has('accept-encoding')) userHeaders.append('accept-encoding', 'gzip, deflate, br');
  if (bodyBuf && !userHeaders.has('content-length')) {
    userHeaders.append('content-length', String(bodyBuf.length));
  }

  for (;;) {
    const u = new url.URL(current);
    if (u.protocol !== 'https:') throw new Error(`只支持 https（当前 ${u.protocol}）`);
    const host = u.hostname;
    const port = u.port ? parseInt(u.port, 10) : 443;
    const pathAndQuery = u.pathname + (u.search || '');

    const conn = await tls13.connect({ host, port, profile, timeout });
    let res;
    try {
      if (conn.alpn === 'h2') {
        const { preface, pseudoOrder } = profile.h2Preface();
        // HTTP/2 里普通头必须全小写；pseudo 单独插入
        const h2Headers = [];
        for (const [k, v] of userHeaders.raw()) {
          if (k.toLowerCase() === 'host') continue; // h2 用 :authority
          h2Headers.push([k.toLowerCase(), v]);
        }
        res = await http2.request({
          stream: conn.stream,
          prefaceBytes: preface,
          pseudoOrder,
          method,
          scheme: 'https',
          authority: host + (port === 443 ? '' : `:${port}`),
          path: pathAndQuery,
          headers: h2Headers,
          body: bodyBuf,
          timeout,
        });
      } else {
        // HTTP/1.1 —— 保调用方传入的头**大小写**
        const h1Headers = [];
        let hasHost = false;
        for (const [k, v] of userHeaders.raw()) {
          if (k.toLowerCase() === 'host') hasHost = true;
          h1Headers.push([k, v]);
        }
        if (!hasHost) h1Headers.unshift(['Host', host + (port === 443 ? '' : `:${port}`)]);
        // 单请求：主动 Connection: close 让服务端在 body 后关流
        if (!userHeaders.has('connection')) h1Headers.push(['Connection', 'close']);
        res = await http1.request({
          stream: conn.stream,
          method,
          path: pathAndQuery,
          headers: h1Headers,
          body: bodyBuf,
          timeout,
        });
      }
    } finally {
      conn.close();
    }

    // 组装 Response
    const respHeaders = new Headers();
    for (const [k, v] of res.headers) respHeaders.append(k, v);
    const status = res.status;

    // 重定向
    const location = respHeaders.get('location');
    const isRedirect = [301, 302, 303, 307, 308].includes(status) && location;
    if (isRedirect && redirect === 'follow') {
      if (hops >= maxRedirects) throw new Error(`重定向超过 ${maxRedirects} 次`);
      hops++;
      redirected = true;
      const nextURL = new url.URL(location, current).toString();
      // 303 always GET；301/302 历史上也常降为 GET
      if (status === 303 || status === 301 || status === 302) {
        // POST → GET
        if (method !== 'GET' && method !== 'HEAD') {
          // 简化：改成 GET 且丢弃 body
          init = { ...init, method: 'GET', body: undefined };
        }
      }
      current = nextURL;
      continue;
    }
    if (isRedirect && redirect === 'error') {
      throw new Error(`不允许重定向：status=${status} location=${location}`);
    }

    const finalBody = decompressResp ? decompress(respHeaders, res.body) : res.body;
    return new Response(finalBody, {
      status,
      statusText: res.statusText || '',
      headers: respHeaders,
      url: current,
      redirected,
    });
  }
}

module.exports = { fetch, Response, Headers };
