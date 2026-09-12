// HTTP/1.1 承接层。挂在 TLS 1.3 Duplex 之上。
//
// 只做客户端要用的那点子事：写 request line + headers，读 status line + headers +
// body（Content-Length 或 chunked）。不做 keep-alive 复用 —— 指纹伪装天然一连一请求，
// 复用需要额外的连接追踪，且真浏览器多数已进 HTTP/2。
//
// 头字段大小写与顺序**按调用方给的原样**发出：伪装场景不能自作主张。

'use strict';

const CRLF = '\r\n';

function encodeRequest({ method, path, headers, body }) {
  const lines = [`${method} ${path} HTTP/1.1`];
  for (const [k, v] of headers) {
    // headers 是 [[k, v], ...] 数组以保序；不做 canonicalize
    lines.push(`${k}: ${v}`);
  }
  const head = Buffer.from(lines.join(CRLF) + CRLF + CRLF, 'ascii');
  if (!body || body.length === 0) return head;
  return Buffer.concat([head, Buffer.isBuffer(body) ? body : Buffer.from(body)]);
}

// 一路读到"两个连续 CRLF"，返回 { headerBuf, rest }
function _readHeaders(stream) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const idx = buf.indexOf('\r\n\r\n');
      if (idx >= 0) {
        stream.off('data', onData);
        stream.off('error', onErr);
        stream.off('end', onEnd);
        resolve({ headerBuf: buf.subarray(0, idx + 4), rest: buf.subarray(idx + 4) });
      }
    };
    const onErr = (e) => {
      stream.off('data', onData);
      stream.off('end', onEnd);
      reject(e);
    };
    const onEnd = () => {
      stream.off('data', onData);
      stream.off('error', onErr);
      reject(new Error('对端在 HTTP header 完整前关闭'));
    };
    stream.on('data', onData);
    stream.once('error', onErr);
    stream.once('end', onEnd);
  });
}

function parseHead(headerBuf) {
  const text = headerBuf.toString('ascii');
  // status line + N * header line + 空行
  const lines = text.split(CRLF);
  const statusLine = lines[0];
  // "HTTP/1.1 200 OK"
  const m = /^HTTP\/1\.(\d)\s+(\d{3})\s*(.*)$/.exec(statusLine);
  if (!m) throw new Error(`status line 解析失败：${statusLine}`);
  const status = parseInt(m[2], 10);
  const statusText = m[3];
  const headers = [];
  for (let i = 1; i < lines.length; i++) {
    const l = lines[i];
    if (l === '') break;
    const c = l.indexOf(':');
    if (c < 0) continue;
    const k = l.slice(0, c);
    const v = l.slice(c + 1).replace(/^\s+/, '');
    headers.push([k, v]);
  }
  return { status, statusText, headers };
}

function findHeader(headers, name) {
  const lc = name.toLowerCase();
  for (const [k, v] of headers) if (k.toLowerCase() === lc) return v;
  return null;
}

// 读定长 body
function _readN(stream, initial, n) {
  return new Promise((resolve, reject) => {
    const parts = [];
    let got = 0;
    if (initial.length > 0) {
      const take = Math.min(initial.length, n);
      parts.push(initial.subarray(0, take));
      got = take;
      // 若还剩，理论上不该发生（我们只在预读缓冲里进来），但兜个底
      if (got === n) return resolve(Buffer.concat(parts, got));
    }
    const onData = (chunk) => {
      const need = n - got;
      const take = Math.min(chunk.length, need);
      parts.push(chunk.subarray(0, take));
      got += take;
      if (got >= n) {
        stream.off('data', onData);
        stream.off('error', onErr);
        stream.off('end', onEnd);
        resolve(Buffer.concat(parts, got));
      }
    };
    const onErr = (e) => {
      stream.off('data', onData);
      stream.off('end', onEnd);
      reject(e);
    };
    const onEnd = () => {
      stream.off('data', onData);
      stream.off('error', onErr);
      // 对端提前关：接受已收到的
      if (got > 0) resolve(Buffer.concat(parts, got));
      else reject(new Error('body 未开始就关'));
    };
    stream.on('data', onData);
    stream.once('error', onErr);
    stream.once('end', onEnd);
  });
}

// 读 chunked body，返回 Buffer
function _readChunked(stream, initial) {
  return new Promise((resolve, reject) => {
    let buf = initial;
    const out = [];
    let state = 'size'; // size | data | trailer
    let dataLen = 0;

    function processBuf() {
      for (;;) {
        if (state === 'size') {
          const idx = buf.indexOf('\r\n');
          if (idx < 0) return; // 需要更多数据
          const line = buf.subarray(0, idx).toString('ascii');
          // 可能带 ";extension"
          const sizeStr = line.split(';')[0].trim();
          dataLen = parseInt(sizeStr, 16);
          if (!Number.isFinite(dataLen) || dataLen < 0) {
            done(new Error(`chunk size 非法：${line}`));
            return;
          }
          buf = buf.subarray(idx + 2);
          if (dataLen === 0) {
            state = 'trailer';
          } else {
            state = 'data';
          }
        } else if (state === 'data') {
          if (buf.length < dataLen + 2) return; // 需要更多数据
          out.push(Buffer.from(buf.subarray(0, dataLen)));
          buf = buf.subarray(dataLen + 2); // 跳过尾随 CRLF
          state = 'size';
        } else if (state === 'trailer') {
          // trailer 段直到空行
          const idx = buf.indexOf('\r\n');
          if (idx < 0) return;
          if (idx === 0) {
            // 空行 —— 完
            done(null, Buffer.concat(out));
            return;
          }
          buf = buf.subarray(idx + 2);
        }
      }
    }

    let finished = false;
    function done(err, res) {
      if (finished) return;
      finished = true;
      stream.off('data', onData);
      stream.off('error', onErr);
      stream.off('end', onEnd);
      if (err) reject(err);
      else resolve(res);
    }
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      try { processBuf(); } catch (e) { done(e); }
    };
    const onErr = (e) => done(e);
    const onEnd = () => done(new Error('对端在 chunked 结束前关'));

    stream.on('data', onData);
    stream.once('error', onErr);
    stream.once('end', onEnd);

    try { processBuf(); } catch (e) { done(e); }
  });
}

/**
 * 在已握手完的 TLS Duplex 上发一次 HTTP/1.1 请求，读完响应，返回：
 *   { status, statusText, headers, body: Buffer }
 *
 * 参数：
 *   stream   已握好手的 Duplex（tls13.connect 返回的 .stream）
 *   method   'GET' 'POST' 等
 *   path     '/'（已含 query）
 *   headers  [[k, v], ...] —— **保序保大小写**
 *   body     Buffer | string | undefined
 *   timeout  毫秒（整个请求周期）
 */
async function request({ stream, method, path, headers, body, timeout = 30000 }) {
  const req = encodeRequest({ method: method || 'GET', path: path || '/', headers: headers || [], body });

  const to = setTimeout(() => stream.destroy(new Error(`HTTP/1.1 请求超时`)), timeout);
  try {
    stream.write(req);
    const { headerBuf, rest } = await _readHeaders(stream);
    const { status, statusText, headers: respHeaders } = parseHead(headerBuf);

    // 决定 body 读法
    const cl = findHeader(respHeaders, 'content-length');
    const te = findHeader(respHeaders, 'transfer-encoding');
    let bodyBuf;
    if (te && te.toLowerCase().includes('chunked')) {
      bodyBuf = await _readChunked(stream, rest);
    } else if (cl !== null) {
      const n = parseInt(cl, 10);
      if (!Number.isFinite(n) || n < 0) throw new Error(`Content-Length 非法：${cl}`);
      bodyBuf = n === 0 ? Buffer.alloc(0) : await _readN(stream, rest, n);
    } else if (status === 204 || status === 304 || (method || 'GET').toUpperCase() === 'HEAD') {
      bodyBuf = Buffer.alloc(0);
    } else {
      // 无 CL 无 TE：读到 EOF
      bodyBuf = await new Promise((resolve, reject) => {
        const parts = [rest];
        stream.on('data', (c) => parts.push(c));
        stream.once('end', () => resolve(Buffer.concat(parts)));
        stream.once('error', reject);
      });
    }
    return { status, statusText, headers: respHeaders, body: bodyBuf };
  } finally {
    clearTimeout(to);
  }
}

module.exports = { request, encodeRequest, parseHead, findHeader };
