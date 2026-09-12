// HTTP/2 承接层（RFC 7540）—— 挂在 TLS 1.3 Duplex 之上。
//
// 与真浏览器"完全一致"的部分（Akamai h2 指纹必须命中）：
//   1. 连接开场字节（PREFACE + SETTINGS + WINDOW_UPDATE + PRIORITY）**逐字节**采用
//      browserfp 生成的字节，不重排、不修改。
//   2. 请求 HEADERS 帧里 pseudo-header 的**顺序**按 profile.pseudoOrder 排。
//      chromium 系是 "m,a,s,p" = :method, :authority, :scheme, :path；gecko 是
//      "m,p,a,s"；WebKit 有另一种。
//
// 不做的部分：
//   - PUSH_PROMISE 接收（浏览器都关了；SETTINGS_ENABLE_PUSH=0）
//   - 客户端流控真正意义上的滑窗（收到 WINDOW_UPDATE 就允许发下一块 DATA；本客户端
//     的请求 body 也就 GET 空 + POST 几 KB，一次性发完的极小场景不用做累计）
//   - 长连接多请求复用（一连接一请求；重连成本用完就走）

'use strict';

const { Decoder, encodeHeaderBlock } = require('./hpack.js');

// 帧类型
const FRAME_DATA = 0x0;
const FRAME_HEADERS = 0x1;
const FRAME_PRIORITY = 0x2;
const FRAME_RST_STREAM = 0x3;
const FRAME_SETTINGS = 0x4;
const FRAME_PUSH_PROMISE = 0x5;
const FRAME_PING = 0x6;
const FRAME_GOAWAY = 0x7;
const FRAME_WINDOW_UPDATE = 0x8;
const FRAME_CONTINUATION = 0x9;

// flags
const F_END_STREAM = 0x1;
const F_ACK = 0x1;
const F_END_HEADERS = 0x4;
const F_PADDED = 0x8;
const F_PRIORITY = 0x20;

const ERR_CODE = {
  0: 'NO_ERROR', 1: 'PROTOCOL_ERROR', 2: 'INTERNAL_ERROR',
  3: 'FLOW_CONTROL_ERROR', 4: 'SETTINGS_TIMEOUT', 5: 'STREAM_CLOSED',
  6: 'FRAME_SIZE_ERROR', 7: 'REFUSED_STREAM', 8: 'CANCEL',
  9: 'COMPRESSION_ERROR', 10: 'CONNECT_ERROR', 11: 'ENHANCE_YOUR_CALM',
  12: 'INADEQUATE_SECURITY', 13: 'HTTP_1_1_REQUIRED',
};

function readFrame(buf, pos) {
  if (buf.length - pos < 9) return null;
  const length = (buf[pos] << 16) | (buf[pos + 1] << 8) | buf[pos + 2];
  const type = buf[pos + 3];
  const flags = buf[pos + 4];
  const streamId = buf.readUInt32BE(pos + 5) & 0x7fffffff;
  if (buf.length - pos < 9 + length) return null;
  const payload = buf.subarray(pos + 9, pos + 9 + length);
  return { length, type, flags, streamId, payload, consumed: 9 + length };
}

function writeFrame(type, flags, streamId, payload) {
  const len = payload.length;
  const buf = Buffer.alloc(9 + len);
  buf[0] = (len >> 16) & 0xff;
  buf[1] = (len >> 8) & 0xff;
  buf[2] = len & 0xff;
  buf[3] = type;
  buf[4] = flags;
  buf.writeUInt32BE(streamId >>> 0, 5);
  if (len) payload.copy(buf, 9);
  return buf;
}

// pseudo-header 顺序编码，如 "m,a,s,p"
const PSEUDO_MAP = {
  m: ':method',
  p: ':path',
  a: ':authority',
  s: ':scheme',
};

function orderHeaders(pseudoOrder, headers) {
  // 拆开 pseudo-header 与普通头
  const byName = new Map();
  const normal = [];
  for (const [k, v] of headers) {
    const lc = k.toLowerCase();
    if (lc.startsWith(':')) {
      byName.set(lc, v);
    } else {
      // HTTP/2 里普通头必须全小写（RFC 7540 §8.1.2）
      normal.push([lc, v]);
    }
  }
  const ordered = [];
  for (const ch of pseudoOrder.split(',')) {
    const name = PSEUDO_MAP[ch];
    if (name && byName.has(name)) {
      ordered.push([name, byName.get(name)]);
      byName.delete(name);
    }
  }
  // profile 里没列的 pseudo（如果有）按出现顺序补
  for (const [k, v] of byName) ordered.push([k, v]);
  for (const p of normal) ordered.push(p);
  return ordered;
}

/**
 * 在已握手完的 TLS Duplex 上跑一次 HTTP/2 GET/POST（一连接一请求），拿到 response。
 *
 * 参数：
 *   stream        TLS Duplex（tls13.connect 返回的 .stream）
 *   prefaceBytes  browserfp 生成的 h2 开场字节（含 PREFACE + SETTINGS + WU + PRIORITY）
 *   pseudoOrder   如 "m,a,s,p"，来自 profile.h2Preface().pseudoOrder
 *   method / path / authority / scheme
 *   headers       [[name, value], ...] 非 pseudo 头
 *   body          Buffer / string / undefined
 *   timeout       毫秒
 *
 * 返回：{ status, headers, body: Buffer }
 */
async function request({
  stream,
  prefaceBytes,
  pseudoOrder,
  method,
  scheme,
  authority,
  path,
  headers,
  body,
  timeout = 30000,
}) {
  // 1. 发我方 h2 开场（原封不动）
  stream.write(prefaceBytes);

  // 状态
  const decoder = new Decoder(4096);
  const streamId = 1; // 客户端第一个流

  const respHeaders = [];
  const respBodyChunks = [];
  let respStatus = null;
  let respBytes = 0;
  let ended = false;
  let error = null;
  let ourStreamEnded = false;

  // HEADERS 跨帧：CONTINUATION
  let headerBufFor = null; // { streamId, block: [Buffer], endStream }
  let firstServerSettingsSeen = false;

  const done = new Promise((resolve, reject) => {
    var _res = resolve, _rej = reject;
    var complete = false;
    var to = setTimeout(() => {
      if (complete) return;
      complete = true;
      _rej(new Error('HTTP/2 请求超时'));
    }, timeout);

    function finish(err) {
      if (complete) return;
      complete = true;
      clearTimeout(to);
      stream.off('data', onData);
      stream.off('end', onEnd);
      stream.off('error', onErr);
      if (err) return _rej(err);
      _res({
        status: respStatus,
        headers: respHeaders.filter(([k]) => !k.startsWith(':')),
        body: Buffer.concat(respBodyChunks, respBytes),
      });
    }

    // 帧到达处理器
    function processFrame(fr) {
      // GOAWAY / RST_STREAM
      if (fr.type === FRAME_GOAWAY) {
        const errCode = fr.payload.readUInt32BE(4);
        if (errCode !== 0) {
          const debug = fr.payload.subarray(8).toString('utf8').slice(0, 200);
          finish(new Error(`GOAWAY error=${ERR_CODE[errCode] || errCode} debug=${debug}`));
        }
        return;
      }
      if (fr.type === FRAME_RST_STREAM && fr.streamId === streamId) {
        const errCode = fr.payload.readUInt32BE(0);
        finish(new Error(`RST_STREAM error=${ERR_CODE[errCode] || errCode}`));
        return;
      }
      if (fr.type === FRAME_SETTINGS) {
        if (fr.flags & F_ACK) return; // 服务端对我方 SETTINGS 的 ACK
        // 服务端 SETTINGS：我们简化处理 —— 立刻 ACK，不真正应用
        // （SETTINGS_HEADER_TABLE_SIZE 变化需要按 §6.3 处理，MVP 略）
        stream.write(writeFrame(FRAME_SETTINGS, F_ACK, 0, Buffer.alloc(0)));
        if (!firstServerSettingsSeen) {
          firstServerSettingsSeen = true;
          // 服务端 SETTINGS 到齐，我方可以送 HEADERS 了
          sendRequest();
        }
        return;
      }
      if (fr.type === FRAME_PING) {
        if (!(fr.flags & F_ACK)) {
          stream.write(writeFrame(FRAME_PING, F_ACK, 0, fr.payload));
        }
        return;
      }
      if (fr.type === FRAME_WINDOW_UPDATE) {
        // 服务端给我方增窗；MVP 场景 body 小，不需要精算。
        return;
      }
      if (fr.type === FRAME_PRIORITY) return;

      if (fr.type === FRAME_HEADERS) {
        if (fr.streamId !== streamId) return; // 我们只关注自己的 stream
        // 去掉 padding / priority 部分
        let p = 0;
        let padLen = 0;
        if (fr.flags & F_PADDED) {
          padLen = fr.payload[p++];
        }
        if (fr.flags & F_PRIORITY) {
          p += 5; // stream_dep(4) + weight(1)
        }
        const block = fr.payload.subarray(p, fr.payload.length - padLen);
        if (fr.flags & F_END_HEADERS) {
          // 一次到齐
          const kvs = decoder.decode(block);
          for (const kv of kvs) {
            respHeaders.push(kv);
            if (kv[0] === ':status' && respStatus === null) {
              respStatus = parseInt(kv[1], 10);
            }
          }
        } else {
          headerBufFor = { block: [block] };
        }
        if (fr.flags & F_END_STREAM) ended = true;
        if (ended && respStatus !== null) return finish(null);
        return;
      }
      if (fr.type === FRAME_CONTINUATION) {
        if (!headerBufFor) throw new Error('孤立的 CONTINUATION');
        headerBufFor.block.push(fr.payload);
        if (fr.flags & F_END_HEADERS) {
          const full = Buffer.concat(headerBufFor.block);
          const kvs = decoder.decode(full);
          for (const kv of kvs) {
            respHeaders.push(kv);
            if (kv[0] === ':status' && respStatus === null) {
              respStatus = parseInt(kv[1], 10);
            }
          }
          headerBufFor = null;
        }
        return;
      }
      if (fr.type === FRAME_DATA) {
        if (fr.streamId !== streamId) return;
        let p = 0;
        let padLen = 0;
        if (fr.flags & F_PADDED) {
          padLen = fr.payload[p++];
        }
        const dat = fr.payload.subarray(p, fr.payload.length - padLen);
        if (dat.length > 0) {
          const c = Buffer.from(dat);
          respBodyChunks.push(c);
          respBytes += c.length;
          // 简易流控：每收 32KB 补一次 WINDOW_UPDATE，避免服务端因窗见底停发
          if (respBytes > 0 && respBytes % 32768 < c.length) {
            const wu = Buffer.alloc(4);
            wu.writeUInt32BE(65535, 0);
            stream.write(writeFrame(FRAME_WINDOW_UPDATE, 0, streamId, wu));
            stream.write(writeFrame(FRAME_WINDOW_UPDATE, 0, 0, wu)); // 连接级
          }
        }
        if (fr.flags & F_END_STREAM) {
          ended = true;
          if (respStatus !== null) return finish(null);
        }
        return;
      }
    }

    function sendRequest() {
      const allHeaders = orderHeaders(pseudoOrder || 'm,a,s,p', [
        [':method', method || 'GET'],
        [':authority', authority],
        [':scheme', scheme || 'https'],
        [':path', path || '/'],
        ...headers,
      ]);
      const hpackBlock = encodeHeaderBlock(allHeaders);

      let flags = F_END_HEADERS;
      const hasBody = body && body.length > 0;
      if (!hasBody) flags |= F_END_STREAM;
      stream.write(writeFrame(FRAME_HEADERS, flags, streamId, hpackBlock));
      if (hasBody) {
        const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
        // 简化：一次性发；不切帧（MVP 场景 body 通常 < 16KB）
        stream.write(writeFrame(FRAME_DATA, F_END_STREAM, streamId, buf));
      }
      ourStreamEnded = true;
    }

    let recvBuf = Buffer.alloc(0);
    function onData(chunk) {
      try {
        recvBuf = recvBuf.length === 0 ? chunk : Buffer.concat([recvBuf, chunk]);
        for (;;) {
          const fr = readFrame(recvBuf, 0);
          if (!fr) break;
          recvBuf = recvBuf.subarray(fr.consumed);
          processFrame(fr);
          if (complete) return;
        }
      } catch (e) {
        finish(e);
      }
    }
    function onEnd() {
      if (!complete) {
        if (ended && respStatus !== null) return finish(null);
        finish(new Error('对端在 h2 响应完整前关闭'));
      }
    }
    function onErr(e) {
      finish(e);
    }
    stream.on('data', onData);
    stream.once('end', onEnd);
    stream.once('error', onErr);
  });

  return done;
}

module.exports = { request, writeFrame, readFrame, orderHeaders };
