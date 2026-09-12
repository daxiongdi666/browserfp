// @fizzgate/browserfp —— 浏览器指纹伪装的 Node.js 原生实现。
//
// 分层：
//   browserfp.js  FFI 绑定（识别 + 出指纹字节 + key_share 密钥）
//   tls13.js      原生 TLS 1.3 客户端（record 层 / HKDF / AEAD / 证书链 / Finished）
//   http1.js      HTTP/1.1
//   http2.js      HTTP/2（含 HPACK；对齐 profile 的 pseudo 顺序）
//   hpack.js      HPACK (RFC 7541)
//   fetch.js      WHATWG fetch 兼容层
//   axios.js      axios adapter
//
// 顶层 API：
//   const bfp = require('@fizzgate/browserfp');
//   const res = await bfp.fetch('https://tls.peet.ws/api/all', { ua: 'Mozilla/5.0 ...' });
//   const axios = bfp.axios({ ua });
//   const res2 = await axios.get('https://...');
//
// 底层想直接控就用：
//   bfp.select({ua})     取 profile
//   bfp.connect(opts)    拨号 + 握手
//   bfp.h2 / bfp.h1     直接发帧

'use strict';

const browserfp = require('./browserfp.js');
const tls13 = require('./tls13.js');
const http1 = require('./http1.js');
const http2 = require('./http2.js');
const { fetch, Response, Headers } = require('./fetch.js');
const { createAxios } = require('./axios.js');

module.exports = {
  ...browserfp,
  connect: tls13.connect,
  h1: http1,
  h2: http2,
  tls13,
  fetch,
  Response,
  Headers,
  axios: createAxios,
};
