// axios adapter —— 让 axios 全套 API 用 browserfp 的指纹出网。
//
// 用法（无 axios 依赖版本）：
//   const bfp = require('@fizzgate/browserfp');
//   const axios = bfp.axios({ ua: 'Mozilla/5.0 ...' });   // 返回一个 axios 实例
//   const res = await axios.get('https://...');
//
// 或者接管现有 axios 实例：
//   const axios = require('axios');
//   const inst = axios.create();
//   inst.defaults.adapter = bfp.axiosAdapter({ ua });      // 也可
//
// 差异：
//   1. baseURL / auth / params 等 axios 通用配置全支持（走 axios 侧处理）
//   2. adapter 承担实际出网 —— fetch 层已经处理 h2/h1、重定向、压缩解开
//   3. `transformResponse` 与 axios 默认行为一致：JSON 自动 parse

'use strict';

const { fetch } = require('./fetch.js');

// axios 用的 config 对象 → 我方 fetch init
function _configToInit(config) {
  const method = (config.method || 'get').toUpperCase();
  const headers = {};
  if (config.headers) {
    // axios 的 headers 可能有嵌套（common / get / post 等），axios 自己会合并；
    // adapter 收到的应该已经是扁平的一层
    for (const k of Object.keys(config.headers)) {
      const v = config.headers[k];
      if (v !== undefined && v !== null) headers[k] = String(v);
    }
  }
  let body;
  if (config.data !== undefined && config.data !== null &&
      method !== 'GET' && method !== 'HEAD') {
    if (typeof config.data === 'string' || Buffer.isBuffer(config.data)) {
      body = config.data;
    } else if (config.data instanceof URLSearchParams) {
      body = config.data.toString();
      if (!headers['content-type'] && !headers['Content-Type']) {
        headers['content-type'] = 'application/x-www-form-urlencoded;charset=utf-8';
      }
    } else {
      body = JSON.stringify(config.data);
      if (!headers['content-type'] && !headers['Content-Type']) {
        headers['content-type'] = 'application/json';
      }
    }
  }
  return {
    method,
    headers,
    body,
    timeout: config.timeout || 30000,
    maxRedirects: config.maxRedirects,
    redirect: config.maxRedirects === 0 ? 'manual' : 'follow',
    ua: config._bfp_ua,
    profile: config._bfp_profile,
  };
}

async function _adapterFn(config) {
  // 拼 URL（含 baseURL + params）
  let url = config.url || '';
  if (config.baseURL && !/^https?:\/\//i.test(url)) {
    url = config.baseURL.replace(/\/+$/, '') + '/' + url.replace(/^\/+/, '');
  }
  if (config.params && typeof config.params === 'object') {
    const qs = new URLSearchParams();
    for (const k of Object.keys(config.params)) {
      const v = config.params[k];
      if (Array.isArray(v)) for (const vv of v) qs.append(k, vv);
      else if (v !== undefined && v !== null) qs.append(k, v);
    }
    const q = qs.toString();
    if (q) url += (url.includes('?') ? '&' : '?') + q;
  }
  const init = _configToInit(config);
  const res = await fetch(url, init);
  const buf = await res.buffer();
  // 响应头 → axios 期望的 object（大小写不敏感就交给 axios 侧包一层）
  const headers = {};
  for (const [k, v] of res.headers) {
    const lc = k.toLowerCase();
    if (headers[lc] !== undefined) headers[lc] = headers[lc] + ', ' + v;
    else headers[lc] = v;
  }
  // 依 responseType 决定 data 形态
  const rt = config.responseType || 'json';
  let data;
  const text = buf.toString('utf8');
  if (rt === 'arraybuffer') {
    data = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  } else if (rt === 'stream') {
    throw new Error('axios responseType=stream 暂不支持');
  } else if (rt === 'text') {
    data = text;
  } else {
    // json / 默认：与 axios 默认 transformResponse 一致 —— 试 JSON.parse，失败原样
    try {
      data = JSON.parse(text);
    } catch (_) {
      data = text;
    }
  }
  return {
    data,
    status: res.status,
    statusText: res.statusText,
    headers,
    config,
    request: null,
  };
}

/**
 * axiosAdapter({ ua, profile })  → 一个 axios 兼容的 adapter 函数。
 * 传给 axios.create({ adapter }) 或 instance.defaults.adapter。
 */
function axiosAdapter(defaults = {}) {
  return async function browserfpAxiosAdapter(config) {
    config._bfp_ua = config._bfp_ua || defaults.ua;
    config._bfp_profile = config._bfp_profile || defaults.profile;
    return _adapterFn(config);
  };
}

/**
 * createAxios({ ua, profile, ...axiosOptions })
 *
 * 返回一个"用起来像 axios"的极简对象：get / post / put / delete / patch / request / head。
 * **不依赖 npm 上的 axios 包** —— 我们自己实现最小 API。也可以：
 *   const axios = require('axios').create({ adapter: bfp.axiosAdapter({ua}) })
 * 这样能拿到 axios 全套（interceptors、cancel token 等）。
 */
function createAxios(defaults = {}) {
  const inst = {
    defaults: { ...defaults },
    async request(config) {
      const merged = { ...defaults, ...config, headers: { ...(defaults.headers || {}), ...(config.headers || {}) } };
      return _adapterFn(merged);
    },
    get(url, config = {}) { return inst.request({ ...config, method: 'GET', url }); },
    delete(url, config = {}) { return inst.request({ ...config, method: 'DELETE', url }); },
    head(url, config = {}) { return inst.request({ ...config, method: 'HEAD', url }); },
    options(url, config = {}) { return inst.request({ ...config, method: 'OPTIONS', url }); },
    post(url, data, config = {}) { return inst.request({ ...config, method: 'POST', url, data }); },
    put(url, data, config = {}) { return inst.request({ ...config, method: 'PUT', url, data }); },
    patch(url, data, config = {}) { return inst.request({ ...config, method: 'PATCH', url, data }); },
  };
  // 把默认 ua/profile 塞进每个 config
  const wrapReq = inst.request;
  inst.request = async function (config) {
    return wrapReq({ _bfp_ua: defaults.ua, _bfp_profile: defaults.profile, ...config });
  };
  return inst;
}

module.exports = { createAxios, axiosAdapter, _adapterFn };
