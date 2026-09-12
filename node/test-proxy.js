// 端到端验证 HTTP CONNECT proxy：
//   1. 起一个本地 HTTP CONNECT proxy（含 Basic auth 校验）
//   2. 用 bfp.fetch 走它去打 tls.peet.ws
//   3. 验证：
//      (a) 请求真的走了 proxy（proxy 侧看到了 CONNECT）
//      (b) TLS 握手成功（能拿到 200 + JSON）
//      (c) 服务端识别到的 JA4 仍与 profile 一致（proxy 只做透传，不改 TLS）
//   4. 再验证一次错误路径：Basic auth 错误时收到 407
//
// 生产场景（outlook_automation）拿到的是 IPIPD/Proxy1024 的 HTTP proxy，
// 出口是住宅 IP —— 与本地 mock proxy 的语义一样，逻辑通就都通。

'use strict';

const net = require('net');
const http = require('http');
const assert = require('assert');
const bfp = require('./index.js');

const AUTH_USER = 'testuser';
const AUTH_PASS = 'testpass123';

// ---- 起本地 CONNECT proxy ---------------------------------------------------
// 用 Node 内置 http 服务器的 'connect' 事件即可 —— 语义是标准 HTTP CONNECT
function startProxy() {
  const server = http.createServer((req, res) => {
    // 普通 HTTP 请求（非 CONNECT）不给走
    res.writeHead(405);
    res.end('only CONNECT');
  });
  const state = { connects: [] };

  server.on('connect', (req, clientSocket, head) => {
    // Basic auth 校验
    const auth = req.headers['proxy-authorization'] || '';
    const m = /^Basic (.+)$/.exec(auth);
    let user = null, pass = null;
    if (m) {
      const dec = Buffer.from(m[1], 'base64').toString('utf8');
      const idx = dec.indexOf(':');
      if (idx >= 0) { user = dec.slice(0, idx); pass = dec.slice(idx + 1); }
    }
    if (user !== AUTH_USER || pass !== AUTH_PASS) {
      clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\n\r\n');
      clientSocket.end();
      return;
    }

    const [targetHost, targetPortStr] = req.url.split(':');
    const targetPort = parseInt(targetPortStr, 10) || 443;
    state.connects.push({ host: targetHost, port: targetPort, ts: Date.now() });

    const upstream = net.createConnection({ host: targetHost, port: targetPort }, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      // 有可能客户端把握手第一字节塞在了 CONNECT 请求的 body 里（RFC 允许，罕见）
      if (head && head.length) upstream.write(head);
      // 双工透传
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on('error', () => { try { clientSocket.destroy(); } catch (_) {} });
    clientSocket.on('error', () => { try { upstream.destroy(); } catch (_) {} });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, state, port });
    });
  });
}

function stopProxy(server) {
  return new Promise((res) => server.close(() => res()));
}

// ---- 跑 ---------------------------------------------------------------------
(async () => {
  bfp.load();
  const { server, state, port } = await startProxy();
  console.log(`[proxy] 本地 mock proxy 起在 127.0.0.1:${port}`);

  let pass = 0, fail = 0;
  async function t(name, fn) {
    try {
      await fn();
      console.log(`  ok  ${name}`);
      pass++;
    } catch (e) {
      console.error(`  FAIL ${name}\n       ${e.stack || e.message || e}`);
      fail++;
    }
  }

  const proxyUrl = `http://${AUTH_USER}:${AUTH_PASS}@127.0.0.1:${port}`;
  const badProxyUrl = `http://baduser:badpass@127.0.0.1:${port}`;

  await t('fetch tls.peet.ws 通过 proxy 拿到 200 + JSON', async () => {
    const res = await bfp.fetch('https://tls.peet.ws/api/all', {
      proxy: proxyUrl,
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
      timeout: 20000,
    });
    assert.strictEqual(res.status, 200);
    const j = await res.json();
    assert.ok(j.tls && j.tls.ja4, 'ja4 应在响应里');
    console.log(`         server 看到 JA4=${j.tls.ja4}`);
    console.log(`         server 看到 akamai=${j.http2.akamai_fingerprint}`);
    console.log(`         server 看到 IP=${j.ip}（应为 proxy 出口 IP，不是本机）`);
  });

  await t('proxy 侧记录了 CONNECT tls.peet.ws:443', () => {
    const seen = state.connects.filter(c => c.host === 'tls.peet.ws' && c.port === 443);
    assert.ok(seen.length >= 1, `proxy 应记录到至少 1 次 CONNECT，实际=${seen.length}`);
    console.log(`         proxy 侧记录到 ${seen.length} 次 CONNECT`);
  });

  await t('proxy 侧 Chrome profile 的 JA4 后两段仍与 profile 一致（代理是 L4 透传，不改 TLS）', async () => {
    const profile = bfp.selectUA('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36');
    const res = await bfp.fetch('https://tls.peet.ws/api/all', { proxy: proxyUrl, profile, timeout: 20000 });
    const j = await res.json();
    // profile.ja4 是 nosni 采集值，server 看到的第一段会带 d（sni）；后两段应逐字节相同
    const [, mine1, mine2] = profile.ja4.split('_');
    const [, srv1, srv2] = j.tls.ja4.split('_');
    assert.strictEqual(srv1, mine1, `JA4 中段应相同：${srv1} != ${mine1}`);
    assert.strictEqual(srv2, mine2, `JA4 尾段应相同：${srv2} != ${mine2}`);
  });

  await t('错误 Basic auth 收到 CONNECT 407 → 我方抛错而不是静默直连', async () => {
    let err = null;
    try {
      await bfp.fetch('https://tls.peet.ws/api/all', { proxy: badProxyUrl, timeout: 10000 });
    } catch (e) {
      err = e;
    }
    assert.ok(err, '应抛错');
    assert.ok(/CONNECT|407/.test(err.message), `错误应指明 CONNECT/407：${err.message}`);
  });

  await t('无代理时**不能**走 proxy（配置隔离）', async () => {
    // 打 peet.ws 直连应仍能成，不能被 proxy 拉走
    const before = state.connects.length;
    const res = await bfp.fetch('https://tls.peet.ws/api/all', { timeout: 20000 });
    assert.strictEqual(res.status, 200);
    const after = state.connects.length;
    assert.strictEqual(after, before, `无 proxy 参数时不应经过 proxy（before=${before} after=${after}）`);
  });

  await t('axios 也支持 proxy（走同一底层）', async () => {
    const ax = bfp.axios({ proxy: proxyUrl });
    const r = await ax.get('https://tls.peet.ws/api/all', { timeout: 20000 });
    assert.strictEqual(r.status, 200);
    assert.ok(r.data && r.data.tls && r.data.tls.ja4);
  });

  console.log(`\n${pass} passed, ${fail} failed`);
  await stopProxy(server);
  process.exit(fail === 0 ? 0 : 1);
})();
