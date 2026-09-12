// SOCKS5 端到端：本地 mock socks5 server + user/pass auth，走它打 tls.peet.ws，
// 验证指纹依旧命中且认证正确。
//
// 同时验证 socket:// 别名（outlook_automation 内部约定）与 socks5:// 都能通。

'use strict';

const net = require('net');
const assert = require('assert');
const bfp = require('./index.js');

const AUTH_USER = 'sockstest';
const AUTH_PASS = 'socks-pw-42';

// ---- 极简 SOCKS5 server（RFC 1928/1929）------------------------------------
function startSocks5() {
  const state = { connects: [], authAttempts: 0, authFails: 0 };
  const server = net.createServer((client) => {
    let buf = Buffer.alloc(0);
    let stage = 'greet'; // greet | auth | connect | pipe

    function readAtLeast(n) {
      return new Promise((resolve) => {
        function check() {
          if (buf.length >= n) {
            const out = buf.subarray(0, n);
            buf = buf.subarray(n);
            client.off('data', onData);
            resolve(out);
          }
        }
        function onData(c) { buf = Buffer.concat([buf, c]); check(); }
        client.on('data', onData);
        check();
      });
    }

    (async () => {
      try {
        // greet: VER(1) NAUTH(1) methods(NAUTH)
        let h = await readAtLeast(2);
        const ver = h[0], nauth = h[1];
        if (ver !== 5) return client.destroy();
        await readAtLeast(nauth);
        // 强制要求 user/pass
        client.write(Buffer.from([0x05, 0x02]));

        // auth: VER(1)=1 ULEN(1) UNAME PLEN(1) PASSWD
        state.authAttempts++;
        h = await readAtLeast(2);
        if (h[0] !== 1) return client.destroy();
        const uLen = h[1];
        const uBuf = await readAtLeast(uLen);
        h = await readAtLeast(1);
        const pLen = h[0];
        const pBuf = await readAtLeast(pLen);
        const gotUser = uBuf.toString('utf8');
        const gotPass = pBuf.toString('utf8');
        if (gotUser !== AUTH_USER || gotPass !== AUTH_PASS) {
          state.authFails++;
          client.write(Buffer.from([0x01, 0x01])); // failure
          return client.destroy();
        }
        client.write(Buffer.from([0x01, 0x00])); // success

        // CONNECT: VER(1) CMD(1) RSV(1) ATYP(1) ...
        h = await readAtLeast(4);
        if (h[0] !== 5 || h[1] !== 1) return client.destroy();
        const atyp = h[3];
        let host, portBuf;
        if (atyp === 1) { // ipv4
          const addr = await readAtLeast(4);
          host = Array.from(addr).join('.');
          portBuf = await readAtLeast(2);
        } else if (atyp === 3) {
          const lb = await readAtLeast(1);
          const hb = await readAtLeast(lb[0]);
          host = hb.toString('utf8');
          portBuf = await readAtLeast(2);
        } else if (atyp === 4) { // ipv6
          await readAtLeast(16);
          portBuf = await readAtLeast(2);
          host = '::';
        } else {
          return client.destroy();
        }
        const port = (portBuf[0] << 8) | portBuf[1];
        state.connects.push({ host, port, ts: Date.now() });

        // 连上游 + 透传
        const upstream = net.createConnection({ host, port }, () => {
          // 回 SUCCESS，BND.ADDR=0.0.0.0, BND.PORT=0
          client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          // 若 buf 里还有先送来的字节（罕见），提前塞 upstream
          if (buf.length) { upstream.write(buf); buf = Buffer.alloc(0); }
          upstream.pipe(client);
          client.pipe(upstream);
        });
        upstream.on('error', () => { try { client.destroy(); } catch (_) {} });
        client.on('error', () => { try { upstream.destroy(); } catch (_) {} });
      } catch (_) {
        try { client.destroy(); } catch (_) {}
      }
    })();
  });
  return new Promise((res) => server.listen(0, '127.0.0.1', () => {
    res({ server, state, port: server.address().port });
  }));
}
function stopServer(s) { return new Promise((r) => s.close(() => r())); }

// ---- 跑 ---------------------------------------------------------------------
(async () => {
  bfp.load();
  const { server, state, port } = await startSocks5();
  console.log(`[socks5] 本地 mock socks5 起在 127.0.0.1:${port}`);

  let pass = 0, fail = 0;
  async function t(name, fn) {
    try { await fn(); console.log(`  ok  ${name}`); pass++; }
    catch (e) { console.error(`  FAIL ${name}\n       ${e.stack || e.message || e}`); fail++; }
  }

  const socks5Url = `socks5://${AUTH_USER}:${AUTH_PASS}@127.0.0.1:${port}`;
  const socketUrl = `socket://${AUTH_USER}:${AUTH_PASS}@127.0.0.1:${port}`; // outlook 别名

  await t('fetch tls.peet.ws 走 SOCKS5 → 200 + JSON', async () => {
    const res = await bfp.fetch('https://tls.peet.ws/api/all', { proxy: socks5Url, timeout: 25000 });
    assert.strictEqual(res.status, 200);
    const j = await res.json();
    assert.ok(j.tls && j.tls.ja4);
    console.log(`         server JA4=${j.tls.ja4}`);
    console.log(`         server IP=${j.ip}`);
  });

  await t('socks5 侧记录了 CONNECT tls.peet.ws:443', () => {
    const seen = state.connects.filter(c => c.host === 'tls.peet.ws' && c.port === 443);
    assert.ok(seen.length >= 1, `期望 ≥ 1 次 CONNECT，实际=${seen.length}`);
    console.log(`         socks5 侧记录到 ${seen.length} 次 CONNECT`);
  });

  await t('socket:// 别名同 socks5:// 都通', async () => {
    const res = await bfp.fetch('https://tls.peet.ws/api/all', { proxy: socketUrl, timeout: 25000 });
    assert.strictEqual(res.status, 200);
  });

  await t('SOCKS5 user/pass 错误时抛错、不继续', async () => {
    const bad = `socks5://baduser:badpass@127.0.0.1:${port}`;
    const beforeFails = state.authFails;
    let err = null;
    try { await bfp.fetch('https://tls.peet.ws/api/all', { proxy: bad, timeout: 10000 }); }
    catch (e) { err = e; }
    assert.ok(err, '应抛错');
    assert.ok(/SOCKS5.*认证|SOCKS5.*auth/i.test(err.message), `错误消息应指明 SOCKS5 auth：${err.message}`);
    assert.ok(state.authFails > beforeFails, 'socks5 侧应记录一次 auth 失败');
  });

  await t('未知 scheme 立即抛（fail-close，不静默直连）', async () => {
    let err = null;
    try { await bfp.fetch('https://tls.peet.ws/api/all', { proxy: 'gopher://x:1080', timeout: 5000 }); }
    catch (e) { err = e; }
    assert.ok(err, '应抛错');
    assert.ok(/不支持的 proxy scheme/.test(err.message), `错误应指明不支持 scheme：${err.message}`);
  });

  console.log(`\n${pass} passed, ${fail} failed`);
  await stopServer(server);
  process.exit(fail === 0 ? 0 : 1);
})();
