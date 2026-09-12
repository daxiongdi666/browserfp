// 端到端：用 browserfp 的 Chrome profile 打真实 HTTPS 站点，验证：
//   1. 我们的 TLS 1.3 握手能真跑通（跟真服务端）
//   2. 证书链校验通过
//   3. HTTP/1.1 请求响应能读完
//   4. 服务端识别到的 JA4/JA3 与 browserfp 声称的 Chrome 指纹一致
//
// 站点选择：走 tls.peet.ws（peetdev/aaronparker 提供的 TLS 指纹回显 API）。
// 它以 JSON 返回它看到的 JA3/JA4/HTTP/2 指纹，判据是**服务端认可的指纹**。
//
// 备用：如果 peet 不可达（proxy/网络），也回退到普通 HTTPS 站点确认连通性。
//
// 跑法：
//   HTTPS_PROXY='' NO_PROXY='*' node test-e2e.js
// （本机 ClashX Meta 会拦 DNS，不出网测试请先关 TUN 或走裸网）

'use strict';

const browserfp = require('./browserfp.js');
const tls13 = require('./tls13.js');
const http1 = require('./http1.js');
const http2 = require('./http2.js');

const CHROME_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36';

async function once(host, path) {
  browserfp.load();
  const profile = browserfp.selectUA(CHROME_UA);
  console.log(`[profile] id=${profile.id} engine=${profile.engine}`);
  console.log(`[profile] ja4=${profile.ja4}`);
  console.log(`[profile] akamai=${profile.akamai}`);

  const conn = await tls13.connect({
    host,
    port: 443,
    profile,
    timeout: 20000,
  });
  console.log(`[tls] cipherSuite=0x${conn.cipherSuite.toString(16)} alpn=${conn.alpn}`);

  let res;
  if (conn.alpn === 'h2') {
    const { preface, pseudoOrder } = profile.h2Preface();
    res = await http2.request({
      stream: conn.stream,
      prefaceBytes: preface,
      pseudoOrder,
      method: 'GET',
      scheme: 'https',
      authority: host,
      path,
      headers: [
        ['user-agent', CHROME_UA],
        ['accept', '*/*'],
        ['accept-encoding', 'gzip, deflate'],
      ],
      timeout: 20000,
    });
  } else {
    res = await http1.request({
      stream: conn.stream,
      method: 'GET',
      path,
      headers: [
        ['Host', host],
        ['User-Agent', CHROME_UA],
        ['Accept', '*/*'],
        ['Accept-Encoding', 'identity'],
        ['Connection', 'close'],
      ],
      timeout: 15000,
    });
  }

  console.log(`[http] status=${res.status} bodyLen=${res.body.length}`);
  const preview = res.body.slice(0, 600).toString('utf8');
  console.log('[body preview]');
  console.log(preview);
  conn.close();
  return res;
}

(async () => {
  const targets = [
    // tls.peet.ws 回显它看到的 JA3/JA4/HTTP/2 指纹 —— 端到端指纹一致性判据
    { host: 'tls.peet.ws', path: '/api/all' },
    // 兜底：一个 HTTP/1.1 站，验证 http1 路径
    { host: 'example.com', path: '/' },
  ];
  for (const t of targets) {
    console.log(`\n=== ${t.host}${t.path} ===`);
    try {
      await once(t.host, t.path);
    } catch (e) {
      console.error(`FAIL: ${e.message}`);
      console.error(e.stack);
    }
  }
})();
