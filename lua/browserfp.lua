-- browserfp —— ClientHello 指纹识别的 LuaJIT FFI 绑定。
--
-- 设计约束（这条是整个集成的前提）：
--   libbrowserfp.so 里所有函数都是**内存进内存出、非阻塞**的，不做 socket/文件 I/O、
--   不 sleep。因此可以在 nginx worker 里直接调用而不会阻塞事件循环。网络 I/O 一律
--   由 Lua 侧的 cosocket 承担，在等待时 yield 给事件循环。
--
--   反例：若把网络 I/O 放进 FFI，一次阻塞调用会冻死整个 worker —— 实测一个 9s 的
--   阻塞调用能让同 worker 上的并发请求卡住 8.88s。
--
-- 典型用法（入站识别，OpenResty 的 ssl_client_hello_by_lua*）：
--   local browserfp = require "browserfp"
--   local ssl_clt_hello = require "ngx.ssl.clienthello"
--   local raw = ssl_clt_hello.get_client_hello_raw()   -- 需 OpenResty 支持
--   local r = browserfp.identify(raw)
--   if r then ngx.log(ngx.INFO, "client=", r.id, " ja4=", r.ja4)
--   else       ngx.log(ngx.WARN, "unknown TLS fingerprint") end

local ffi = require "ffi"

ffi.cdef [[
typedef struct {
    uint16_t items[64];
    size_t   len;
} browserfp_u16list;

typedef struct {
    uint16_t      client_version;
    uint8_t       session_id_len;
    browserfp_u16list ciphers;
    browserfp_u16list extensions;
    browserfp_u16list curves;
    browserfp_u16list sig_algs;
    browserfp_u16list supported_versions;
    int           has_grease;
    int           has_sni;
    char          alpn_first[16];
    size_t        alpn_count;
} browserfp_hello;

typedef struct {
    const char     *id;
    const char     *ja4;
    const char     *h2_akamai;
    const char     *mode;
    const uint16_t *ciphers;   size_t n_ciphers;
    const uint16_t *exts;      size_t n_exts;
    const uint16_t *curves;    size_t n_curves;
    const uint16_t *sigalgs;   size_t n_sigalgs;
} browserfp_profile;

int  browserfp_parse_client_hello(const uint8_t *record, size_t len, browserfp_hello *out);
int  browserfp_parse_ua(const char *ua, char *brand_out, size_t brand_cap,
                    uint16_t *version);
const browserfp_profile *browserfp_lookup_ua(const char *brand, uint16_t version, int *confidence);
int  browserfp_ja4(const browserfp_hello *h, char transport, char *out, size_t outlen);
int  browserfp_build_client_hello(const browserfp_profile *p, const char *sni,
                              const uint8_t *random32, const uint8_t *session_id,
                              uint8_t *out, size_t outlen);
typedef struct { uint16_t group; const uint8_t *pub; size_t pub_len; } browserfp_keyshare;
int  browserfp_build_client_hello_ex(const browserfp_profile *p, const char *sni,
                                 const uint8_t *random32, const uint8_t *session_id,
                                 const browserfp_keyshare *ks, size_t n_ks,
                                 unsigned flags,
                                 uint8_t *out, size_t outlen);
int  browserfp_rebuild_hrr(const uint8_t *ch1, size_t ch1_len, uint16_t group,
                       const uint8_t *pub, size_t publen,
                       uint8_t *out, size_t outlen);
size_t browserfp_key_share_groups(const browserfp_profile *p, uint16_t *groups,
                              size_t *lens, size_t max);
int    browserfp_kx_init(const char *libcrypto_path);
const char *browserfp_kx_openssl_version(void);
size_t browserfp_kx_pub_len(uint16_t group);
size_t browserfp_kx_secret_len(uint16_t group);
int    browserfp_kx_keygen(uint16_t group, uint8_t *pub, size_t publen, void **out);
int    browserfp_kx_derive(void *ctx, const uint8_t *peer, size_t peerlen,
                       uint8_t *secret, size_t seclen);
void   browserfp_kx_free(void *ctx);
typedef struct {
    const uint32_t *settings; size_t n_settings;
    uint32_t        window;
    const uint32_t *prio;     size_t n_prio;
    const char     *pseudo;
    const char     *akamai;
    const char     *engine;
    uint16_t        ver_lo, ver_hi;
} browserfp_h2;

const browserfp_h2 *browserfp_lookup_h2(const char *brand, uint16_t version);
const browserfp_h2 *browserfp_identify_h2(const char *akamai);
int browserfp_coherence(const char *ja4, const char *akamai,
                    const char **tls_engine, const char **h2_engine);
int  browserfp_build_h2_preface(const browserfp_h2 *h, uint8_t *out, size_t outlen);
const char *browserfp_h2_pseudo(const browserfp_h2 *h);
const browserfp_profile *browserfp_profile_at(size_t idx);
const browserfp_profile *browserfp_lookup_ja4(const char *ja4);
size_t browserfp_profile_count(void);
]]

local _M = { _VERSION = "0.1" }

local lib
do
    -- 依次尝试常见位置；调用方也可先设 package.cpath 或用 browserfp.load(path)
    local candidates = {
        "libbrowserfp.so", "./libbrowserfp.so", "csrc/libbrowserfp.so",
        "/usr/local/lib/libbrowserfp.so",
    }
    for _, p in ipairs(candidates) do
        local ok, handle = pcall(ffi.load, p)
        if ok then lib = handle break end
    end
end

function _M.load(path)
    lib = ffi.load(path)
    return lib
end

-- 复用同一块 buffer，避免每请求分配（nginx worker 里这条很重要）
local hello_buf = ffi.new("browserfp_hello")
local ja4_buf   = ffi.new("char[40]")

--- 解析 ClientHello 并算 JA4。
-- @param record  完整 TLS record（含 5 字节头）的字符串
-- @param transport  "t"（TCP，默认）或 "q"（QUIC）
-- @return ja4 字符串；失败返回 nil, err
function _M.ja4(record, transport)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(record) ~= "string" or #record < 5 then return nil, "record 太短" end

    local rc = lib.browserfp_parse_client_hello(record, #record, hello_buf)
    if rc ~= 0 then return nil, "解析失败 rc=" .. tonumber(rc) end

    local t = (transport == "q") and 113 or 116   -- 'q' / 't'
    if lib.browserfp_ja4(hello_buf, t, ja4_buf, 40) ~= 0 then
        return nil, "ja4 计算失败"
    end
    return ffi.string(ja4_buf)
end

--- 识别 ClientHello 对应的已知 profile。
-- **未命中时返回 nil 而不是"最接近的那个"**：把陌生指纹安静地归到某个已知
-- profile，比认不出更糟——它让盲区永远不可见。
-- @return table{id, ja4, h2, mode} 或 nil, ja4（未知时把算出的 ja4 一并返回，
--         便于调用方记日志、后续补录）
function _M.identify(record, transport)
    local ja4, err = _M.ja4(record, transport)
    if not ja4 then return nil, err end

    local p = lib.browserfp_lookup_ja4(ja4)
    if p == nil then return nil, ja4 end

    return {
        id   = ffi.string(p.id),
        ja4  = ja4,
        h2   = p.h2_akamai ~= nil and ffi.string(p.h2_akamai) or nil,
        mode = ffi.string(p.mode),
    }
end

-- C 侧的 confidence 取值：0/1/2 是可用档，负值表示"没给 profile"但原因不同。
-- **NULL 返回时也要把 confidence 带出去**：fallback（存在跨段的最近版本，只是
-- 严格模式不许用，该记进补录清单）与 no-brand（表里根本没这个品牌）是两件事，
-- 合并成一个 nil 会让调用方分不清，也让差分门禁把两侧判成不一致。
local conf_names = {
    [0] = "exact", [1] = "same-seg", [2] = "fallback",
    [-1] = "no-brand", [-2] = "no-version",
}
local conf_buf = ffi.new("int[1]")

--- 按 UA 的品牌与主版本选出该用的指纹（生产主入口）。
-- 网关在 CDN 之后拿不到 ClientHello，只能按 UA 选。
-- **默认严格**：只有 exact / same-seg 才返回 profile；没有精确指纹时返回 nil，
-- 调用方应放弃伪装。拿最近版本的指纹冒充另一个版本正是 split-brain 的来源。
-- @return table{id, ja4, h2, confidence} 或 nil, err
function _M.by_ua(brand, version)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(brand) ~= "string" or type(version) ~= "number" then
        return nil, "brand/version 类型错误"
    end
    conf_buf[0] = -1
    local p = lib.browserfp_lookup_ua(brand, version, conf_buf)
    local conf = conf_names[conf_buf[0]] or "unknown"
    if p == nil then
        -- 第三个返回值给出 confidence：调用方据此区分"该补录"与"本就没有"
        return nil, "该品牌/版本无可用 profile", conf
    end
    return {
        id   = ffi.string(p.id),
        ja4  = ffi.string(p.ja4),
        h2   = p.h2_akamai ~= nil and ffi.string(p.h2_akamai) or nil,
        confidence = conf,
    }
end

-- 复用缓冲区，避免每请求分配（nginx worker 里这条很重要）
-- **以下这些是模块级共享缓冲**：一个 worker 里所有协程共用。
-- 安全的前提只有一条 —— 写进去和 ffi.string 读出来**之间不能有让出点**
-- （不能 ngx.sleep / cosocket 读写 / ngx.say 等）。现在的代码满足这一条。
--
-- 这不是理论顾虑：test_openresty 的并发检查做过阴性对照 —— 在 build 与
-- ffi.string 之间插一个 ngx.sleep(0.003)，16 路并发 60 个请求里只有 12 个
-- 拿到自己的字节，其余拿到别的品牌的、甚至解析都失败。
-- 往这几行之后加代码时，先问一句"这里会不会让出"。
local ch_buf   = ffi.new("uint8_t[16384]")
local ks_buf   = ffi.new("browserfp_keyshare[8]")
local ks_grp   = ffi.new("uint16_t[8]")
local ks_len   = ffi.new("size_t[8]")
local h2_buf = ffi.new("uint8_t[?]", 8192)
local ua_brand_buf = ffi.new("char[64]")
local rnd_buf  = ffi.new("uint8_t[32]")
local sid_buf  = ffi.new("uint8_t[32]")

-- 前向声明：keygen / gen_key_shares 都用它，而它定义在后面。**要是 local，
-- 不能漏** —— 漏了就成全局函数，污染 _G，两个模块同名时会互相覆盖。
local _wrap_keys

--- 为**单独一个组**生成密钥。HRR 用：服务端选的那个组多半不在 profile 的
-- key_share 里，gen_key_shares() 不会为它产密钥。
-- @return keys 对象（keys.shares = {[组号]=公钥}）或 nil, err
function _M.keygen(group)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if lib.browserfp_kx_init(nil) ~= 0 then
        return nil, "解析 libcrypto 符号失败"
    end
    local want = tonumber(lib.browserfp_kx_pub_len(group))
    if want == 0 then
        return nil, string.format("组 0x%04x 不支持 —— 只做 X25519 / P-256 / "
                                  .. "P-384 / X25519MLKEM768", group)
    end
    return _wrap_keys({ [group] = want })
end


--- HelloRetryRequest：服务端要一个我们没发过的组，补发第二条 ClientHello。
--
-- **拿第一条的字节改，不要重新造一条**。RFC 8446 §4.1.2 要求 CH2 与 CH1 只差
-- 指定的几处 —— random / session_id / GREASE / GREASE ECH 全都必须原样带回，
-- 就地改写让它们天然逐字节相同。记录层版本会换成 0x0303（只有首条是 0x0301）。
--
-- 服务端选的那个组多半不在 gen_key_shares() 产的那几组里，得单独生成：
--   local pub, h = browserfp.keygen(group)
--   local ch2 = browserfp.client_hello_hrr(ch1, group, pub)
--
-- @param ch1    第一条 ClientHello 的完整 record
-- @param group  服务端在 HelloRetryRequest 里选的组
-- @param pub    该组的公钥
-- @return record 字符串；失败返回 nil, err
function _M.client_hello_hrr(ch1, group, pub)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(ch1) ~= "string" or type(pub) ~= "string" then
        return nil, "ch1 与 pub 都必须是字符串"
    end
    local n = lib.browserfp_rebuild_hrr(ch1, #ch1, group, pub, #pub,
                                    ch_buf, ffi.sizeof(ch_buf))
    if n < 0 then
        return nil, "重建 CH2 失败：ch1 不是完整的 ClientHello，或里面没有 key_share"
    end
    return ffi.string(ch_buf, n)
end


--- 为一个 profile 的每一组生成密钥，直接交给 client_hello 用。
--
-- **这是伪装链上唯一一处需要私钥的地方**，所以私钥不出这个模块：返回的
-- keys 对象自己持有句柄，拿到 ServerHello 之后用 keys:derive(group, peer)
-- 算共享密钥。私钥挂在 ffi.gc 上，协程被 kill 掉也会回收。
--
-- 密码学不是自己实现的 —— 走的是**运行时已经加载的那份 OpenSSL**（worker 里
-- 就是 OpenResty 自带的 3.5.x，ML-KEM-768 在里面）。
--
-- @return keys 对象（keys.shares = {[组号]=公钥字符串}）或 nil, err
function _M.gen_key_shares(brand, version)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if lib.browserfp_kx_init(nil) ~= 0 then
        return nil, "解析 libcrypto 符号失败：这个进程里没有加载 OpenSSL？"
    end
    local groups, err = _M.key_share_groups(brand, version)
    if not groups then return nil, err end

    local want = {}
    for _, g in ipairs(groups) do want[g.group] = g.len end
    return _wrap_keys(want)
end


-- 产一组密钥并包成 keys 对象。**私钥只存在这个闭包里** —— 不放模块级表，
-- 免得两个协程互相看得见对方的私钥。
function _wrap_keys(want)
    local shares, handles = {}, {}
    for group, len in pairs(want) do
        local buf = ffi.new("uint8_t[?]", len)
        local hp = ffi.new("void*[1]")
        local n = lib.browserfp_kx_keygen(group, buf, len, hp)
        if n ~= len then
            return nil, string.format("组 0x%04x 生成密钥失败（要 %d 字节，得 %d）"
                                      .. "——这一组当前的 OpenSSL 可能不支持",
                                      group, len, tonumber(n))
        end
        shares[group] = ffi.string(buf, n)
        handles[group] = ffi.gc(hp[0], lib.browserfp_kx_free)
    end

    return {
        shares = shares,
        -- @return 共享密钥字符串；失败返回 nil, err
        derive = function(self, group, peer)
            local h = handles[group]
            if not h then
                return nil, string.format("没有为组 0x%04x 生成过密钥", group)
            end
            local want = tonumber(lib.browserfp_kx_secret_len(group))
            local out = ffi.new("uint8_t[?]", want)
            local n = lib.browserfp_kx_derive(h, peer, #peer, out, want)
            if n ~= want then
                return nil, string.format("组 0x%04x 算共享密钥失败 —— "
                                          .. "服务端那段长度对不上？给了 %d 字节",
                                          group, #peer)
            end
            return ffi.string(out, n)
        end,
        -- 用完尽早放，别等 GC —— 一个 ML-KEM 私钥不小
        free = function(self)
            for g, h in pairs(handles) do
                ffi.gc(h, nil)
                lib.browserfp_kx_free(h)
                handles[g] = nil
            end
        end,
    }
end


--- 这个 profile 的 key_share 要哪些组、每组公钥多少字节。
-- **调用方必须先问这个再去生成密钥**：组是 profile 决定的，不同浏览器、不同版本
-- 差别很大（X25519 / P-256 / X25519MLKEM768 都出现过），照着某一个写死必然有
-- profile 对不上。GREASE 那条不列 —— 它的内容由库自己按 RFC 8701 填。
-- @return 数组 {{group=…, len=…}, …}  或 nil, err
function _M.key_share_groups(brand, version)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    local p = lib.browserfp_lookup_ua(brand, version, conf_buf)
    if p == nil then return nil, "无可用 profile" end
    local n = lib.browserfp_key_share_groups(p, ks_grp, ks_len, 8)
    local out = {}
    for i = 0, tonumber(n) - 1 do
        out[#out + 1] = { group = tonumber(ks_grp[i]), len = tonumber(ks_len[i]) }
    end
    return out
end


--- 按 profile id 列出 key_share 要哪些组。与 key_share_groups 相同，但按 id 查表。
function _M.key_share_groups_by_id(id)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    local p
    for i = 0, tonumber(lib.browserfp_profile_count()) - 1 do
        local pp = lib.browserfp_profile_at(i)
        if pp ~= nil and ffi.string(pp.id) == id then p = pp; break end
    end
    if not p then return nil, "profile id 无可用 profile：" .. id end
    local n = lib.browserfp_key_share_groups(p, ks_grp, ks_len, 8)
    local out = {}
    for i = 0, tonumber(n) - 1 do
        out[#out + 1] = { group = tonumber(ks_grp[i]), len = tonumber(ks_len[i]) }
    end
    return out
end


--- 按 profile id 为每一组生成密钥。与 gen_key_shares 相同，但按 id 查表。
function _M.gen_key_shares_by_id(id)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if lib.browserfp_kx_init(nil) ~= 0 then
        return nil, "解析 libcrypto 符号失败"
    end
    local groups, err = _M.key_share_groups_by_id(id)
    if not groups then return nil, err end
    local want = {}
    for _, g in ipairs(groups) do want[g.group] = g.len end
    return _wrap_keys(want)
end


--- User-Agent 字符串 → (品牌, 版本)。认不出返回 nil。
--
-- **"按用户自己的浏览器出指纹"就靠这一步**：网关拿到的是 UA 字符串，而底下
-- 所有接口收的都是 (品牌, 版本)。规则与 Python 侧逐字节对齐，判据是 77 条 UA
-- 的全量差分（60 条真实生产 UA + 17 条逐分支的合成用例）。
--
-- 认不出时**不要拿别的浏览器顶替** —— 那正是这个库一直在防的 split-brain。
-- 调用方该做的是放弃伪装、走原来的通道，并把这次降级记下来。
-- @return brand, version 或 nil
function _M.parse_ua(ua)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(ua) ~= "string" or ua == "" then return nil, "ua 必须是非空字符串" end
    local vbuf = ffi.new("uint16_t[1]")
    if lib.browserfp_parse_ua(ua, ua_brand_buf, ffi.sizeof(ua_brand_buf), vbuf) ~= 1 then
        return nil, "认不出这个 User-Agent"
    end
    return ffi.string(ua_brand_buf), tonumber(vbuf[0])
end


--- 按 UA 选出指纹并组装 ClientHello 字节，供 cosocket 直接发出。
-- **伪装链的最后一环**：查表只拿到 profile，得把它变成真正的字节。
--
-- random 与 session_id 每次调用都重新生成 —— 照抄 golden 里那份会让所有连接的
-- ClientHello 逐字节相同，比不伪装还容易被判。这里用 resty.random 取强随机；
-- 不在 OpenResty 环境时退回 math.random（仅供离线自测，**不要用于生产**）。
--
-- key_shares **是必填的**，且必须盖满 key_share_groups() 列出的每一组。缺一组
-- 时发出去的是采集那台机器的公钥，我们没有对应私钥 —— 握手一定失败，而报错会
-- 指向"共享密钥算错"，与真因毫无关系。所以这里宁可当场报错，不给默认值。
--
-- @param brand    品牌，移动端传 "<brand>-mobile"
-- @param version  主版本；Chromium 系衍生浏览器传 UA 里 Chrome/ 的版本号
-- @param sni      目标域名，必须给 —— 少了它多租户站点直接 handshake_failure
-- @param key_shares  {[组号] = 公钥字符串}，长度须与 key_share_groups() 给的一致
-- @return record 字符串, profile 信息表；失败返回 nil, err
function _M.client_hello(brand, version, sni, key_shares)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(sni) ~= "string" or sni == "" then
        return nil, "必须提供 sni：多租户站点缺 SNI 会直接 handshake_failure"
    end
    if type(key_shares) ~= "table" then
        return nil, "必须提供 key_shares：否则发的是采集机的公钥，握不上手"
    end
    local prof, err, conf = _M.by_ua(brand, version)
    if not prof then return nil, err or "无可用 profile" end

    local strong = nil
    local ok_rand, rnd = pcall(require, "resty.random")
    if ok_rand and rnd and rnd.bytes then strong = rnd.bytes(64, true) end
    if strong and #strong >= 64 then
        ffi.copy(rnd_buf, strong, 32)
        ffi.copy(sid_buf, strong:sub(33, 64), 32)
    else
        -- 离线自测退路：math.random 不是密码学随机，生产必须走 resty.random
        for i = 0, 31 do
            rnd_buf[i] = math.random(0, 255)
            sid_buf[i] = math.random(0, 255)
        end
    end

    local p = lib.browserfp_lookup_ua(brand, version, conf_buf)
    if p == nil then return nil, "profile 已失效" end
    -- 组必须**盖满**。C 侧只查"给进来的组在不在 profile 里"（多给会报错），
    -- 查不了"少给" —— 少给的那组会安静地沿用采集机的公钥。这一侧补上。
    local n_ks = 0
    local hold = {}
    local want = lib.browserfp_key_share_groups(p, ks_grp, ks_len, 8)
    for i = 0, tonumber(want) - 1 do
        local g = tonumber(ks_grp[i])
        local pub = key_shares[g]
        if type(pub) ~= "string" then
            return nil, string.format("key_share 缺组 0x%04x（或不是字符串）", g)
        end
        if #pub ~= tonumber(ks_len[i]) then
            return nil, string.format("key_share 组 0x%04x 公钥应为 %d 字节，给了 %d",
                                      g, tonumber(ks_len[i]), #pub)
        end
        local buf = ffi.new("uint8_t[?]", #pub)
        ffi.copy(buf, pub, #pub)
        hold[#hold + 1] = buf                -- 防止 GC 在 FFI 调用前回收
        ks_buf[n_ks].group = g
        ks_buf[n_ks].pub = buf
        ks_buf[n_ks].pub_len = #pub
        n_ks = n_ks + 1
    end
    -- 多给的组要报错，不能静默丢。**"以为注入了、其实没有"是最难查的一种**：
    -- 字节合法、指纹全对，只有服务端算共享密钥时才炸。GREASE 那条也算多给 ——
    -- 它的内容按 RFC 8701 由库自己填，注入进去等于把伪装做坏了。
    for g in pairs(key_shares) do
        if type(g) ~= "number" then
            return nil, "key_shares 的键必须是组号（数字），拿到 " .. type(g)
        end
        local listed = false
        for i = 0, tonumber(want) - 1 do
            if tonumber(ks_grp[i]) == g then listed = true break end
        end
        if not listed then
            return nil, string.format("key_shares 里的组 0x%04x 不在这个 profile 的 "
                                      .. "key_share 里，注入会被丢掉", g)
        end
    end
    local n = lib.browserfp_build_client_hello_ex(p, sni, rnd_buf, sid_buf,
                                              ks_buf, n_ks,
                                              0, ch_buf, ffi.sizeof(ch_buf))
    if n < 0 then return nil, "组装失败（缓冲区不足或 profile 缺重建字段）" end
    return ffi.string(ch_buf, n), prof
end

--- 内部：从已选中的 profile 组装 ClientHello（codex/rustls 这类**非浏览器**客户端用）。
--
-- codex 真身（rustls 保守 TLS1.2，JA3 e4d448 / JA4 t12d2207…）三点决定：
--   1. **无 key_share**：TLS1.2 的 ECDHE 公钥在 ClientKeyExchange 才发，ClientHello 里没有
--      key_share（0x0033），所以不需要、也不能注入 key_shares。
--   2. **VERBATIM**：codex 无 GREASE、扩展顺序恒定；照 profile 字节原样出。非 VERBATIM 会触发
--      Chrome 那套（重掷 GREASE / 每连接打乱扩展 / padding 到 512），把 e4d448 破坏成不存在的组合。
--   3. random / session_id 每次强随机——照抄 golden 会让所有连接逐字节相同。
local function client_hello_from_profile(p, sni)
    if type(sni) ~= "string" or sni == "" then
        return nil, "必须提供 sni：多租户站点缺 SNI 会直接 handshake_failure"
    end
    local strong = nil
    local ok_rand, rnd = pcall(require, "resty.random")
    if ok_rand and rnd and rnd.bytes then strong = rnd.bytes(64, true) end
    if strong and #strong >= 64 then
        ffi.copy(rnd_buf, strong, 32)
        ffi.copy(sid_buf, strong:sub(33, 64), 32)
    else
        for i = 0, 31 do rnd_buf[i] = math.random(0, 255); sid_buf[i] = math.random(0, 255) end
    end
    -- key_shares=NULL/0，flags=TLSFP_BUILD_VERBATIM(=1)。
    -- **这几行之间不能有让出点**（同 client_hello 的告诫）：ch_buf 是 worker 级共享。
    local n = lib.browserfp_build_client_hello_ex(p, sni, rnd_buf, sid_buf,
                                              nil, 0,
                                              1, ch_buf, ffi.sizeof(ch_buf))
    if n < 0 then return nil, "组装 ClientHello 失败（缓冲区不足或 profile 缺字段）" end
    return ffi.string(ch_buf, n), { id = ffi.string(p.id), ja4 = ffi.string(p.ja4) }
end

--- 按 **profile id**（profiles.json 主键，如 "codex:rustls-tls12"）选指纹并组装 ClientHello。
--
-- 给 codex/rustls 这类**非浏览器**客户端用：它们没有 UA（进不了 by_ua 的品牌表），且调用方
-- 该按**语义主键**选，而不是在业务代码里背一串 ja4 哈希。id 是稳定主键（ja4 会随指纹微调变化，
-- id 不会），指纹知识（包括对应哪条 ja4）留在指纹库这一层。
--
-- @param id   profiles.json 里的 profile id（主键）
-- @param sni  目标域名，必须给
-- @return record 字符串, profile 信息表；失败返回 nil, err
function _M.client_hello_by_id(id, sni)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(id) ~= "string" or id == "" then return nil, "必须提供 profile id" end
    for i = 0, tonumber(lib.browserfp_profile_count()) - 1 do
        local p = lib.browserfp_profile_at(i)
        if p ~= nil and ffi.string(p.id) == id then
            return client_hello_from_profile(p, sni)
        end
    end
    return nil, "profile id 无可用 profile：" .. id
end

--- 按 profile id 组装 ClientHello **并注入 key_shares**。
--
-- 给 bun/BoringSSL 这类 TLS 1.3 非浏览器客户端用：它们需要 VERBATIM（不掷 GREASE /
-- 不乱序扩展），但又有 key_share 要注入（TLS 1.3 握手需要）。与 client_hello_by_id 的
-- 唯一区别就是传了 key_shares 给 build_client_hello_ex。
--
-- padding 由 C 侧按实际长度重算（build_client_hello_ex 对 rawext 含 0x0015 的 profile
-- 即使 VERBATIM 也会重算 padding）。
--
-- @param id          profiles.json 里的 profile id
-- @param sni         目标域名
-- @param key_shares  {[组号] = 公钥字符串}
-- @return record 字符串, profile 信息表；失败返回 nil, err
--- @param det  可选，**仅供判据**：{ random = <32B>, session_id = <32B> }。
--- 给了就用它替代内部强随机，让同样的入参产出逐字节相同的 ClientHello ——
--- 逐字节黄金向量（真机 bun 1.4.0 抓包）只有能固定 random/session_id 才对得起来。
--- ⛔ **生产绝不能传**：所有连接的 ClientHello 逐字节相同，比不伪装还容易判别。
--- C 侧 browserfp_build_client_hello_ex 本来就收这两个参数，此前只是没暴露。
function _M.client_hello_by_id_with_keys(id, sni, key_shares, det)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(id) ~= "string" or id == "" then return nil, "必须提供 profile id" end
    if type(sni) ~= "string" or sni == "" then
        return nil, "必须提供 sni：多租户站点缺 SNI 会直接 handshake_failure"
    end
    if type(key_shares) ~= "table" then
        return nil, "必须提供 key_shares：TLS 1.3 握手需要注入公钥"
    end

    local p
    for i = 0, tonumber(lib.browserfp_profile_count()) - 1 do
        local pp = lib.browserfp_profile_at(i)
        if pp ~= nil and ffi.string(pp.id) == id then p = pp break end
    end
    if not p then return nil, "profile id 无可用 profile：" .. id end

    if det then
        if type(det.random) ~= "string" or #det.random ~= 32 then
            return nil, "det.random 必须是 32 字节"
        end
        if type(det.session_id) ~= "string" or #det.session_id ~= 32 then
            return nil, "det.session_id 必须是 32 字节"
        end
        ffi.copy(rnd_buf, det.random, 32)
        ffi.copy(sid_buf, det.session_id, 32)
    else
        local strong = nil
        local ok_rand, rnd = pcall(require, "resty.random")
        if ok_rand and rnd and rnd.bytes then strong = rnd.bytes(64, true) end
        if strong and #strong >= 64 then
            ffi.copy(rnd_buf, strong, 32)
            ffi.copy(sid_buf, strong:sub(33, 64), 32)
        else
            for i = 0, 31 do rnd_buf[i] = math.random(0, 255); sid_buf[i] = math.random(0, 255) end
        end
    end

    local n_ks = 0
    local hold = {}
    for group, pub in pairs(key_shares) do
        if type(pub) ~= "string" then
            return nil, string.format("key_share 组 0x%04x 公钥不是字符串", group)
        end
        local buf = ffi.new("uint8_t[?]", #pub)
        ffi.copy(buf, pub, #pub)
        hold[#hold + 1] = buf
        ks_buf[n_ks].group = group
        ks_buf[n_ks].pub = buf
        ks_buf[n_ks].pub_len = #pub
        n_ks = n_ks + 1
    end

    local n = lib.browserfp_build_client_hello_ex(p, sni, rnd_buf, sid_buf,
                                              ks_buf, n_ks,
                                              1, ch_buf, ffi.sizeof(ch_buf))
    if n < 0 then return nil, "组装 ClientHello 失败（缓冲区不足或 profile 缺字段）" end
    return ffi.string(ch_buf, n), { id = ffi.string(p.id), ja4 = ffi.string(p.ja4) }
end

--- 按 JA4 选指纹并组装 ClientHello（通用 by-ja4；业务侧语义化选择优先用 client_hello_by_id）。
-- @param ja4  目标 profile 的 JA4，须与 profile.ja4 一致
-- @param sni  目标域名，必须给
function _M.client_hello_by_ja4(ja4, sni)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(ja4) ~= "string" or ja4 == "" then return nil, "必须提供 ja4" end
    local p = lib.browserfp_lookup_ja4(ja4)
    if p == nil then return nil, "ja4 无可用 profile：" .. ja4 end
    return client_hello_from_profile(p, sni)
end

-- HTTP/2 连接开场：PREFACE + SETTINGS + WINDOW_UPDATE + PRIORITY。
--
-- **按 (品牌, 版本) 独立查，不从 TLS profile 上读**。注册表按 TLS 指纹去重，
-- 而 h2 参数与 ClientHello 各改各的：两个版本 TLS 相同、h2 不同是常态，实测
-- chrome 106-117 共 9 个版本曾因搭车拿到没有任何一个库归给它们的 h2。
-- 伪装是分层的，TLS 像 Chrome、h2 不像任何浏览器，是现实中不存在的组合。
--
-- 版本口径与 by_ua 一致：Chromium 系衍生浏览器传**内核** Chrome 版本。
--
-- HEADERS 不在返回值里：内容依赖具体请求，本库只给伪头**顺序**（第二个返回值）。
--
-- @return string 开场字节, string 伪头序   或  nil, err
function _M.h2_preface(brand, version)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(brand) ~= "string" or type(version) ~= "number" then
        return nil, "brand 必须是字符串、version 必须是数字"
    end
    local h = lib.browserfp_lookup_h2(brand, version)
    -- 查不到就明确失败。**不能退回一组默认 SETTINGS** —— 那等于发一个不属于
    -- 任何浏览器的 h2 指纹。调用方该走 HTTP/1.1，或换一个有数据的版本。
    if h == nil then return nil, "该品牌/版本没有 h2 数据，不能构造开场" end
    local n = lib.browserfp_build_h2_preface(h, h2_buf, ffi.sizeof(h2_buf))
    if n < 0 then return nil, "组装失败（缓冲区不足）" end
    local ps = lib.browserfp_h2_pseudo(h)
    return ffi.string(h2_buf, n), ps ~= nil and ffi.string(ps) or nil
end

--- 这个 (品牌, 版本) 应该呈现的 Akamai h2 指纹串。
--
-- **不要拿 by_ua().h2 当这个用**：注册表按 TLS 指纹去重，profile 上那个 h2
-- 字段只是「采集这条 TLS 指纹时顺带看到的 h2」，两个版本 TLS 相同、h2 不同是
-- 常态，还有一批 profile 那个字段干脆是空的（实测 firefox153 就是）。
-- h2 必须按 (品牌, 版本) 独立查 —— 与 h2_preface 同一个源。
-- @return akamai 串 或 nil, err
function _M.h2_akamai(brand, version)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(brand) ~= "string" or type(version) ~= "number" then
        return nil, "brand 必须是字符串、version 必须是数字"
    end
    local h = lib.browserfp_lookup_h2(brand, version)
    if h == nil then return nil, "该品牌/版本没有 h2 数据" end
    return h.akamai ~= nil and ffi.string(h.akamai) or nil
end

-- 按观测到的 akamai 指纹反查（入站识别）。
--
-- **认得出引擎，认不出版本**：实测 644 个 (品牌,版本) 只归成 19 个 akamai，
-- 最常见的一个覆盖 223 个组合。但没有一个 akamai 跨引擎，所以 engine 是确定的；
-- ver_lo/ver_hi 只是该指纹覆盖的版本范围，不要当成"就是这个版本"。
--
-- @return table{engine, ver_lo, ver_hi, akamai} 或 nil
function _M.identify_h2(akamai)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    if type(akamai) ~= "string" then return nil, "akamai 必须是字符串" end
    local h = lib.browserfp_identify_h2(akamai)
    if h == nil then return nil end
    return {engine = ffi.string(h.engine), ver_lo = h.ver_lo,
            ver_hi = h.ver_hi, akamai = ffi.string(h.akamai)}
end

-- 三层各自认出的引擎是否自洽。检测方正是这么查的：TLS 说 Chromium 而 h2 说
-- Gecko，一眼就假。也可以拿它自查自己拼出来的伪装。
--
-- 任一参数传 nil 表示该层没有观测。返回 (verdict, 各层引擎)：
--   verdict = "ok"      有观测的那些层一致
--             "mismatch" 矛盾
--             "unknown"  可用信息不足（少于两层认得出来）
-- 第二个返回值是 {tls=…, h2=…, headers=…}，认不出的为 nil ——
-- 报"哪一层不一致"比只报一个布尔有用得多。
local e1, e2 = ffi.new("const char*[1]"), ffi.new("const char*[1]")
function _M.coherence(ja4, akamai)
    if not lib then return nil, "libbrowserfp.so 未加载" end
    -- **两个参数都必须是字符串或 nil**。FFI 遇到数字/布尔会抛
    -- "cannot convert 'number' to 'const char *'" —— 未捕获就是 500。
    local function str_or_nil(v)
        return type(v) == "string" and v or nil
    end
    ja4, akamai = str_or_nil(ja4), str_or_nil(akamai)
    e1[0], e2[0] = nil, nil
    local r = lib.browserfp_coherence(ja4, akamai, e1, e2)
    local function str(b) return b[0] ~= nil and ffi.string(b[0]) or nil end
    return (r == 0 and "ok") or (r == 1 and "mismatch") or "unknown",
           {tls = str(e1), h2 = str(e2)}
end

function _M.profile_count()
    if not lib then return 0 end
    return tonumber(lib.browserfp_profile_count())
end

return _M
