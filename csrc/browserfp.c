/* ClientHello 解析与 JA4 计算。行为以 the Python reference (clienthello.py) 为准。 */
#include "browserfp.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <dlfcn.h>

/* SHA-256 走**运行时 dlsym**，不在链接期绑 libcrypto。
 *
 * 两个理由：
 *   ① 交叉编译。这个 .so 要按目标平台预编进包（与 vendor/protobuf/<TARGET>/pb.so
 *      同样的做法），链了 libcrypto 就得连目标平台的 openssl 一起准备。去掉之后
 *      它是**纯 C 无外部依赖**，随便哪个 Linux 工具链都能出。
 *   ② 一个进程里别出现两份 OpenSSL。宿主是 OpenResty，它自带 OpenSSL（本机实测
 *      3.5.7）；再链一份系统 libcrypto 进来就是两份。RTLD_DEFAULT 拿到的正是
 *      **宿主已经加载的那一份**，与 browserfp_kx.c 的做法一致。
 *
 * 拿不到就返回 -1，调用方按失败处理 —— 不自带一份 SHA-256 兜底：那等于在指纹
 * 库里塞第二套密码学实现，两套算出来不一致时症状是「指纹莫名其妙不对」。 */
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

typedef unsigned char *(*fn_sha256)(const unsigned char *, size_t, unsigned char *);
static fn_sha256 browserfp_sha256_fn;

/* 先看宿主进程里有没有（OpenResty 里 nginx 已经链了 libcrypto，这条就够）；
 * 没有就按常见 soname 自己 dlopen 一个。**纯 LuaJIT 进程属于后者** —— 门禁大多
 * 用 luajit 跑，只靠 RTLD_DEFAULT 的话 SHA256 拿不到、返回 NULL，症状是
 * 82 个 profile 全部不符（JA4 与扩展置换都用它派生）。2026-08-03 实测过。 */
static const char *const TLSFP_CRYPTO_SONAMES[] = {
    /* Linux 优先（生产就是它）：进程里通常已经加载，dlopen 只是兜底 */
    "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so",
    /* macOS：**必须给绝对路径**。裸名 "libcrypto.dylib" 会命中系统那份
     * LibreSSL，而它被 dlopen 时主动 abort：
     *     WARNING: … is loading libcrypto in an unsafe way
     *     SIGABRT
     * 在 OpenResty 里碰不到（进程已链好 libcrypto，走 RTLD_DEFAULT 就命中），
     * 但 Go 绑定 / 离线 CLI 这类**自己没链 libcrypto 的宿主**一试就崩。
     * 2026-08-04 写 Go 绑定时撞到。 */
    "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
    "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
    "/opt/homebrew/lib/libcrypto.3.dylib",
    "/usr/local/lib/libcrypto.3.dylib",
    "libcrypto.3.dylib", "libcrypto.1.1.dylib",
    NULL
};

static int browserfp_sha256_init(void) {
    if (browserfp_sha256_fn) return 0;
    void *p = dlsym(RTLD_DEFAULT, "SHA256");
    if (!p) {
        for (int i = 0; TLSFP_CRYPTO_SONAMES[i]; i++) {
            void *h = dlopen(TLSFP_CRYPTO_SONAMES[i], RTLD_NOW | RTLD_GLOBAL);
            if (!h) continue;
            p = dlsym(h, "SHA256");
            if (p) break;
        }
    }
    if (!p) return -1;
    browserfp_sha256_fn = (fn_sha256)p;
    return 0;
}

/* 让调用方显式指定 libcrypto（与 browserfp_kx_init 同一口径）。返回 0 成功。 */
int browserfp_crypto_init(const char *libcrypto_path) {
    if (browserfp_sha256_fn) return 0;
    if (libcrypto_path && *libcrypto_path) {
        void *h = dlopen(libcrypto_path, RTLD_NOW | RTLD_GLOBAL);
        if (h) {
            void *p = dlsym(h, "SHA256");
            if (p) { browserfp_sha256_fn = (fn_sha256)p; return 0; }
        }
    }
    return browserfp_sha256_init();
}

/* 与 OpenSSL 的 SHA256() 同签名；拿不到实现时把输出清零并返回 NULL。 */
static unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md) {
    if (browserfp_sha256_init() != 0) return NULL;
    return browserfp_sha256_fn(d, n, md);
}

#include "profiles.inc"

const browserfp_profile *browserfp_lookup_ja4(const char *ja4) {
    if (!ja4) return NULL;
    for (size_t i = 0; i < TLSFP_PROFILE_COUNT; i++)
        if (strcmp(browserfp_profiles[i].ja4, ja4) == 0) return &browserfp_profiles[i];
    return NULL;
}

size_t browserfp_profile_count(void) { return TLSFP_PROFILE_COUNT; }

#define ERR_SHORT      -1
#define ERR_NOT_HS     -2
#define ERR_NOT_CH     -3
#define ERR_TRUNCATED  -4

static void list_push(browserfp_u16list *l, uint16_t v) {
    if (l->len < TLSFP_MAX_ITEMS) l->items[l->len++] = v;
}

#ifdef TLSFP_FUZZ_COUNTERS
unsigned long browserfp_ext_hits[6];         /* SNI/groups/sigalgs/alpn/versions/其它 */
/* **计数必须放在每个 case 的体内**，不能放在 switch 之前：放前面计的是
   "看见了这个扩展"，而不是"解析体真的执行了" —— 实测把四个 case 的体改空之后，
   放在 switch 前的计数器照样满额，断言完全失灵。这与并发检查那次"比错字段"
   是同一类错误：测了一个相邻但不等价的东西。 */
#define TLSFP_EXT_SEEN(i) (browserfp_ext_hits[i]++)
#else
#define TLSFP_EXT_SEEN(id) ((void)0)
#endif

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

/* 解析 supported_groups / signature_algorithms 这类「2 字节长度 + u16 数组」的扩展。
 * skip_grease 仅对 curves 有意义：Chrome 会在 supported_groups 里塞 GREASE。 */
static void parse_u16_vector(const uint8_t *body, size_t len,
                             browserfp_u16list *out, int skip_grease) {
    if (len < 2) return;
    size_t n = rd16(body);
    if (n + 2 > len) n = len - 2;
    for (size_t i = 0; i + 1 < n; i += 2) {
        uint16_t v = rd16(body + 2 + i);
        if (skip_grease && browserfp_is_grease(v)) continue;
        list_push(out, v);
    }
}

int browserfp_parse_client_hello(const uint8_t *rec, size_t len,
                               browserfp_hello *out) {
    memset(out, 0, sizeof(*out));
    if (len < 5) return ERR_SHORT;
    if (rec[0] != 0x16) return ERR_NOT_HS;

    size_t body_len = rd16(rec + 3);
    if (body_len + 5 > len) return ERR_TRUNCATED;
    const uint8_t *b = rec + 5;
    size_t o = 0;

    if (body_len < 4 || b[0] != 0x01) return ERR_NOT_CH;
    o = 4;                                   /* handshake type + 3 字节长度 */
    if (o + 2 + 32 + 1 > body_len) return ERR_TRUNCATED;
    out->client_version = rd16(b + o);
    o += 2 + 32;                             /* version + random */

    out->session_id_len = b[o];
    o += 1 + out->session_id_len;
    if (o + 2 > body_len) return ERR_TRUNCATED;

    size_t cs_len = rd16(b + o);
    o += 2;
    if (o + cs_len > body_len) return ERR_TRUNCATED;
    for (size_t i = 0; i + 1 < cs_len; i += 2) {
        uint16_t c = rd16(b + o + i);
        if (browserfp_is_grease(c)) { out->has_grease = 1; continue; }
        list_push(&out->ciphers, c);
    }
    o += cs_len;

    if (o >= body_len) return ERR_TRUNCATED;
    o += 1 + b[o];                           /* compression methods */
    if (o + 2 > body_len) return 0;          /* 无扩展，合法 */

    size_t ext_total = rd16(b + o);
    o += 2;
    size_t end = o + ext_total;
    if (end > body_len) end = body_len;

    while (o + 4 <= end) {
        uint16_t eid = rd16(b + o);
        size_t elen = rd16(b + o + 2);
        o += 4;
        if (o + elen > end) break;
        const uint8_t *ebody = b + o;

        if (browserfp_is_grease(eid)) {
            out->has_grease = 1;
        } else {
            list_push(&out->extensions, eid);
            /* 只在健壮性构建里计数：用来断言变异**真的走到了**每一个分支。
               "没崩"若是因为某个 case 从没被执行过，那是平凡通过 ——
               本项目在别处（h2 的 PRIORITY、sec-ch-ua 的两项分支）栽过同样
               的坑，所以这里把它变成可断言的数字。生产构建里整段消失。 */
            switch (eid) {
            case 0x0000:                     /* server_name */
                TLSFP_EXT_SEEN(0);
                out->has_sni = 1;
                break;
            case 0x000a:                     /* supported_groups */
                TLSFP_EXT_SEEN(1);
                parse_u16_vector(ebody, elen, &out->curves, 1);
                break;
            case 0x000d:                     /* signature_algorithms */
                TLSFP_EXT_SEEN(2);
                parse_u16_vector(ebody, elen, &out->sig_algs, 0);
                break;
            case 0x0010:                     /* ALPN：只取第一项 */
                TLSFP_EXT_SEEN(3);
                if (elen >= 3) {
                    size_t l = ebody[2];
                    if (l > 0 && 3 + l <= elen) {
                        size_t cp = l < sizeof(out->alpn_first) - 1
                                        ? l : sizeof(out->alpn_first) - 1;
                        memcpy(out->alpn_first, ebody + 3, cp);
                        out->alpn_first[cp] = '\0';
                        out->alpn_count = 1;
                    }
                }
                break;
            case 0x002b:                     /* supported_versions */
                TLSFP_EXT_SEEN(4);
                if (elen >= 1) {
                    /* **长度字段要夹到扩展体之内**：n 来自报文（1 字节，
                       最大 255），不夹的话恶意 ClientHello 声称 255 就能读到
                       扩展外、缓冲外。这条是 ASan + 精确大小堆缓冲才暴露出来的
                       —— 之前用固定大小的静态数组喂，越界落在数组内部，
                       看不见。入站识别的输入完全由对方控制，这里是真漏洞。 */
                    size_t n = ebody[0];
                    if (n + 1 > elen) n = elen - 1;
                    for (size_t i = 0; i + 1 < n; i += 2) {
                        uint16_t v = rd16(ebody + 1 + i);
                        if (!browserfp_is_grease(v))
                            list_push(&out->supported_versions, v);
                    }
                }
                break;
            default:
                break;
            }
        }
        o += elen;
    }
    return 0;
}

static int cmp_u16(const void *a, const void *b) {
    uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
    return (x > y) - (x < y);
}

/* sha256 前 12 个十六进制字符；空输入按规范记 12 个 '0' */
static void hash12(const char *s, char *out) {
    if (!s || !*s) { memcpy(out, "000000000000", 12); out[12] = '\0'; return; }
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)s, strlen(s), d);
    for (int i = 0; i < 6; i++) sprintf(out + i * 2, "%02x", d[i]);
    out[12] = '\0';
}

int browserfp_ja4(const browserfp_hello *h, char transport, char *out, size_t outlen) {
    /* **空指针必须挡在门口**：这些函数跑在 nginx worker 里，解引用一个 NULL
       不是"这个请求失败"，是整个 worker 挂掉。实测 ASan 下
       browserfp_ja4(NULL, …) 直接 SEGV。 */
    if (!h || !out || outlen == 0) return -1;
    if (outlen < TLSFP_JA4_LEN) return -1;

    /* 版本取 supported_versions 的最大值，没有该扩展则退回 client_version
     * —— 与 Python 侧一致；TLS1.3 客户端的 legacy_version 恒为 0x0303。 */
    uint16_t ver = h->client_version;
    for (size_t i = 0; i < h->supported_versions.len; i++)
        if (h->supported_versions.items[i] > ver) ver = h->supported_versions.items[i];
    const char *vs = ver == 0x0304 ? "13" : ver == 0x0303 ? "12"
                   : ver == 0x0302 ? "11" : ver == 0x0301 ? "10" : "00";

    size_t nc = h->ciphers.len > 99 ? 99 : h->ciphers.len;
    size_t ne = h->extensions.len > 99 ? 99 : h->extensions.len;

    char alpn[3] = {'0', '0', '\0'};
    if (h->alpn_count && h->alpn_first[0]) {
        size_t l = strlen(h->alpn_first);
        alpn[0] = h->alpn_first[0];
        alpn[1] = h->alpn_first[l - 1];
    }

    /* ja4_b：cipher 排序后拼接 */
    uint16_t tmp[TLSFP_MAX_ITEMS];
    memcpy(tmp, h->ciphers.items, h->ciphers.len * sizeof(uint16_t));
    qsort(tmp, h->ciphers.len, sizeof(uint16_t), cmp_u16);
    char buf[TLSFP_MAX_ITEMS * 5 + 1];
    size_t p = 0;
    for (size_t i = 0; i < h->ciphers.len; i++)
        p += sprintf(buf + p, i ? ",%04x" : "%04x", tmp[i]);
    buf[p] = '\0';
    char hb[13];
    hash12(h->ciphers.len ? buf : "", hb);

    /* ja4_c：扩展排序后拼接（**排除 SNI 0x0000 与 ALPN 0x0010**），
     * 再接 "_" 与按原序的 sig_algs。规范如此，两处都容易写错。 */
    size_t m = 0;
    for (size_t i = 0; i < h->extensions.len; i++) {
        uint16_t e = h->extensions.items[i];
        if (e == 0x0000 || e == 0x0010) continue;
        tmp[m++] = e;
    }
    qsort(tmp, m, sizeof(uint16_t), cmp_u16);
    char cbuf[TLSFP_MAX_ITEMS * 10 + 2];
    p = 0;
    for (size_t i = 0; i < m; i++)
        p += sprintf(cbuf + p, i ? ",%04x" : "%04x", tmp[i]);
    if (h->sig_algs.len) {
        p += sprintf(cbuf + p, "_");
        /* GREASE 处处忽略，签名算法列表也算（见 oracle/clienthello.py 同处注释） */
        int first = 1;
        for (size_t i = 0; i < h->sig_algs.len; i++) {
            if (browserfp_is_grease(h->sig_algs.items[i])) continue;
            p += sprintf(cbuf + p, first ? "%04x" : ",%04x", h->sig_algs.items[i]);
            first = 0;
        }
    }
    cbuf[p] = '\0';
    char hc[13];
    hash12(m ? cbuf : "", hc);

    snprintf(out, outlen, "%c%s%c%02zu%02zu%s_%s_%s",
             transport, vs, h->has_sni ? 'd' : 'i', nc, ne, alpn, hb, hc);
    return 0;
}

/* UA → profile。语义与 Python 侧 oracle/uamap.py 完全一致（由差分门禁保证）。 */
/* ---- User-Agent 解析 ---------------------------------------------------
 *
 * 与 Python 侧 oracle/uamap.py 的 parse_ua 逐字节对齐。**不用正则**：需要的
 * 只有"找子串、读十进制"，手写反而更清楚，也不用把正则库拖进 worker。
 */

/* 从 p 处读一个十进制数；没有数字返回 -1，有则写回读到哪。 */
static int ua_num(const char *p, const char **end) {
    if (*p < '0' || *p > '9') return -1;
    long v = 0;
    int overflow = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (*p - '0');
        if (v > 65535) { v = 65536; overflow = 1; }   /* 标记，不夹住 */
        p++;
    }
    if (end) *end = p;
    /* **溢出要当"认不出"，不能夹到 65535**：夹完是个看着合理的数，会去查表、
       可能命中某条 profile。真浏览器的主版本从来没有超过三位数的。 */
    if (overflow) return -1;
    return (int)v;
}

/* 找 tag 之后紧跟的数字，如 "Chrome/151" → 151。找不到返回 -1。 */
static int ua_after(const char *ua, const char *tag) {
    const char *p = strstr(ua, tag);
    if (!p) return -1;
    return ua_num(p + strlen(tag), NULL);
}

/* Safari 那条比别人多一个条件：Version/N 之后**还要出现 Safari 那个标记**，
   否则 Chrome 的 UA（它不含 Version 这个标记，但 iOS 上的壳会）会误命中。 */
static int ua_safari_version(const char *ua) {
    const char *p = strstr(ua, "Version/");
    if (!p) return -1;
    const char *end = NULL;
    int v = ua_num(p + 8, &end);
    if (v < 0) return -1;

    /* **Safari 那个标记必须紧跟其后**，中间只允许 "Mobile/xxx "。
       只检查"后面某处出现 Safari"是不够的：Android 上的 UC Browser 是
       `Version/4.0 UCBrowser/13.4 Mobile Safari/537.36` —— 后面确实有
       Safari，但它不是 Safari，而且整条 UA 里没有 Chrome/，Python 侧判的是
       "认不出"。全量差分一跑就抓到了这一条。 */
    while (*end == '.' || (*end >= '0' && *end <= '9')) end++;   /* [\d.]* */
    if (*end != ' ' && *end != '\t') return -1;
    while (*end == ' ' || *end == '\t') end++;
    if (!strncmp(end, "Mobile/", 7)) {
        end += 7;
        while (*end && *end != ' ' && *end != '\t') end++;       /* \S+ */
        if (*end != ' ' && *end != '\t') return -1;
        while (*end == ' ' || *end == '\t') end++;
    }
    return !strncmp(end, "Safari/", 7) ? v : -1;
}

static int ua_is_mobile(const char *ua) {
    return strstr(ua, "Android") || strstr(ua, "iPhone") || strstr(ua, "iPad")
        || strstr(ua, "iPod") || strstr(ua, "; Mobile")
        || strstr(ua, "Mobile Safari");
}

/* iOS 上的第三方浏览器壳。带 '/' 一起匹配，避免撞上别的词。 */
static int ua_ios_third_party(const char *ua) {
    static const char *tags[] = { "CriOS/", "FxiOS/", "EdgiOS/", "OPiOS/",
                                  "YaBrowser/" };
    for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); i++)
        if (strstr(ua, tags[i])) return 1;
    return 0;
}

int browserfp_parse_ua(const char *ua, char *brand_out, size_t brand_cap,
                   uint16_t *version) {
    if (!ua || !brand_out || !version || brand_cap < 16) return 0;
    if (strncmp(ua, "Mozilla/", 8) != 0) return 0;   /* 不是浏览器 */

    int mobile = ua_is_mobile(ua);

    /* iOS 第三方壳：TLS 栈同为系统 WebKit，一律按 iOS Safari 处理 */
    if (ua_ios_third_party(ua)) {
        const char *p = strstr(ua, "CPU iPhone OS ");
        if (p) p += 14;
        else if ((p = strstr(ua, "CPU OS ")) != NULL) p += 7;
        if (!p) return 0;
        int v = ua_num(p, NULL);
        if (v < 0) return 0;
        snprintf(brand_out, brand_cap, "safari-mobile");
        *version = (uint16_t)v;
        return 1;
    }

    /* **顺序有意义**：Edge/Opera 的 UA 里也含 Chrome/ */
    struct { const char *brand; const char *tag; } rules[] = {
        { "edge",    NULL },      /* Edg / EdgA / EdgiOS 三种写法，单独处理 */
        { "opera",   "OPR/" },
        { "firefox", "Firefox/" },
        { "safari",  NULL },      /* Version/N … Safari/ ，单独处理 */
        { "chrome",  "Chrome/" },
    };

    for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        int v = -1;
        if (!strcmp(rules[i].brand, "edge")) {
            v = ua_after(ua, "Edg/");
            if (v < 0) v = ua_after(ua, "EdgA/");
            if (v < 0) v = ua_after(ua, "EdgiOS/");
            if (v < 0) v = ua_after(ua, "Edge/");
        } else if (!strcmp(rules[i].brand, "safari")) {
            v = ua_safari_version(ua);
        } else {
            v = ua_after(ua, rules[i].tag);
        }
        if (v < 0) continue;

        /* Chromium 系衍生：**指纹由内核决定**，取 Chrome/ 那个版本号 */
        if (!strcmp(rules[i].brand, "edge") || !strcmp(rules[i].brand, "opera")) {
            int core = ua_after(ua, "Chrome/");
            if (core >= 0) v = core;
        }
        snprintf(brand_out, brand_cap, "%s%s", rules[i].brand,
                 mobile ? "-mobile" : "");
        *version = (uint16_t)v;
        return 1;
    }
    return 0;
}


const browserfp_profile *browserfp_lookup_ua(const char *brand, uint16_t version,
                                     int *confidence) {
    return browserfp_lookup_ua_ex(brand, version, confidence, 0);
}

/* Chromium 系衍生浏览器：指纹由内核决定，调用方传进来的 version 必须已经是
   UA 里 Chrome/ 的版本号（oracle/uamap.py 的 parse_ua 就是这么解析的）。
   自家表查不到时回落到内核表 —— Opera 110 的内核是 Chromium 125，而
   opera 表里不会有 125 这个号。

   **必须先剥 -mobile 再判**：移动端品牌是 edge-mobile / opera-mobile，
   拿它去和 "edge" / "opera" 逐字比永远不等，Android 版会一条都认不出来。
   Python 侧的 chromium_engine() 是同一条规则，两边必须一致。 */
static const char *chromium_engine(const char *brand) {
    if (strcmp(brand, "edge") == 0 || strcmp(brand, "opera") == 0)
        return "chrome";
    if (strcmp(brand, "edge-mobile") == 0 || strcmp(brand, "opera-mobile") == 0)
        return "chrome-mobile";
    return NULL;
}

const browserfp_profile *browserfp_lookup_ua_ex(const char *brand, uint16_t version,
                                        int *confidence, int relaxed) {
    if (!brand) return NULL;
    /* 区分"表里没有该品牌"与"有品牌但没有可用版本"：两者都返回 NULL，但
       confidence 不同，好与 Python 侧的命名对齐（差分门禁逐字符比对）。 */
    int brand_seen = 0;
    const browserfp_ua_entry *exact = NULL, *lo = NULL, *hi = NULL;
    const char *engine = chromium_engine(brand);

    /* Python 侧的语义是"把内核表并进自家表后再统一查"（own 覆盖 engine），
       不是"自家表查不到再去内核表查一遍"。两者在 lo/hi 跨表时会分歧：
       自家表只有 100、内核表只有 120，查 110 时合并语义能判 100..120 同段，
       分两趟查则各自都缺一端而弃权。所以这里在**一趟遍历**里同时收两个
       品牌的条目，并在版本号撞车时让自家表优先。 */
    for (size_t i = 0; i < TLSFP_UA_COUNT; i++) {
        const browserfp_ua_entry *e = &browserfp_ua_table[i];
        int own = strcmp(e->brand, brand) == 0;
        int eng = engine && strcmp(e->brand, engine) == 0;
        if (!own && !eng) continue;
        if (own) brand_seen = 1;

        /* 撞车时的取舍：**只有**"当前这条不是自家、新来的是自家"才替换。
           写成 `own` 就替换会退化成"取最后一条"，而原实现是命中即返回、
           即"取第一条" —— 同一 (品牌,版本) 在表里出现多次时两者结果不同，
           实测这么写会让 chrome 120/123、firefox 133 等本来正确的版本翻车。 */
        if (e->version == version) {
            if (!exact || (own && strcmp(exact->brand, brand) != 0)) exact = e;
            continue;
        }
        if (e->version < version) {
            if (!lo || e->version > lo->version) lo = e;
            else if (e->version == lo->version && own
                     && strcmp(lo->brand, brand) != 0) lo = e;
        } else {
            if (!hi || e->version < hi->version) hi = e;
            else if (e->version == hi->version && own
                     && strcmp(hi->brand, brand) != 0) hi = e;
        }
    }

    if (exact) {
        /* 由源码段表补齐的条目报 same-seg：它是段内替代而非直接采到的，
           调用方有权知道这个区别。 */
        if (confidence)
            *confidence = exact->from_seg ? TLSFP_CONF_SAME_SEG
                                          : TLSFP_CONF_EXACT;
        return &browserfp_profiles[exact->profile];
    }

    /* same-seg 需两端指纹同组**且**来源库有交集 —— 跨库的"相同"是巧合，
     * 实测 29 个多库收录的版本里 17 个存在跨库分歧。 */
    if (lo && hi && lo->fp_group == hi->fp_group && (lo->src_mask & hi->src_mask)) {
        if (confidence) *confidence = TLSFP_CONF_SAME_SEG;
        return &browserfp_profiles[hi->profile];
    }

    const browserfp_ua_entry *near = hi ? hi : lo;
    if (!near) {
        /* 衍生品牌即便自家表为空，只要内核表在就不该报 no-brand */
        if (confidence) *confidence = (brand_seen || engine) ? -2 : -1;
        return NULL;
    }
    if (confidence) *confidence = TLSFP_CONF_FALLBACK;
    /* 严格模式（默认）：跨指纹段的最近版本**不返回** —— 用它伪装等于制造
     * split-brain。调用方据 confidence 得知存在最近版本，但拿不到 profile。 */
    return relaxed ? &browserfp_profiles[near->profile] : NULL;
}


const browserfp_profile *browserfp_profile_at(size_t idx) {
    return idx < TLSFP_PROFILE_COUNT ? &browserfp_profiles[idx] : NULL;
}

/* ---- HTTP/2 连接开场组装 ------------------------------------------------- */

/* 定长数组塞不下字符串字面量的结尾 NUL，会触发
   -Wunterminated-string-initialization；用 sizeof-1 的惯用写法回避。 */
static const char H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_PREFACE_LEN (sizeof(H2_PREFACE) - 1)

static size_t put_u24(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v;
    return 3;
}

static size_t put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
    return 4;
}

/* 帧头 9 字节：长度(24) 类型(8) 标志(8) 流 ID(31，最高位保留必须为 0) */
static size_t put_frame_head(uint8_t *p, uint32_t len, uint8_t type,
                             uint8_t flags, uint32_t sid) {
    size_t n = put_u24(p, len);
    p[n++] = type;
    p[n++] = flags;
    n += put_u32(p + n, sid & 0x7FFFFFFFu);
    return n;
}

int browserfp_coherence(const char *ja4, const char *akamai,
                    const char **tls_engine, const char **h2_engine) {
    const char *t = NULL, *h = NULL;
    if (ja4) {
        const browserfp_profile *p = browserfp_lookup_ja4(ja4);
        if (p && p->engine && *p->engine) t = p->engine;
    }
    if (akamai) {
        const browserfp_h2 *x = browserfp_identify_h2(akamai);
        if (x) h = x->engine;
    }
    if (tls_engine) *tls_engine = t;
    if (h2_engine) *h2_engine = h;
    if (!t || !h) return -1;             /* 两层都要有观测才谈得上一致 */
    return strcmp(t, h) != 0;            /* 1=矛盾 */
}

const browserfp_h2 *browserfp_identify_h2(const char *akamai) {
    if (!akamai) return NULL;
    for (size_t i = 0; i < TLSFP_H2_RECORD_COUNT; i++)
        if (strcmp(browserfp_h2_records[i].akamai, akamai) == 0)
            return &browserfp_h2_records[i];
    return NULL;
}

const char *browserfp_h2_pseudo(const browserfp_h2 *h) {
    return h ? h->pseudo : NULL;
}

/* (品牌, 版本) → h2 记录。表按 (品牌, 版本) 建，与 TLS 的 profile 表分开 ——
   h2 与 TLS 的变更点不是同一批，绑在一起就会出现"TLS 对、h2 错"。 */
const browserfp_h2 *browserfp_lookup_h2(const char *brand, uint16_t version) {
    if (!brand) return NULL;
    for (size_t i = 0; i < TLSFP_H2_COUNT; i++) {
        const browserfp_h2_entry *e = &browserfp_h2_table[i];
        if (e->version == version && strcmp(e->brand, brand) == 0)
            return &browserfp_h2_records[e->rec];
    }
    return NULL;
}

int browserfp_build_h2_preface(const browserfp_h2 *p, uint8_t *out, size_t outlen) {
    if (!p || !out) return -1;
    /* 查不到 h2 数据时调用方拿到的是 NULL，走不到这里；这里再挡一层空记录，
       免得凭空造出一个不属于任何浏览器的开场。 */
    if (!p->n_settings && !p->window && !p->n_prio) return -1;

    size_t need = H2_PREFACE_LEN
                + 9 + p->n_settings * 6
                + (p->window ? 9 + 4 : 0)
                + p->n_prio * (9 + 5);
    if (outlen < need) return -1;

    size_t o = 0;
    memcpy(out + o, H2_PREFACE, H2_PREFACE_LEN);
    o += H2_PREFACE_LEN;

    /* SETTINGS：每项 6 字节（id 16 位 + value 32 位），流 ID 恒为 0。
       即便一项都没有也要发这个空帧 —— 协议要求 PREFACE 之后紧跟 SETTINGS。 */
    o += put_frame_head(out + o, (uint32_t)(p->n_settings * 6), 4, 0, 0);
    for (size_t i = 0; i < p->n_settings; i++) {
        uint32_t id = p->settings[i * 2], val = p->settings[i * 2 + 1];
        out[o++] = (uint8_t)(id >> 8);
        out[o++] = (uint8_t)id;
        o += put_u32(out + o, val);
    }

    /* 连接级 WINDOW_UPDATE（流 ID 0）。0 表示这个浏览器不发，不能补一个默认值。 */
    if (p->window) {
        o += put_frame_head(out + o, 4, 8, 0, 0);
        o += put_u32(out + o, p->window & 0x7FFFFFFFu);
    }

    /* PRIORITY：Firefox 会在开场发一组优先级树，Chrome 系一般不发。
       载荷 5 字节 = 依赖流(31) + 独占位(1) + 权重(8)。
       线上权重比实际值小 1（RFC 7540 §6.3），而 h2probe 解析时 +1 还原，
       所以这里必须减回去 —— 不减会让权重逐轮漂移。 */
    for (size_t i = 0; i < p->n_prio; i++) {
        uint32_t sid = p->prio[i * 4], dep = p->prio[i * 4 + 1];
        uint32_t excl = p->prio[i * 4 + 2], wt = p->prio[i * 4 + 3];
        o += put_frame_head(out + o, 5, 2, 0, sid);
        o += put_u32(out + o, (dep & 0x7FFFFFFFu) | (excl ? 0x80000000u : 0u));
        out[o++] = (uint8_t)(wt ? wt - 1 : 0);
    }
    return (int)o;
}

/* ---- ClientHello 组装 ---------------------------------------------------- */

static size_t put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2;
}

/* HelloRetryRequest：服务端要一个我们没发过的组时，必须补发第二条 ClientHello。
 *
 * 做法是**在 CH1 的字节上就地改写**，而不是照 profile 重新造一条。RFC 8446
 * §4.1.2 要求 CH2 与 CH1 只差指定的几处 —— random / session_id / GREASE /
 * GREASE ECH 的体全都必须原样带回。重新造就得让调用方把这些随机量存下来再传
 * 进来，多一个能出错的环节；就地改写让它们天然逐字节相同。
 *
 * 唯二要动的：key_share 换成服务端选的那一个组（RFC 规定 CH2 的 key_share 只
 * 有一条，GREASE 那条也不留），以及 padding 按新长度重算 —— key_share 从
 * 1216 字节缩到几十字节，总长会掉进 [256,512) 这一档，BoringSSL 会补上。
 *
 * 记录层版本必须是 0x0303（只有首条才是 0x0301）。这条是最后才查出来的：
 * 告警报 protocol_version，而先怀疑的是三处扩展 —— **告警码指向的是"哪一类"，
 * 不是"哪一处"**。
 */
int browserfp_rebuild_hrr(const uint8_t *ch1, size_t ch1_len, uint16_t group,
                      const uint8_t *pub, size_t publen,
                      uint8_t *out, size_t outlen) {
    if (!ch1 || ch1_len < 5 + 4 + 2 + 32 + 1 || !pub || !publen) return -1;
    const uint8_t *h = ch1 + 5;                       /* 握手头 */
    if (h[0] != 0x01) return -1;
    size_t hlen = ((size_t)h[1] << 16) | ((size_t)h[2] << 8) | h[3];
    if (5 + 4 + hlen != ch1_len) return -1;

    const uint8_t *b = h + 4;                         /* ClientHello 体 */
    size_t i = 2 + 32;                                /* 版本 + random */
    if (i + 1 > hlen) return -1;
    size_t sid = b[i]; i += 1 + sid;
    if (i + 2 > hlen) return -1;
    size_t nciph = ((size_t)b[i] << 8) | b[i + 1]; i += 2 + nciph;
    if (i + 1 > hlen) return -1;
    size_t ncomp = b[i]; i += 1 + ncomp;
    if (i + 2 > hlen) return -1;
    size_t extlen = ((size_t)b[i] << 8) | b[i + 1]; i += 2;
    if (i + extlen != hlen) return -1;

    size_t prefix = i - 2;                            /* 扩展块长度字段之前 */
    const uint8_t *ext = b + i;

    /* 第一遍：算出去掉 padding、换掉 key_share 之后的扩展块长度。 */
    uint8_t tmp[16384];
    size_t o = 0;
    int seen_ks = 0;
    for (size_t j = 0; j + 4 <= extlen; ) {
        uint16_t id = (uint16_t)((ext[j] << 8) | ext[j + 1]);
        uint16_t n  = (uint16_t)((ext[j + 2] << 8) | ext[j + 3]);
        if (j + 4 + n > extlen) return -1;
        if (id == 0x0015) { j += 4 + n; continue; }   /* padding 后面重算 */
        if (id == 0x0033) {
            seen_ks = 1;
            if (o + 4 + 2 + 4 + publen > sizeof(tmp)) return -1;
            o += put_u16(tmp + o, 0x0033);
            o += put_u16(tmp + o, (uint16_t)(2 + 4 + publen));
            o += put_u16(tmp + o, (uint16_t)(4 + publen));
            o += put_u16(tmp + o, group);
            o += put_u16(tmp + o, (uint16_t)publen);
            memcpy(tmp + o, pub, publen); o += publen;
        } else {
            if (o + 4 + n > sizeof(tmp)) return -1;
            memcpy(tmp + o, ext + j, 4 + n); o += 4 + n;
        }
        j += 4 + n;
    }
    if (!seen_ks) return -1;                          /* CH1 里没有 key_share */

    /* CH2 **不加** padding。BoringSSL 只在首条 ClientHello 加 padding（F5 规则），
       HRR 之后重建的 CH2 跳过 —— 源码里 ssl_add_clienthello_tlsext 检查
       hs->hello_retry_request，为 true 时不走 padding 分支。
       实测 bun 1.4.0：CH1=512(含 padding), CH2=302(无 padding)。 */

    size_t body_len = prefix + 2 + o;
    size_t total = 5 + 4 + body_len;
    if (total > outlen) return -1;

    size_t w = 0;
    out[w++] = 0x16;
    w += put_u16(out + w, 0x0303);                    /* CH2 的记录层版本 */
    w += put_u16(out + w, (uint16_t)(4 + body_len));
    out[w++] = 0x01;
    out[w++] = (uint8_t)(body_len >> 16);
    out[w++] = (uint8_t)(body_len >> 8);
    out[w++] = (uint8_t)body_len;
    memcpy(out + w, b, prefix); w += prefix;
    w += put_u16(out + w, (uint16_t)o);
    memcpy(out + w, tmp, o); w += o;
    return (int)w;
}

size_t browserfp_key_share_groups(const browserfp_profile *p, uint16_t *groups,
                              size_t *lens, size_t max) {
    if (!p) return 0;
    for (size_t i = 0; i < p->n_rawext; i++) {
        if (p->rawext[i] != 0x0033) continue;
        const uint8_t *b = p->extblob + p->extoff[i];
        uint16_t blen = p->extlen[i];
        size_t n = 0, j = 2;
        while (j + 4 <= blen && n < max) {
            uint16_t g = (uint16_t)((b[j] << 8) | b[j + 1]);
            uint16_t l = (uint16_t)((b[j + 2] << 8) | b[j + 3]);
            if (!browserfp_is_grease(g)) { groups[n] = g; lens[n] = l; n++; }
            j += 4 + l;
        }
        return n;
    }
    return 0;
}

int browserfp_build_client_hello(const browserfp_profile *p, const char *sni,
                             const uint8_t *random32, const uint8_t *session_id,
                             uint8_t *out, size_t outlen) {
    /* **默认是出网口径**，与 Python 侧一致。
       这里原来默认 VERBATIM，理由是"不动既有调用方" —— 而 Lua 绑定用的正是这个
       签名，于是**生产路径上 GREASE 恒为 0x4a4a/0x5a5a、ECH 恒为 218**，七处
       修复全是死的。实测四次调用字节完全一样。
       默认值要选"错了会响"的那个：重建门禁忘了传 VERBATIM 会当场比对失败（看得见），
       而生产忘了传 flags=0 是静默地发固定字节（看不见）。 */
    return browserfp_build_client_hello_ex(p, sni, random32, session_id,
                                       NULL, 0, 0, out, outlen);
}

/* 按 profile 的 key_share 形状重写公钥。形状（分组/顺序/每条长度）一律照抄，
   只换内容 —— 少一组、多一组、长度变一位，都不再是那个浏览器。
   写不下或形状对不上返回 -1。 */
/* GREASE ECH 的 body 必须**每次新鲜**，不能照抄 profile。
   config_id 只有 1 字节，固定值一旦撞上服务端真实的 ECH 配置，服务端会拿自己
   的私钥去解 payload、失败，回 handshake_failure(40)。34/81 条默认 profile 带
   0xFE0D，也就是绝大多数 Chrome 形态都埋着这个雷。

   形状照抄：kdf/aead 与 enc/payload 的**长度**都取自 profile —— payload 长度
   决定 ClientHello 总长度，是该 profile 指纹的一部分。只有内容是新鲜的。

   **本库没有内部 RNG**（内存进内存出的架构约束），随机性从调用方给的 random32
   派生：SHA256(random32 || 序号)。random32 每次连接都不同，派生出来的自然也
   不同；而库本身仍然是确定性的、可差分比对的。 */
static void ech_bytes(const uint8_t *random32, uint32_t idx,
                      uint8_t *out, size_t n) {
    uint8_t seed[36], digest[32];
    size_t done = 0;
    memcpy(seed, random32, 32);
    while (done < n) {
        uint32_t counter = idx + (uint32_t)(done / 32);
        seed[32] = (uint8_t)(counter >> 24); seed[33] = (uint8_t)(counter >> 16);
        seed[34] = (uint8_t)(counter >> 8);  seed[35] = (uint8_t)counter;
        SHA256(seed, sizeof(seed), digest);
        size_t take = n - done < 32 ? n - done : 32;
        memcpy(out + done, digest, take);
        done += take;
    }
}

#define SNI_SLOT ((size_t)-1)

/* 从 SHA256(random32 || 计数器) 取字节，够用就续。与 Python 侧 permute_extensions
 * 里的 stream() 逐字节一致 —— 计数器从 0 起、每 32 字节 +1。 */
typedef struct { const uint8_t *r; uint8_t buf[64]; size_t pos, have; uint32_t blk; } perm_rng;

static uint8_t perm_next(perm_rng *s) {
    if (s->pos >= s->have) {
        ech_bytes(s->r, s->blk, s->buf, 32);
        s->blk += 1;
        s->pos = 0; s->have = 32;
    }
    return s->buf[s->pos++];
}

/* 拒绝采样取 [0,n)。**规则要写死**：两边必须一致，取模偏置在这里不是精度问题
 * 而是"两边排出不同顺序"。 */
static size_t perm_below(perm_rng *s, size_t n) {
    size_t limit = 256 - (256 % n);
    for (;;) {
        uint8_t b = perm_next(s);
        if (b < limit) return b % n;
    }
}

/* 就地打乱 seq[]，GREASE / padding / pre_shared_key 的位置钉住。 */
static void permute_seq(const browserfp_profile *p, size_t *seq, size_t n_seq,
                        const uint8_t *random32) {
    size_t mov[TLSFP_MAX_ITEMS + 1], n_mov = 0;
    for (size_t k = 0; k < n_seq; k++) {
        uint16_t id = seq[k] == SNI_SLOT ? 0x0000 : p->rawext[seq[k]];
        if (id == 0x0015 || id == 0x0029 || browserfp_is_grease(id)) continue;
        mov[n_mov++] = k;
    }
    if (n_mov < 2) return;

    size_t picked[TLSFP_MAX_ITEMS + 1];
    for (size_t k = 0; k < n_mov; k++) picked[k] = seq[mov[k]];

    perm_rng rng = { random32, {0}, 0, 0, 0 };
    for (size_t k = n_mov - 1; k > 0; k--) {
        size_t j = perm_below(&rng, k + 1);
        size_t t = picked[k]; picked[k] = picked[j]; picked[j] = t;
    }
    for (size_t k = 0; k < n_mov; k++) seq[mov[k]] = picked[k];
}

/* GREASE ECH 的**整个扩展体**长度每次连接随机，取自这个固定集合。
   26 次本地抓包（curl_cffi chrome119 与 chrome131）实测都是这四个，两两差 32，
   且与 profile 自身大小无关。照抄 golden 会让我们的 JA4 永不变化，而真实客户端
   在变 —— 一个 JA4 恒定的"Chrome"在聚合统计里很显眼。推导见 oracle/chbuild.py。 */
static const uint16_t browserfp_ech_body_lens[4] = {186, 218, 250, 282};

static int rewrite_ech(const uint8_t *body, uint16_t blen,
                       const uint8_t *random32, int verbatim,
                       uint8_t *out, uint16_t *outlen) {
    if (blen < 8) return -1;
    uint16_t enc_len = (uint16_t)((body[6] << 8) | body[7]);
    if ((size_t)8 + enc_len + 2 > blen) return -1;
    uint16_t pay_len = (uint16_t)((body[8 + enc_len] << 8) | body[9 + enc_len]);
    if ((size_t)10 + enc_len + pay_len != blen) return -1;
    /* **只对实测过的族随机**：blen 已经在集合里才认。Firefox 的 golden 是
       249/281/569（模 32 余 25），与这组（余 26）不是同一个族 —— 套过去等于
       凭空造一个没人发过的长度。没测过的栈保持 golden 长度。 */
    if (!verbatim) {
        int known = 0;
        for (int i = 0; i < 4; i++) if (browserfp_ech_body_lens[i] == blen) known = 1;
        if (known) {
            uint8_t pick[1];
            ech_bytes(random32, 7, pick, 1);
            uint16_t want = browserfp_ech_body_lens[pick[0] & 3];
            if (want > 10 + enc_len) pay_len = (uint16_t)(want - 10 - enc_len);
        }
    }

    size_t o = 0;
    out[o++] = 0x00;                         /* outer */
    out[o++] = body[1]; out[o++] = body[2];  /* kdf   */
    out[o++] = body[3]; out[o++] = body[4];  /* aead  */
    ech_bytes(random32, 1, out + o, 1); o += 1;            /* config_id */
    out[o++] = (uint8_t)(enc_len >> 8); out[o++] = (uint8_t)enc_len;
    ech_bytes(random32, 2, out + o, enc_len); o += enc_len;
    out[o++] = (uint8_t)(pay_len >> 8); out[o++] = (uint8_t)pay_len;
    ech_bytes(random32, 3 + enc_len, out + o, pay_len); o += pay_len;
    *outlen = (uint16_t)o;
    return 0;
}

/* 一次连接用的 GREASE 值。规格实测自真机 curl_cffi chrome119（6~10 次采样）：
   两个扩展 id 每次随机且**恒不相同**；密码套件独立；supported_groups 首项随机
   且 **key_share 里那条与它相同**；supported_versions 独立。
   取值域是 RFC 8701 的 16 个。随机性从调用方给的 random32 派生（库内无 RNG）。 */
typedef struct { uint16_t ext[2], cipher, group, version; } browserfp_grease;

static uint16_t grease_at(const uint8_t *random32, uint32_t idx) {
    uint8_t b[1];
    ech_bytes(random32, 1000 + idx, b, 1);
    return (uint16_t)(0x0A0A + 0x1010 * (b[0] & 0x0F));
}

static void pick_grease(const uint8_t *random32, browserfp_grease *g) {
    g->ext[0] = grease_at(random32, 0);
    uint32_t k = 1;
    do { g->ext[1] = grease_at(random32, k++); } while (g->ext[1] == g->ext[0]);
    g->cipher  = grease_at(random32, 100);
    g->group   = grease_at(random32, 200);
    g->version = grease_at(random32, 300);
}

/* 把一串 u16 里的 GREASE 逐个换掉 */
static void regrease_u16(uint8_t *p, size_t n_vals, const uint16_t *repl,
                         size_t n_repl) {
    size_t j = 0;
    for (size_t i = 0; i < n_vals; i++) {
        uint16_t v = (uint16_t)((p[i * 2] << 8) | p[i * 2 + 1]);
        if (!browserfp_is_grease(v)) continue;
        uint16_t nv = repl[j % n_repl]; j++;
        p[i * 2] = (uint8_t)(nv >> 8); p[i * 2 + 1] = (uint8_t)(nv & 0xff);
    }
}

static int rewrite_key_share(const uint8_t *body, uint16_t blen,
                             const browserfp_keyshare *ks, size_t n_ks,
                             uint16_t grease_group,
                             uint8_t *out, uint16_t *outlen) {
    if (blen < 2) return -1;
    size_t i = 2, o = 2;
    while (i + 4 <= blen) {
        uint16_t g = (uint16_t)((body[i] << 8) | body[i + 1]);
        uint16_t n = (uint16_t)((body[i + 2] << 8) | body[i + 3]);
        if (i + 4 + n > blen) return -1;
        const uint8_t *pub = body + i + 4;
        if (browserfp_is_grease(g) && grease_group) {
            g = grease_group;            /* 与 supported_groups 那条一致 */
        }
        if (!browserfp_is_grease(g)) {
            for (size_t k = 0; k < n_ks; k++) {
                if (ks[k].group != g) continue;
                if (ks[k].pub_len != n) return -1;   /* 长度必须相同 */
                pub = ks[k].pub;
                break;
            }
        }
        if (o + 4 + n > 65535) return -1;
        out[o++] = (uint8_t)(g >> 8); out[o++] = (uint8_t)(g & 0xff);
        out[o++] = (uint8_t)(n >> 8); out[o++] = (uint8_t)(n & 0xff);
        memcpy(out + o, pub, n); o += n;
        i += 4 + n;
    }
    if (i != blen) return -1;                        /* 尾部有残渣 */
    /* **每个给进来的分组都必须在 profile 里存在**。调用方以为注入了、实际
       被忽略，是最难查的一类错：握手会用一把 profile 里的旧公钥去算共享密钥。 */
    for (size_t k = 0; k < n_ks; k++) {
        int found = 0;
        for (size_t j = 2; j + 4 <= blen; ) {
            uint16_t g = (uint16_t)((body[j] << 8) | body[j + 1]);
            uint16_t n = (uint16_t)((body[j + 2] << 8) | body[j + 3]);
            if (g == ks[k].group) { found = 1; break; }
            j += 4 + n;
        }
        if (!found) return -1;
    }
    out[0] = (uint8_t)((o - 2) >> 8);
    out[1] = (uint8_t)((o - 2) & 0xff);
    *outlen = (uint16_t)o;
    return 0;
}

int browserfp_build_client_hello_ex(const browserfp_profile *p, const char *sni,
                                const uint8_t *random32, const uint8_t *session_id,
                                const browserfp_keyshare *ks, size_t n_ks,
                                unsigned flags,
                                uint8_t *out, size_t outlen) {
    /* 注入了 key_share = 调用方真要握手。这时候不能把 profile 里那张采集当时的
       票据发出去：验不过，服务端退回完整握手 —— 一个"声称自己来过"却拿不出
       有效票据的客户端，比干净的首连更可疑。真做恢复也不可能靠照抄，binder 是
       对整段 transcript 的 HMAC。不注入时照常原样构造，那是重建验证要用的。 */
    if (n_ks) {
        for (size_t i = 0; i < p->n_rawext; i++)
            if (p->rawext[i] == 0x0029) return -1;
    }
    if (!p || !out || !p->rawciph || !p->rawext) return -1;
    if (!random32 || (p->session_id_len && !session_id)) return -1;

    /* 先拼扩展块，因为握手体长度要回填 */
    uint8_t ext[8192];
    size_t e = 0;

    /* **库里的 golden 绝大多数采自无 SNI 场景**（81 条里只有 2 条带
       server_name），所以不能只做"替换"——那样 sni 参数会被静默忽略，构造出
       的握手压根没有 SNI，多租户站点直接 handshake_failure。需要在正确位置
       **插入**：真实浏览器把 server_name 排在首个 GREASE 之后、其余扩展之前。 */
    int sni_done = 0;
    for (size_t i = 0; i < p->n_rawext; i++) {
        if (p->rawext[i] == 0x0000) { sni_done = 1; break; }
    }
    browserfp_grease g;
    int regrease = !(flags & TLSFP_BUILD_VERBATIM);
    size_t n_ext_g = 0;
    if (regrease) pick_grease(random32, &g);

    size_t sni_at = 0;
    if (!sni_done && sni) {
        /* 首个 GREASE 之后；没有 GREASE 就放最前 */
        if (p->n_rawext && browserfp_is_grease(p->rawext[0])) sni_at = 1;
    }

    /* —— Chrome 106+ 每连接打乱扩展顺序 ——
     *
     * 真 Chromium 每次连接的扩展顺序都不同（RFC 8701 permutation），本仓实测
     * 真机 5 次连接出 5 种顺序、Firefox 恒 1 种。**恒定顺序是真 Chrome 110+
     * 永远产不出来的东西**，与照抄固定 GREASE 属于同一类破绽。
     *
     * 规则取自 utls 的 ShuffleChromeTLSExtensions：GREASE / padding /
     * pre_shared_key 位置钉住，其余全部打乱。
     *
     * **派生必须与 Python 侧逐字节一致**（oracle/chbuild.py 的
     * permute_extensions）：同一个 random32 要排出同一个顺序，否则三方差分
     * 立刻炸，而且不可调试。两边都是 SHA256(random32 || 计数器) 的字节流 +
     * 拒绝采样的 Fisher-Yates。
     *
     * seq[] 存的是**源下标**：i < n_rawext 表示 p->rawext[i]，SNI_SLOT 表示
     * 那个插进来的 SNI。存 id 不行 —— 扩展体要靠下标去 extblob 里取。 */
    size_t seq[TLSFP_MAX_ITEMS + 1];
    size_t n_seq = 0;
    for (size_t i = 0; i < p->n_rawext; i++) {
        if (!sni_done && sni && i == sni_at) seq[n_seq++] = SNI_SLOT;
        seq[n_seq++] = i;
    }
    if (!sni_done && sni && sni_at >= p->n_rawext) seq[n_seq++] = SNI_SLOT;

    if (!(flags & TLSFP_BUILD_VERBATIM) && p->engine
        && !strcmp(p->engine, "chromium")) {
        permute_seq(p, seq, n_seq, random32);
    }

    for (size_t k = 0; k < n_seq; k++) {
        size_t i = seq[k];
        if (i == SNI_SLOT) {
            size_t n = strlen(sni);
            if (n > 4096 || e + 9 + n > sizeof(ext)) return -1;
            e += put_u16(ext + e, 0x0000);
            e += put_u16(ext + e, (uint16_t)(n + 5));
            e += put_u16(ext + e, (uint16_t)(n + 3));
            ext[e++] = 0x00;
            e += put_u16(ext + e, (uint16_t)n);
            memcpy(ext + e, sni, n); e += n;
            sni_done = 1;
            continue;
        }
        uint16_t id = p->rawext[i];
        if (regrease && browserfp_is_grease(id)) id = g.ext[n_ext_g++ % 2];
        const uint8_t *body = p->extblob + p->extoff[i];
        uint16_t blen = p->extlen[i];

        if (id == 0x0000 && sni) {
            /* 重写 SNI：真实请求必须带正确域名，否则多租户站点直接拒绝。
               结构 = list_len(2) + type(1) + name_len(2) + name */
            size_t n = strlen(sni);
            if (n > 4096 || e + 9 + n > sizeof(ext)) return -1;
            e += put_u16(ext + e, id);
            e += put_u16(ext + e, (uint16_t)(n + 5));
            e += put_u16(ext + e, (uint16_t)(n + 3));
            ext[e++] = 0x00;
            e += put_u16(ext + e, (uint16_t)n);
            memcpy(ext + e, sni, n); e += n;
            continue;
        }
        if (regrease && (id == 0x000A || id == 0x002B) && blen >= 2) {
            /* supported_groups / supported_versions 的首项是 GREASE，也要换。
               两者的前缀长度不同：groups 是 2 字节列表长，versions 是 1 字节。 */
            uint8_t tmp[512];
            if (blen > sizeof(tmp)) return -1;
            memcpy(tmp, body, blen);
            size_t pre = (id == 0x000A) ? 2 : 1;
            uint16_t repl = (id == 0x000A) ? g.group : g.version;
            regrease_u16(tmp + pre, (size_t)(blen - pre) / 2, &repl, 1);
            if (e + 4 + blen > sizeof(ext)) return -1;
            e += put_u16(ext + e, id);
            e += put_u16(ext + e, blen);
            memcpy(ext + e, tmp, blen); e += blen;
            continue;
        }
        if (id == 0xFE0D && blen >= 8) {
            uint8_t tmp[4096];
            uint16_t tlen = 0;
            if (blen > sizeof(tmp)) return -1;
            if (rewrite_ech(body, blen, random32,
                            (flags & TLSFP_BUILD_VERBATIM) != 0,
                            tmp, &tlen) != 0) return -1;
            if (e + 4 + tlen > sizeof(ext)) return -1;
            e += put_u16(ext + e, id);
            e += put_u16(ext + e, tlen);
            memcpy(ext + e, tmp, tlen); e += tlen;
            continue;
        }
        if (id == 0x0033 && (n_ks || regrease)) {
            /* **没有注入公钥时也要进来**：key_share 里那条 GREASE 的组 id 要跟
               supported_groups 保持一致。第一版写的是 `&& n_ks`，于是不注入时
               整段照抄 golden，GREASE 组与 supported_groups 对不上 —— 实测
               grp=0x8a8a 而 ks 还是 golden 的 0xaaaa。 */
            /* key_share：只换公钥，形状照抄。见 rewrite_key_share 的说明。 */
            uint8_t tmp[8192];
            uint16_t tlen = 0;
            if (blen > sizeof(tmp)) return -1;
            if (rewrite_key_share(body, blen, ks, n_ks,
                                  regrease ? g.group : 0, tmp, &tlen) != 0)
                return -1;
            if (e + 4 + tlen > sizeof(ext)) return -1;
            e += put_u16(ext + e, id);
            e += put_u16(ext + e, tlen);
            memcpy(ext + e, tmp, tlen); e += tlen;
            continue;
        }
        if (e + 4 + blen > sizeof(ext)) return -1;
        e += put_u16(ext + e, id);
        e += put_u16(ext + e, blen);
        if (blen) { memcpy(ext + e, body, blen); e += blen; }
    }

    /* **padding（0x0015）按实际长度重算**：BoringSSL 把 ClientHello 补齐到
       512 字节（含 4 字节握手头），**只在 256..511 之间才补**，两端之外都不发。
       判据是长度，不是"profile 里有没有记录 padding"——两个方向都实测到过：
       chrome119 照抄会多发一条（对端看到 17 个扩展、本尊 16 个），而 OkHttp 系
       不看长度就会少发一条（本尊 13 个、我们 12 个）。
       推导与全语料零反例的核对见 oracle/chbuild.py 的同名说明。

       VERBATIM 下原来整段跳过——codex (rustls TLS1.2) 无 padding 扩展、跳了不碍事。
       但 bun (BoringSSL TLS1.3) 有 padding 且需要按实际 SNI 长度重算：golden 里的
       padding 是采集时那个 SNI 算的，换了 SNI 就不对了。
       修法：profile 的 rawext 里有 0x0015 就重算，即使 VERBATIM。codex 无 0x0015
       不受影响。 */
    {
        size_t no_pad = 0;
        for (size_t i = 0; i + 4 <= e; ) {
            uint16_t id2 = (uint16_t)((ext[i] << 8) | ext[i + 1]);
            uint16_t n2 = (uint16_t)((ext[i + 2] << 8) | ext[i + 3]);
            if (id2 != 0x0015) no_pad += 4 + n2;
            i += 4 + n2;
        }
        int profile_has_pad = 0;
        for (size_t k = 0; k < p->n_rawext; k++)
            if (p->rawext[k] == 0x0015) { profile_has_pad = 1; break; }
        if (!(flags & TLSFP_BUILD_VERBATIM) || profile_has_pad) {
            size_t fixed = 4 + 2 + 32 + 1 + p->session_id_len
                         + 2 + p->n_rawciph * 2 + 2 + 2 + no_pad;
            uint8_t tmp[sizeof(ext)];
            size_t o = 0;
            for (size_t i = 0; i + 4 <= e; ) {
                uint16_t id2 = (uint16_t)((ext[i] << 8) | ext[i + 1]);
                uint16_t n2 = (uint16_t)((ext[i + 2] << 8) | ext[i + 3]);
                if (id2 != 0x0015) { memcpy(tmp + o, ext + i, 4 + n2); o += 4 + n2; }
                i += 4 + n2;
            }
            if (fixed >= 256 && fixed + 5 <= 512) {
                size_t need = 512 - fixed - 4;
                if (o + 4 + need > sizeof(tmp)) return -1;
                o += put_u16(tmp + o, 0x0015);
                o += put_u16(tmp + o, (uint16_t)need);
                memset(tmp + o, 0, need); o += need;
            } else if (fixed >= 508 && fixed <= 511) {
                /* BoringSSL 边界：剩余空间装不下 4B 头 + 1B body 时，发最小
                   padding（body=1）。总长超过 512 是 BoringSSL 自己的行为。
                   实测 bun 1.4.0：m0 508→body=1, 509→body=1, 510→body=1, 511→body=1。
                   判据见 bun_clienthello.lua 的同名注释与
                   spec/clienthello_padding_edge_spec.lua。 */
                if (o + 5 > sizeof(tmp)) return -1;
                o += put_u16(tmp + o, 0x0015);
                o += put_u16(tmp + o, 1);
                tmp[o++] = 0;
            }
            memcpy(ext, tmp, o);
            e = o;
        }
    }

    size_t body_len = 2 + 32 + 1 + p->session_id_len
                    + 2 + p->n_rawciph * 2 + 2 + 2 + e;
    size_t total = 5 + 4 + body_len;
    if (total > outlen) return -1;

    size_t o = 0;
    out[o++] = 0x16;                              /* handshake */
    o += put_u16(out + o, 0x0301);                /* record 版本恒 TLS1.0 */
    o += put_u16(out + o, (uint16_t)(4 + body_len));
    out[o++] = 0x01;                              /* client_hello */
    out[o++] = (uint8_t)(body_len >> 16);
    o += put_u16(out + o, (uint16_t)body_len);
    o += put_u16(out + o, p->client_version);
    memcpy(out + o, random32, 32); o += 32;
    out[o++] = (uint8_t)p->session_id_len;
    if (p->session_id_len) {
        memcpy(out + o, session_id, p->session_id_len);
        o += p->session_id_len;
    }
    o += put_u16(out + o, (uint16_t)(p->n_rawciph * 2));
    for (size_t i = 0; i < p->n_rawciph; i++) {
        uint16_t c = p->rawciph[i];
        if (regrease && browserfp_is_grease(c)) c = g.cipher;
        o += put_u16(out + o, c);
    }
    out[o++] = 0x01;                              /* compression 长度 */
    out[o++] = 0x00;                              /* null */
    o += put_u16(out + o, (uint16_t)e);
    memcpy(out + o, ext, e); o += e;
    return (int)o;
}
