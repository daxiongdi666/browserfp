// TypeScript 类型声明。与 browserfp.js 的实现同步维护。

export type Reason = 'no_ua' | 'unknown_ua' | 'no_profile' | 'no_h2';

export const Reason: {
  readonly NoUA: 'no_ua';
  readonly UnknownUA: 'unknown_ua';
  readonly NoProfile: 'no_profile';
  readonly NoH2: 'no_h2';
};

export class SelectError extends Error {
  reason: Reason;
  detail: string;
  constructor(reason: Reason, detail: string);
}

export interface Spec {
  /** 目前只有 'browser'；留空即 'browser'。 */
  kind?: 'browser';
  /** 有 UA 就按 UA 解析，优先级高于 brand/version。 */
  ua?: string;
  /** chrome / firefox / safari / edge / opera / *-mobile */
  brand?: string;
  version?: number;
}

export interface H2Preface {
  /** 完整的 h2 开场字节：MAGIC + SETTINGS + WINDOW_UPDATE + PRIORITY */
  preface: Buffer;
  /** 伪头顺序，如 "m,a,s,p" */
  pseudoOrder: string;
}

export interface UAParseResult {
  brand: string;
  version: number;
}

/** Keys 持有私钥。用完必须 close()（也挂了 finalizer 兜底）。不可并发。 */
export class Keys {
  /** 这批密钥覆盖的组（顺序与 ClientHello 里一致）。 */
  groups(): number[];
  /** 用服务端选中组的公钥算共享密钥。 */
  derive(group: number, peer: Buffer | Uint8Array): Buffer;
  /** 释放全部私钥。可重复调用。 */
  close(): void;
}

/** Profile 是一个可用的浏览器指纹句柄。只读、可并发。 */
export class Profile {
  readonly id: string;
  readonly brand: string;
  readonly version: number;
  /** JA4 是**注册表记录值**（多为 nosni 采集）；线上比对请用 ja4For(sni)。 */
  readonly ja4: string;
  readonly akamai: string;
  readonly engine: string;
  readonly sessionIdLen: number;

  /**
   * 组装一条完整的 TLS record（含 5 字节头），可直接写进 socket。
   * GREASE / 扩展置换每次调用重新生成 —— 同 profile 连续调用产出字节**本来就应该不同**。
   */
  clientHello(sni: string | null | undefined, keys: Keys): Buffer;

  /** HTTP/2 开场字节 + 伪头顺序。**一个字节都不要改**。 */
  h2Preface(): H2Preface;

  /** 为该 profile 生成全部需要的 key_share。 */
  keygen(): Keys;

  /** 按给定 SNI 现算 JA4（与线上观测比较用这个，别用 profile.ja4）。 */
  ja4For(sni: string): string;
}

/**
 * 加载 libbrowserfp.so。可显式指定路径；否则按 BROWSERFP_LIB 环境变量、
 * 相对 node/ 的 ../csrc/libbrowserfp.so、以及若干常见路径依次尝试。
 */
export function load(libPath?: string): void;

/**
 * 显式指定 libcrypto 路径。**必须在任何 keygen 之前调用**。
 * 不调用时走自动探测（Homebrew openssl@3 / 常见系统路径）。
 */
export function initCrypto(libcryptoPath?: string | null): Error | null;

/** 已解析到的 OpenSSL 版本串；未初始化时返回空串。**建议记进日志**。 */
export function opensslVersion(): string;

/**
 * 从 User-Agent 解析 (品牌, 主版本)。认不出抛 SelectError('unknown_ua')。
 * Chromium 系衍生浏览器取的是**内核 Chrome 的版本**。
 */
export function parseUA(ua: string): UAParseResult;

/** 按 spec 挑一个可用的 profile。两层（TLS + h2）都要有才算可用。 */
export function select(spec: Spec): Profile;

/** select({ ua }) 的便捷包装。 */
export function selectUA(ua: string): Profile;

/** 按 JA4 反查内置 profile。**不做近似匹配**；未命中返回 null。 */
export function lookupJA4(ja4: string): Profile | null;

/** 解析 ClientHello 并算出 JA4。transport 传 't'(TCP) 或 'q'(QUIC)。 */
export function ja4(record: Buffer | Uint8Array, transport: string | number): string;

/** JA4 与 Akamai h2 指纹是否出自同一引擎。 */
export function coherence(ja4: string, akamai: string): boolean;

/** 内置 profile 总数。差分测试遍历用；生产走 select()。 */
export function count(): number;

/** 按下标取 profile。差分测试用；生产走 select()。 */
export function profileAt(idx: number): Profile | null;
