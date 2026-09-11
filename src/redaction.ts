export type RedactionReplacement = '[REDACTED]' | '[HIDDEN]' | string;

export interface RedactionConfig {
  readonly headerRedactions?: ReadonlyArray<RegExp | string>;
  readonly queryParamRedactions?: ReadonlyArray<RegExp | string>;
  readonly bodyKeyRedactions?: ReadonlyArray<RegExp | string>;
  readonly bodyKeyAllowList?: ReadonlyArray<RegExp | string>;
  readonly includeBody?: boolean;
  readonly maxStringLength?: number;
  readonly maxArrayLength?: number;
  readonly maxObjectKeys?: number;
  readonly replacement?: RedactionReplacement;
  readonly customFieldRedactor?: (key: string, value: unknown) => unknown;
}

const DEFAULT_HEADER_REDACTIONS: ReadonlyArray<RegExp> = [
  /^authorization$/i,
  /^proxy-authorization$/i,
  /^cookie$/i,
  /^set-cookie$/i,
  /^x-api-key$/i,
  /^api-key$/i,
  /^x-auth-token$/i,
  /^x-csrf-token$/i,
  /^csrf-token$/i,
  /^x-forwarded-for$/i,
  /^x-real-ip$/i,
  /^x-amz-security-token$/i,
];

const DEFAULT_QUERY_REDACTIONS: ReadonlyArray<RegExp> = [
  /^(token|access_token|refresh_token|id_token|api[_-]?key|apikey|password|passwd|pwd|secret|code|state)$/i,
  /^x-api-key$/i,
];

const DEFAULT_BODY_KEY_REDACTIONS: ReadonlyArray<RegExp> = [
  /^(password|passwd|pwd|current[_-]?password|new[_-]?password)$/i,
  /^(secret|secret[_-]?key|client[_-]?secret)$/i,
  /^(token|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|csrf[_-]?token|x-csrf-token)$/i,
  /^(api[_-]?key|x-api-key|apikey)$/i,
  /^(authorization|auth)$/i,
  /^(cookie|set-cookie)$/i,
  /^(credit[_-]?card|card[_-]?number|cvv|cvc|ssn|social[_-]?security)$/i,
  /^(private[_-]?key|privatekey)$/i,
];

export const DEFAULT_REDACTION_CONFIG: Required<
  Omit<RedactionConfig, 'customFieldRedactor' | 'replacement'>
> & {
  readonly replacement: string;
} = {
  headerRedactions: DEFAULT_HEADER_REDACTIONS,
  queryParamRedactions: DEFAULT_QUERY_REDACTIONS,
  bodyKeyRedactions: DEFAULT_BODY_KEY_REDACTIONS,
  bodyKeyAllowList: [],
  includeBody: false,
  maxStringLength: 1024,
  maxArrayLength: 100,
  maxObjectKeys: 100,
  replacement: '[REDACTED]',
};

function matchesAny(name: string, patterns: ReadonlyArray<RegExp | string>): boolean {
  for (const p of patterns) {
    if (typeof p === 'string') {
      if (p.toLowerCase() === name.toLowerCase()) return true;
    } else if (p.test(name)) {
      return true;
    }
  }
  return false;
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + `\u2026[truncated ${s.length - max} chars]`;
}

export class RedactionEngine {
  private readonly headerPatterns: ReadonlyArray<RegExp>;
  private readonly queryPatterns: ReadonlyArray<RegExp>;
  private readonly bodyKeyPatterns: ReadonlyArray<RegExp>;
  private readonly allowList: ReadonlyArray<RegExp | string>;
  private readonly includeBody: boolean;
  private readonly maxStringLength: number;
  private readonly maxArrayLength: number;
  private readonly maxObjectKeys: number;
  private readonly replacement: string;
  private readonly customRedactor?: (key: string, value: unknown) => unknown;

  constructor(config: RedactionConfig = {}) {
    this.headerPatterns = (config.headerRedactions ?? DEFAULT_HEADER_REDACTIONS).map(compile);
    this.queryPatterns = (config.queryParamRedactions ?? DEFAULT_QUERY_REDACTIONS).map(compile);
    this.bodyKeyPatterns = (config.bodyKeyRedactions ?? DEFAULT_BODY_KEY_REDACTIONS).map(compile);
    this.allowList = config.bodyKeyAllowList ?? [];
    this.includeBody = config.includeBody ?? DEFAULT_REDACTION_CONFIG.includeBody;
    this.maxStringLength = config.maxStringLength ?? DEFAULT_REDACTION_CONFIG.maxStringLength;
    this.maxArrayLength = config.maxArrayLength ?? DEFAULT_REDACTION_CONFIG.maxArrayLength;
    this.maxObjectKeys = config.maxObjectKeys ?? DEFAULT_REDACTION_CONFIG.maxObjectKeys;
    this.replacement = config.replacement ?? DEFAULT_REDACTION_CONFIG.replacement;
    this.customRedactor = config.customFieldRedactor;
  }

  redactHeaders(
    headers: Readonly<Record<string, string | ReadonlyArray<string> | undefined>>,
  ): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [name, raw] of Object.entries(headers)) {
      if (raw === undefined) continue;
      if (POLLUTION_KEYS.has(name)) continue;
      const display: string = Array.isArray(raw) ? raw.join(', ') : (raw as string);
      if (matchesAny(name, this.headerPatterns)) {
        out[name] = this.replacement;
      } else {
        out[name] = truncate(display, this.maxStringLength);
      }
    }
    return out;
  }

  redactQuery(query: Readonly<Record<string, unknown>>): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(query)) {
      if (POLLUTION_KEYS.has(k)) continue;
      const display =
        v === null || v === undefined ? '' : Array.isArray(v) ? v.join(',') : String(v);
      if (matchesAny(k, this.queryPatterns)) {
        out[k] = this.replacement;
      } else {
        out[k] = truncate(display, this.maxStringLength);
      }
    }
    return out;
  }

  redactBody(
    body: unknown,
    bodyKeys: ReadonlyArray<string>,
  ): { body: unknown; bodyKeys: ReadonlyArray<string> } {
    const keys = bodyKeys.slice().sort();
    if (!this.includeBody) return { body: null, bodyKeys: keys };
    if (body === null || body === undefined) return { body: null, bodyKeys: keys };
    return { body: this.walk(body, ''), bodyKeys: keys };
  }

  private walk(value: unknown, key: string): unknown {
    if (this.customRedactor !== undefined) {
      const custom = this.customRedactor(key, value);
      if (custom !== undefined) return custom;
    }
    if (value === null) return null;
    if (typeof value === 'undefined') return undefined;
    if (typeof value === 'string') return truncate(value, this.maxStringLength);
    if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint')
      return value;
    if (Array.isArray(value)) {
      if (value.length > this.maxArrayLength) {
        return [
          ...value.slice(0, this.maxArrayLength).map((v) => this.walk(v, key)),
          `[truncated ${value.length - this.maxArrayLength} more]`,
        ];
      }
      return value.map((v) => this.walk(v, key));
    }
    if (typeof value === 'object') {
      if (this.allowList.length > 0 && matchesAny(key, this.allowList)) {
        return value;
      }
      const entries = safeOwnEntries(value as object);
      const truncated = entries.length > this.maxObjectKeys;
      const out: Record<string, unknown> = {};
      const slice = truncated ? entries.slice(0, this.maxObjectKeys) : entries;
      for (const [k, v] of slice) {
        if (this.customRedactor !== undefined) {
          const custom = this.customRedactor(k, v);
          if (custom !== undefined) {
            out[k] = custom;
            continue;
          }
        }
        if (matchesAny(k, this.bodyKeyPatterns)) {
          out[k] = this.replacement;
        } else {
          out[k] = this.walk(v, k);
        }
      }
      if (truncated) {
        out['__truncated_keys__'] = entries.length - this.maxObjectKeys;
      }
      return out;
    }
    return value;
  }

  redactField(key: string, value: unknown): unknown {
    if (this.customRedactor !== undefined) {
      const custom = this.customRedactor(key, value);
      if (custom !== undefined) return custom;
    }
    if (matchesAny(key, this.bodyKeyPatterns)) return this.replacement;
    return this.walk(value, key);
  }
}

function compile(p: RegExp | string): RegExp {
  if (p instanceof RegExp) return p;
  return new RegExp(p, 'i');
}

const POLLUTION_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function safeOwnEntries(value: object): Array<[string, unknown]> {
  const out: Array<[string, unknown]> = [];
  for (const k of Object.keys(value as Record<string, unknown>)) {
    if (POLLUTION_KEYS.has(k)) continue;
    out.push([k, (value as Record<string, unknown>)[k]]);
  }
  return out;
}

export function isSensitiveHeader(name: string): boolean {
  return matchesAny(name, DEFAULT_HEADER_REDACTIONS);
}

export function isSensitiveQueryParam(name: string): boolean {
  return matchesAny(name, DEFAULT_QUERY_REDACTIONS);
}

export function isSensitiveBodyKey(name: string): boolean {
  return matchesAny(name, DEFAULT_BODY_KEY_REDACTIONS);
}
