const SECRET_KEY_PATTERNS: ReadonlyArray<RegExp> = [
  /^authorization$/i,
  /^proxy-authorization$/i,
  /^cookie$/i,
  /^set-cookie$/i,
  /^(x-api-key|api-key|x-auth-token|x-csrf-token|csrf-token|x-amz-security-token)$/i,
  /^(password|passwd|pwd|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|csrf[_-]?token)$/i,
  /^(credit[_-]?card|card[_-]?number|cvv|cvc|ssn|social[_-]?security|private[_-]?key)$/i,
];

const ALLOWED_NON_SECRET_PREFIXES: ReadonlyArray<RegExp> = [
  /^express_intent\./i,
  /^http\./i,
  /^net\./i,
  /^enduser\.(id|pseudo)$/i,
  /^intent\./i,
  /^risk\./i,
  /^policy\./i,
  /^decision\./i,
  /^actor\.(id|pseudo|authenticated|roles|tenant|scope|anonymous)$/i,
  /^request\.(method|path|route|user_agent)$/i,
  /^response\.(status|bytes)$/i,
];

export interface RedactionConfig {
  readonly additionalDenyPatterns?: ReadonlyArray<RegExp>;
  readonly allowList?: ReadonlyArray<RegExp>;
  readonly replacement?: string;
}

export const DEFAULT_REDACTION_CONFIG: Required<Omit<RedactionConfig, never>> = {
  additionalDenyPatterns: [],
  allowList: [],
  replacement: '[REDACTED]',
};

function matchesAny(name: string, patterns: ReadonlyArray<RegExp>): boolean {
  for (const p of patterns) if (p.test(name)) return true;
  return false;
}

export class AttributeRedactor {
  private readonly deny: ReadonlyArray<RegExp>;
  private readonly allow: ReadonlyArray<RegExp>;
  private readonly replacement: string;

  constructor(config: RedactionConfig = {}) {
    this.deny = [...SECRET_KEY_PATTERNS, ...(config.additionalDenyPatterns ?? [])];
    this.allow = [...ALLOWED_NON_SECRET_PREFIXES, ...(config.allowList ?? [])];
    this.replacement = config.replacement ?? DEFAULT_REDACTION_CONFIG.replacement;
  }

  isAllowed(key: string): boolean {
    if (matchesAny(key, this.allow)) return true;
    if (matchesAny(key, this.deny)) return false;
    return true;
  }

  filter(attributes: Readonly<Record<string, unknown>>): Record<string, string | number | boolean> {
    const out: Record<string, string | number | boolean> = {};
    for (const [k, v] of Object.entries(attributes)) {
      if (matchesAny(k, this.deny)) {
        out[k] = this.replacement;
        continue;
      }
      if (v === null || v === undefined) continue;
      if (typeof v === 'string') {
        out[k] = v.length > 1024 ? v.slice(0, 1024) + '\u2026' : v;
      } else if (typeof v === 'number' || typeof v === 'boolean') {
        out[k] = v;
      } else {
        out[k] = this.replacement;
      }
    }
    return out;
  }
}
