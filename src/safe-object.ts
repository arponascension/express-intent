const POLLUTION_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

export function safeOwnKeys(value: object): string[] {
  return Object.keys(value as Record<string, unknown>).filter((k) => !POLLUTION_KEYS.has(k));
}

export function safeOwnEntries(value: object): Array<[string, unknown]> {
  const out: Array<[string, unknown]> = [];
  for (const k of safeOwnKeys(value)) {
    out.push([k, (value as Record<string, unknown>)[k]]);
  }
  return out;
}

export function safeSpread<T extends object>(value: T | null | undefined): Record<string, unknown> {
  if (value === null || value === undefined) return {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of safeOwnEntries(value as object)) {
    out[k] = v;
  }
  return out;
}

export function isPollutionKey(k: string): boolean {
  return POLLUTION_KEYS.has(k);
}
