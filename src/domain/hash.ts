import { createHash } from 'node:crypto';

import type { Decision } from './decision.js';
import type { IntentContext } from './context.js';
import type { Risk } from './risk.js';

function stableStringify(value: unknown, seen = new Set<unknown>()): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (seen.has(value)) {
    return '"[circular]"';
  }
  seen.add(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v, seen)).join(',')}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v, seen)}`).join(',')}}`;
}

export function hashContext(ctx: IntentContext): string {
  return createHash('sha256').update(stableStringify(ctx)).digest('hex').slice(0, 16);
}

export function hashDecision(d: Decision): string {
  return createHash('sha256').update(stableStringify(d)).digest('hex').slice(0, 16);
}

export function hashRisk(risk: Risk): string {
  return createHash('sha256').update(stableStringify(risk)).digest('hex').slice(0, 16);
}
