import type { Decision } from './decision.js';
import type { IntentContext } from './context.js';
import type { Risk } from './risk.js';
import type { Intent } from './intent.js';

export interface PolicyInput {
  readonly intent: Intent;
  readonly context: IntentContext;
  readonly risk: Risk;
}

export type PolicyResult = Decision | { readonly kind: 'noop' };

export interface Policy {
  readonly name: string;
  readonly version: number;
  evaluate(input: PolicyInput): PolicyResult | Promise<PolicyResult>;
}

export function isDecision(value: PolicyResult | null | undefined): value is Decision {
  if (!value) return false;
  return (value as { kind: string }).kind !== 'noop';
}
