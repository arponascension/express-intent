import type { IntentContext } from './context.js';
import type { RiskSignal } from './risk.js';
import type { PolicyInput, PolicyResult } from './policy.js';
import type { AuditEvent } from '../audit-defs.js';

export type EnricherOutcome =
  | { readonly type: 'patch'; readonly patch: Readonly<Record<string, unknown>> }
  | { readonly type: 'context'; readonly context: Partial<IntentContext> }
  | { readonly type: 'error'; readonly error: Error };

export interface ContextEnricher {
  readonly name: string;
  readonly version: number;
  enrich(ctx: IntentContext): EnricherOutcome | Promise<EnricherOutcome>;
}

export interface SignalProvider {
  readonly name: string;
  readonly version: number;
  compute(ctx: IntentContext): RiskSignal | null | Promise<RiskSignal | null>;
}

export type AdapterResult = PolicyResult;

export interface PolicyAdapter {
  readonly name: string;
  readonly version: number;
  evaluate(input: PolicyInput): AdapterResult | Promise<AdapterResult>;
}

export interface StoreEntry {
  readonly count: number;
  readonly expiresAt: number;
}

export interface SignalStore {
  increment(key: string, ttlMs: number, delta?: number): Promise<number>;
  count(key: string): Promise<number>;
  reset(key: string): Promise<void>;
  shutdown?(): Promise<void>;
}

export interface DecisionSink {
  emit(event: AuditEvent): void | Promise<void>;
}

export interface Logger {
  debug(message: string, meta?: Readonly<Record<string, unknown>>): void;
  info(message: string, meta?: Readonly<Record<string, unknown>>): void;
  warn(message: string, meta?: Readonly<Record<string, unknown>>): void;
  error(message: string, meta?: Readonly<Record<string, unknown>>): void;
  child(bindings: Readonly<Record<string, unknown>>): Logger;
}
