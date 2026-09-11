import { IntentError } from './errors.js';
import type {
  Actor,
  AuthMethod,
  AuthRequirement,
  Decision,
  Intent,
  IntentContext,
  MutationClass,
  SensitivityClass,
} from './types.js';

export type PolicySeverity = 'low' | 'medium' | 'high' | 'critical';

export type Condition =
  | { readonly kind: 'action'; readonly pattern: string }
  | { readonly kind: 'tagged'; readonly tag: string }
  | { readonly kind: 'sensitivity'; readonly value: SensitivityClass }
  | { readonly kind: 'mutation'; readonly value: MutationClass }
  | { readonly kind: 'authRequirement'; readonly value: AuthRequirement }
  | { readonly kind: 'authenticated'; readonly value: boolean }
  | { readonly kind: 'actorSubject'; readonly equals: string | null }
  | { readonly kind: 'actorRole'; readonly role: string }
  | { readonly kind: 'actorScope'; readonly scope: string }
  | {
      readonly kind: 'actorField';
      readonly field: 'subject' | 'authMethod' | 'authenticatedAt';
      readonly equals: string | number | boolean | null;
    }
  | { readonly kind: 'actorAuthMethod'; readonly value: AuthMethod | null }
  | { readonly kind: 'riskScoreAtLeast'; readonly value: number }
  | { readonly kind: 'riskScoreBelow'; readonly value: number }
  | { readonly kind: 'riskAtLeast'; readonly severity: PolicySeverity }
  | { readonly kind: 'riskBelow'; readonly severity: PolicySeverity }
  | { readonly kind: 'signalExists'; readonly name: string }
  | { readonly kind: 'signalMissing'; readonly name: string }
  | {
      readonly kind: 'signalValue';
      readonly name: string;
      readonly equals: string | number | boolean | null;
    }
  | { readonly kind: 'pathMatches'; readonly pattern: string }
  | { readonly kind: 'ipMatches'; readonly pattern: string }
  | { readonly kind: 'methodMatches'; readonly method: string }
  | { readonly kind: 'headerEquals'; readonly name: string; readonly value: string }
  | { readonly kind: 'and'; readonly all: ReadonlyArray<Condition> }
  | { readonly kind: 'or'; readonly any: ReadonlyArray<Condition> }
  | { readonly kind: 'not'; readonly inner: Condition };

export interface PolicyEffect {
  readonly decision: Decision;
}

export type PolicyEffectInput = PolicyEffect | Decision;

export interface PolicyDefinition {
  readonly id: string;
  readonly version: number;
  readonly description?: string;
  readonly when: Condition;
  readonly then: PolicyEffect;
}

export interface PolicyDefinitionInput {
  readonly id: string;
  readonly version?: number;
  readonly description?: string;
  readonly when: Condition;
  readonly then: PolicyEffectInput;
}

export interface PolicyInputShape {
  readonly intent: Intent;
  readonly context: IntentContext;
  readonly actor: Actor;
  readonly score: number;
  readonly severity: PolicySeverity;
  readonly signals: ReadonlyMap<string, unknown>;
  readonly missingSignals: ReadonlySet<string>;
}

export interface PolicyEvaluationTrace {
  readonly id: string;
  readonly matched: boolean;
  readonly durationMs: number;
  readonly decision: Decision | null;
}

export class PolicyValidationError extends IntentError {
  readonly issues: ReadonlyArray<string>;

  constructor(
    message: string,
    readonly rawIssues: ReadonlyArray<{ path: string; message: string }> = [],
  ) {
    super(message);
    this.name = 'PolicyValidationError';
    this.issues = rawIssues.map((i) => `${i.path}: ${i.message}`);
  }
}
