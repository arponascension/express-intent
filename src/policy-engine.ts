import { allow, deny, challenge, monitor, rateLimit } from './decision/helpers.js';
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
import { compareDecisions } from './domain/decision.js';
import type {
  Condition,
  PolicyDefinition,
  PolicyDefinitionInput,
  PolicyEffect,
  PolicyEvaluationTrace,
  PolicyInputShape,
  PolicySeverity,
} from './policy-defs.js';
import { PolicyValidationError } from './policy-defs.js';

const SEVERITY_ORDER: ReadonlyArray<PolicySeverity> = ['low', 'medium', 'high', 'critical'];
const SENSITIVITY_VALUES: ReadonlyArray<SensitivityClass> = [
  'public',
  'internal',
  'pii',
  'critical',
];
const MUTATION_VALUES: ReadonlyArray<MutationClass> = [
  'none',
  'read',
  'create',
  'update',
  'destructive',
];
const AUTH_VALUES: ReadonlyArray<AuthRequirement> = ['anonymous', 'required', 'mfa-required'];
const AUTH_METHOD_VALUES: ReadonlyArray<AuthMethod> = [
  'password',
  'oauth2',
  'sso',
  'api-key',
  'mfa',
  'passkey',
  'unknown',
];

interface ValidationIssue {
  readonly path: string;
  readonly message: string;
}

const GLOB_SPECIAL = /[.+^${}()|[\]\\]/g;

function globToRegex(pattern: string): RegExp {
  let body = '';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        body += '.*';
        i++;
      } else {
        body += '[^.]*';
      }
    } else {
      body += ch.replace(GLOB_SPECIAL, (m) => `\\${m}`);
    }
  }
  return new RegExp(`^${body}$`);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

function validateCondition(c: unknown, path: string, issues: ValidationIssue[]): void {
  if (!isPlainObject(c)) {
    issues.push({ path, message: 'condition must be an object' });
    return;
  }
  const kind = c.kind;
  if (typeof kind !== 'string') {
    issues.push({ path: `${path}.kind`, message: 'must be a string' });
    return;
  }

  switch (kind) {
    case 'action':
      if (!isNonEmptyString(c.pattern))
        issues.push({ path: `${path}.pattern`, message: 'must be a non-empty string' });
      break;
    case 'tagged':
      if (!isNonEmptyString(c.tag))
        issues.push({ path: `${path}.tag`, message: 'must be a non-empty string' });
      break;
    case 'sensitivity':
      if (!SENSITIVITY_VALUES.includes(c.value as SensitivityClass))
        issues.push({
          path: `${path}.value`,
          message: `must be one of ${SENSITIVITY_VALUES.join(', ')}`,
        });
      break;
    case 'mutation':
      if (!MUTATION_VALUES.includes(c.value as MutationClass))
        issues.push({
          path: `${path}.value`,
          message: `must be one of ${MUTATION_VALUES.join(', ')}`,
        });
      break;
    case 'authRequirement':
      if (!AUTH_VALUES.includes(c.value as AuthRequirement))
        issues.push({ path: `${path}.value`, message: `must be one of ${AUTH_VALUES.join(', ')}` });
      break;
    case 'authenticated':
      if (typeof c.value !== 'boolean')
        issues.push({ path: `${path}.value`, message: 'must be boolean' });
      break;
    case 'actorSubject':
      if (c.equals !== null && !isNonEmptyString(c.equals))
        issues.push({ path: `${path}.equals`, message: 'must be string or null' });
      break;
    case 'actorRole':
      if (!isNonEmptyString(c.role))
        issues.push({ path: `${path}.role`, message: 'must be a non-empty string' });
      break;
    case 'actorScope':
      if (!isNonEmptyString(c.scope))
        issues.push({ path: `${path}.scope`, message: 'must be a non-empty string' });
      break;
    case 'actorField': {
      const field = c.field;
      if (field !== 'subject' && field !== 'authMethod' && field !== 'authenticatedAt') {
        issues.push({
          path: `${path}.field`,
          message: 'must be subject, authMethod, or authenticatedAt',
        });
      }
      const allowedTypes = ['string', 'number', 'boolean', 'object'];
      if (c.equals === null || typeof c.equals === 'undefined') {
        // ok
      } else if (field === 'subject' && typeof c.equals !== 'string' && c.equals !== null) {
        issues.push({
          path: `${path}.equals`,
          message: 'must be string or null when field is subject',
        });
      } else if (!allowedTypes.includes(typeof c.equals)) {
        issues.push({ path: `${path}.equals`, message: 'unsupported type' });
      }
      break;
    }
    case 'actorAuthMethod':
      if (c.value !== null && !AUTH_METHOD_VALUES.includes(c.value as AuthMethod))
        issues.push({
          path: `${path}.value`,
          message: `must be null or one of ${AUTH_METHOD_VALUES.join(', ')}`,
        });
      break;
    case 'riskScoreAtLeast':
    case 'riskScoreBelow': {
      const n = c.value;
      if (typeof n !== 'number' || Number.isNaN(n) || n < 0 || n > 100) {
        issues.push({ path: `${path}.value`, message: 'must be a number in [0, 100]' });
      }
      break;
    }
    case 'riskAtLeast':
    case 'riskBelow':
      if (!SEVERITY_ORDER.includes(c.severity as PolicySeverity))
        issues.push({
          path: `${path}.severity`,
          message: `must be one of ${SEVERITY_ORDER.join(', ')}`,
        });
      break;
    case 'signalExists':
    case 'signalMissing':
      if (!isNonEmptyString(c.name))
        issues.push({ path: `${path}.name`, message: 'must be a non-empty string' });
      break;
    case 'signalValue':
      if (!isNonEmptyString(c.name))
        issues.push({ path: `${path}.name`, message: 'must be a non-empty string' });
      else if (
        c.equals !== null &&
        typeof c.equals !== 'string' &&
        typeof c.equals !== 'number' &&
        typeof c.equals !== 'boolean'
      ) {
        issues.push({
          path: `${path}.equals`,
          message: 'must be string, number, boolean, or null',
        });
      }
      break;
    case 'methodMatches':
      if (!isNonEmptyString(c.method)) {
        issues.push({ path: `${path}.method`, message: 'must be a non-empty string' });
      }
      break;
    case 'pathMatches':
    case 'ipMatches':
      if (!isNonEmptyString(c.pattern)) {
        issues.push({ path: `${path}.pattern`, message: 'must be a non-empty string' });
      } else {
        try {
          new RegExp(c.pattern as string);
        } catch (e) {
          issues.push({
            path: `${path}.pattern`,
            message: `invalid regex: ${(e as Error).message}`,
          });
        }
      }
      break;
    case 'headerEquals':
      if (!isNonEmptyString(c.name))
        issues.push({ path: `${path}.name`, message: 'must be a non-empty string' });
      if (typeof c.value !== 'string')
        issues.push({ path: `${path}.value`, message: 'must be a string' });
      break;
    case 'and':
    case 'or': {
      const list = (kind === 'and' ? c.all : c.any) as ReadonlyArray<unknown> | undefined;
      if (!Array.isArray(list) || list.length === 0) {
        issues.push({
          path: `${path}.${kind === 'and' ? 'all' : 'any'}`,
          message: 'must be a non-empty array',
        });
      } else {
        list.forEach((inner, i) => validateCondition(inner, `${path}[${i}]`, issues));
      }
      break;
    }
    case 'not':
      validateCondition(c.inner, `${path}.inner`, issues);
      break;
    default:
      issues.push({ path: `${path}.kind`, message: `unknown condition kind "${String(kind)}"` });
  }
}

function validateEffect(e: unknown, path: string, issues: ValidationIssue[]): void {
  if (!isPlainObject(e)) {
    issues.push({ path, message: 'effect must be an object' });
    return;
  }
  if (!isPlainObject(e.decision)) {
    issues.push({ path: `${path}.decision`, message: 'must be an object' });
    return;
  }
  const d = e.decision as Record<string, unknown>;
  const k = d.kind;
  switch (k) {
    case 'allow':
      break;
    case 'monitor':
      if (typeof d.reason !== 'string')
        issues.push({ path: `${path}.decision.reason`, message: 'must be a string' });
      break;
    case 'rate_limit':
      if (typeof d.reason !== 'string')
        issues.push({ path: `${path}.decision.reason`, message: 'must be a string' });
      if (typeof d.limit !== 'number' || !Number.isInteger(d.limit) || d.limit < 1)
        issues.push({ path: `${path}.decision.limit`, message: 'must be a positive integer' });
      if (typeof d.remaining !== 'number' || d.remaining < 0)
        issues.push({
          path: `${path}.decision.remaining`,
          message: 'must be a non-negative number',
        });
      if (typeof d.retryAfterMs !== 'number' || d.retryAfterMs < 0)
        issues.push({
          path: `${path}.decision.retryAfterMs`,
          message: 'must be a non-negative number',
        });
      if (d.scope !== undefined && !['subject', 'ip', 'pair', 'global'].includes(d.scope as string))
        issues.push({
          path: `${path}.decision.scope`,
          message: 'must be subject, ip, pair, or global',
        });
      break;
    case 'challenge':
      if (typeof d.reason !== 'string')
        issues.push({ path: `${path}.decision.reason`, message: 'must be a string' });
      if (!['reauth', 'captcha', 'mfa'].includes(d.challenge as string))
        issues.push({
          path: `${path}.decision.challenge`,
          message: 'must be reauth, captcha, or mfa',
        });
      if (d.ttlMs !== null && (typeof d.ttlMs !== 'number' || d.ttlMs < 0))
        issues.push({
          path: `${path}.decision.ttlMs`,
          message: 'must be a non-negative number or null',
        });
      break;
    case 'deny':
      if (typeof d.reason !== 'string')
        issues.push({ path: `${path}.decision.reason`, message: 'must be a string' });
      if (typeof d.status !== 'number' || d.status < 400 || d.status > 599)
        issues.push({ path: `${path}.decision.status`, message: 'must be HTTP status in 400–599' });
      break;
    default:
      issues.push({
        path: `${path}.decision.kind`,
        message: `unknown decision kind "${String(k)}"`,
      });
  }
}

function normalizeEffect(e: unknown): unknown {
  if (isPlainObject(e) && typeof e.kind === 'string' && !('decision' in e)) {
    return { decision: e };
  }
  return e;
}

export function validatePolicyDefinition(input: unknown): PolicyDefinition {
  const issues: ValidationIssue[] = [];
  if (!isPlainObject(input)) {
    throw new PolicyValidationError('Policy definition must be a plain object', [
      { path: '', message: 'must be a plain object' },
    ]);
  }
  if (!isNonEmptyString(input.id))
    issues.push({ path: 'id', message: 'must be a non-empty string' });
  const version = input.version === undefined ? 1 : input.version;
  if (typeof version !== 'number' || !Number.isInteger(version) || version < 0)
    issues.push({ path: 'version', message: 'must be a non-negative integer' });
  if (input.description !== undefined && typeof input.description !== 'string')
    issues.push({ path: 'description', message: 'must be a string when present' });

  validateCondition(input.when, 'when', issues);

  const normalizedEffect = normalizeEffect(input.then);
  validateEffect(normalizedEffect, 'then', issues);

  if (issues.length > 0) {
    throw new PolicyValidationError(
      `Invalid policy definition "${String(input.id)}": ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}`,
      issues,
    );
  }

  const effect = normalizedEffect as PolicyEffect;
  return Object.freeze({
    id: input.id as string,
    version,
    description: input.description as string | undefined,
    when: input.when as Condition,
    then: Object.freeze({ decision: Object.freeze({ ...effect.decision }) }) as PolicyEffect,
  }) as PolicyDefinition;
}

export function definePolicy(input: PolicyDefinitionInput): PolicyDefinition {
  return validatePolicyDefinition(input);
}

export const when = {
  action(pattern: string): Condition {
    return { kind: 'action', pattern };
  },
  tag(tag: string): Condition {
    return { kind: 'tagged', tag };
  },
  tagged(tag: string): Condition {
    return { kind: 'tagged', tag };
  },
  sensitivity(value: SensitivityClass): Condition {
    return { kind: 'sensitivity', value };
  },
  mutation(value: MutationClass): Condition {
    return { kind: 'mutation', value };
  },
  authRequirement(value: AuthRequirement): Condition {
    return { kind: 'authRequirement', value };
  },
  authenticated(value = true): Condition {
    return { kind: 'authenticated', value };
  },
  subject(equals: string | null): Condition {
    return { kind: 'actorSubject', equals };
  },
  role(role: string): Condition {
    return { kind: 'actorRole', role };
  },
  scope(scope: string): Condition {
    return { kind: 'actorScope', scope };
  },
  authMethod(value: AuthMethod | null): Condition {
    return { kind: 'actorAuthMethod', value };
  },
  actorField(
    field: 'subject' | 'authMethod' | 'authenticatedAt',
    equals: string | number | boolean | null,
  ): Condition {
    return { kind: 'actorField', field, equals };
  },
  riskScoreAtLeast(value: number): Condition {
    return { kind: 'riskScoreAtLeast', value };
  },
  riskScoreBelow(value: number): Condition {
    return { kind: 'riskScoreBelow', value };
  },
  riskAtLeast(severity: PolicySeverity): Condition {
    return { kind: 'riskAtLeast', severity };
  },
  riskBelow(severity: PolicySeverity): Condition {
    return { kind: 'riskBelow', severity };
  },
  signalExists(name: string): Condition {
    return { kind: 'signalExists', name };
  },
  signalMissing(name: string): Condition {
    return { kind: 'signalMissing', name };
  },
  signalValue(name: string, equals: string | number | boolean | null): Condition {
    return { kind: 'signalValue', name, equals };
  },
  path(pattern: string): Condition {
    return { kind: 'pathMatches', pattern };
  },
  ip(pattern: string): Condition {
    return { kind: 'ipMatches', pattern };
  },
  method(method: string): Condition {
    return { kind: 'methodMatches', method };
  },
  header(name: string, value: string): Condition {
    return { kind: 'headerEquals', name, value };
  },
  and(...conditions: Condition[]): Condition {
    return { kind: 'and', all: conditions };
  },
  or(...conditions: Condition[]): Condition {
    return { kind: 'or', any: conditions };
  },
  not(inner: Condition): Condition {
    return { kind: 'not', inner };
  },
};

function compileCondition(c: Condition): (input: PolicyInputShape) => boolean {
  switch (c.kind) {
    case 'action': {
      const re = globToRegex(c.pattern);
      return (input) => re.test(input.intent.key);
    }
    case 'tagged':
      return (input) => input.intent.tags.includes(c.tag);
    case 'sensitivity':
      return (input) => input.intent.sensitivity === c.value;
    case 'mutation':
      return (input) => input.intent.mutation === c.value;
    case 'authRequirement':
      return (input) => input.intent.auth === c.value;
    case 'authenticated':
      return (input) => input.actor.authenticated === c.value;
    case 'actorSubject':
      return (input) => input.actor.subject === c.equals;
    case 'actorRole':
      return (input) => input.actor.roles.includes(c.role);
    case 'actorScope':
      return (input) => input.actor.scopes.includes(c.scope);
    case 'actorField': {
      const field = c.field;
      return (input) => {
        const a = input.actor as unknown as Record<string, unknown>;
        return a[field] === c.equals;
      };
    }
    case 'actorAuthMethod':
      return (input) => input.actor.authMethod === c.value;
    case 'riskScoreAtLeast':
      return (input) => input.score >= c.value;
    case 'riskScoreBelow':
      return (input) => input.score < c.value;
    case 'riskAtLeast': {
      const idx = SEVERITY_ORDER.indexOf(c.severity);
      return (input) => SEVERITY_ORDER.indexOf(input.severity) >= idx;
    }
    case 'riskBelow': {
      const idx = SEVERITY_ORDER.indexOf(c.severity);
      return (input) => SEVERITY_ORDER.indexOf(input.severity) < idx;
    }
    case 'signalExists':
      return (input) => input.signals.has(c.name) && !input.missingSignals.has(c.name);
    case 'signalMissing':
      return (input) => input.missingSignals.has(c.name) || !input.signals.has(c.name);
    case 'signalValue':
      return (input) => input.signals.has(c.name) && input.signals.get(c.name) === c.equals;
    case 'pathMatches': {
      const re = new RegExp(c.pattern);
      return (input) => re.test(input.context.path);
    }
    case 'ipMatches': {
      const re = new RegExp(c.pattern);
      return (input) => (input.context.ip ? re.test(input.context.ip) : false);
    }
    case 'methodMatches':
      return (input) => input.context.method.toUpperCase() === c.method.toUpperCase();
    case 'headerEquals':
      return (input) => input.context.headers[c.name.toLowerCase()] === c.value;
    case 'and': {
      const parts = c.all.map(compileCondition);
      return (input) => parts.every((p) => p(input));
    }
    case 'or': {
      const parts = c.any.map(compileCondition);
      return (input) => parts.some((p) => p(input));
    }
    case 'not': {
      const inner = compileCondition(c.inner);
      return (input) => !inner(input);
    }
  }
}

export interface CompiledPolicy {
  readonly id: string;
  readonly version: number;
  readonly description?: string;
  evaluate(input: PolicyInputShape): boolean;
  effect(input: PolicyInputShape): PolicyEffect;
}

export function compilePolicy(definition: PolicyDefinition): CompiledPolicy {
  const predicate = compileCondition(definition.when);
  return {
    id: definition.id,
    version: definition.version,
    description: definition.description,
    evaluate: predicate,
    effect: () => definition.then,
  };
}

export interface BuiltPolicy {
  readonly id: string;
  readonly version: number;
  readonly description?: string;
  evaluate(input: PolicyInputShape): { kind: 'noop' } | PolicyEffect;
}

export function toBuiltPolicy(definition: PolicyDefinition): BuiltPolicy {
  const compiled = compilePolicy(definition);
  return {
    id: compiled.id,
    version: compiled.version,
    description: compiled.description,
    evaluate(input) {
      return compiled.evaluate(input) ? compiled.effect(input) : NOOP;
    },
  };
}

export function sortPoliciesById<T extends { readonly id: string }>(
  policies: ReadonlyArray<T>,
): ReadonlyArray<T> {
  return [...policies].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

export interface EngineOptions {
  readonly policies: ReadonlyArray<BuiltPolicy>;
  readonly defaultDecision?: Decision;
  readonly deterministic?: boolean;
}

export interface EngineInput {
  readonly intent: Intent;
  readonly context: IntentContext;
  readonly actor: Actor;
  readonly score: number;
  readonly severity: PolicySeverity;
  readonly signals?: ReadonlyMap<string, unknown>;
  readonly missingSignals?: ReadonlySet<string>;
}

export interface EngineOutput {
  readonly decision: Decision;
  readonly trace: ReadonlyArray<PolicyEvaluationTrace>;
  readonly matchedPolicyIds: ReadonlyArray<string>;
}

const NOOP: { kind: 'noop' } = Object.freeze({ kind: 'noop' as const });

function mergeDecisions(a: Decision, b: Decision): Decision {
  return compareDecisions(a.kind, b.kind) <= 0 ? a : b;
}

export function evaluatePolicies(input: EngineInput, options: EngineOptions): EngineOutput {
  const deterministic = options.deterministic ?? true;
  const policies = deterministic ? sortPoliciesById(options.policies) : options.policies;
  const signals = input.signals ?? new Map<string, unknown>();
  const missingSignals = input.missingSignals ?? new Set<string>();

  const policyInput: PolicyInputShape = {
    intent: input.intent,
    context: input.context,
    actor: input.actor,
    score: input.score,
    severity: input.severity,
    signals,
    missingSignals,
  };

  const trace: PolicyEvaluationTrace[] = [];
  const matched: string[] = [];
  let merged: Decision | null = null;

  for (const policy of policies) {
    const startedAt = Date.now();
    const result = policy.evaluate(policyInput);
    const durationMs = Date.now() - startedAt;
    const matched_ = (result as { kind: string }).kind !== 'noop';
    const decision = matched_ ? (result as PolicyEffect).decision : null;
    trace.push(
      Object.freeze({
        id: policy.id,
        matched: matched_,
        durationMs,
        decision,
      }) as PolicyEvaluationTrace,
    );
    if (matched_ && decision) {
      matched.push(policy.id);
      merged = merged === null ? decision : mergeDecisions(merged, decision);
    }
  }

  const decision: Decision = merged ?? options.defaultDecision ?? allow();
  return Object.freeze({
    decision,
    trace: Object.freeze(trace) as ReadonlyArray<PolicyEvaluationTrace>,
    matchedPolicyIds: Object.freeze(matched) as ReadonlyArray<string>,
  }) as EngineOutput;
}

export {
  allow as pAllow,
  deny as pDeny,
  challenge as pChallenge,
  monitor as pMonitor,
  rateLimit as pRateLimit,
};
export { NOOP };
export type {
  Condition,
  PolicyDefinition,
  PolicyDefinitionInput,
  PolicyEffect,
  PolicyEffectInput,
  PolicySeverity,
  PolicyInputShape,
  PolicyEvaluationTrace,
} from './policy-defs.js';
export { PolicyValidationError } from './policy-defs.js';
