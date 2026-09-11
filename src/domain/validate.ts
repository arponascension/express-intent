import type {
  AuthRequirement,
  IntentOptions,
  SensitivityClass,
  MutationClass,
  WindowSpec,
} from './intent.js';

export interface ValidationIssue {
  readonly path: string;
  readonly message: string;
}

const AUTH_VALUES: ReadonlyArray<AuthRequirement> = ['anonymous', 'required', 'mfa-required'];
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
const UNITS: ReadonlyArray<WindowSpec['unit']> = ['ms', 's', 'm', 'h', 'd'];

export function validateWindowSpec(spec: unknown, path: string): ReadonlyArray<ValidationIssue> {
  const issues: ValidationIssue[] = [];
  if (spec === null || typeof spec !== 'object') {
    issues.push({ path, message: 'must be an object' });
    return issues;
  }
  const obj = spec as Record<string, unknown>;
  if (typeof obj.amount !== 'number' || !Number.isFinite(obj.amount) || obj.amount <= 0) {
    issues.push({ path: `${path}.amount`, message: 'must be a positive finite number' });
  }
  if (typeof obj.unit !== 'string' || !UNITS.includes(obj.unit as WindowSpec['unit'])) {
    issues.push({
      path: `${path}.unit`,
      message: `must be one of ${UNITS.join(', ')}`,
    });
  }
  return issues;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export function validateIntentOptions(input: unknown): ReadonlyArray<ValidationIssue> {
  const issues: ValidationIssue[] = [];
  if (!isPlainObject(input)) {
    issues.push({ path: '', message: 'must be a plain object' });
    return issues;
  }

  if (input.auth !== undefined) {
    if (typeof input.auth !== 'string' || !AUTH_VALUES.includes(input.auth as AuthRequirement)) {
      issues.push({ path: 'auth', message: `must be one of ${AUTH_VALUES.join(', ')}` });
    }
  }
  if (input.sensitivity !== undefined) {
    if (
      typeof input.sensitivity !== 'string' ||
      !SENSITIVITY_VALUES.includes(input.sensitivity as SensitivityClass)
    ) {
      issues.push({
        path: 'sensitivity',
        message: `must be one of ${SENSITIVITY_VALUES.join(', ')}`,
      });
    }
  }
  if (input.mutation !== undefined) {
    if (
      typeof input.mutation !== 'string' ||
      !MUTATION_VALUES.includes(input.mutation as MutationClass)
    ) {
      issues.push({ path: 'mutation', message: `must be one of ${MUTATION_VALUES.join(', ')}` });
    }
  }

  if (input.velocity !== undefined) {
    if (!isPlainObject(input.velocity)) {
      issues.push({ path: 'velocity', message: 'must be an object' });
    } else {
      issues.push(...validateWindowSpec(input.velocity.window, 'velocity.window'));
      if (typeof input.velocity.max !== 'number' || !Number.isInteger(input.velocity.max)) {
        issues.push({ path: 'velocity.max', message: 'must be an integer' });
      }
      if (
        typeof input.velocity.per !== 'string' ||
        !['ip', 'subject', 'pair'].includes(input.velocity.per)
      ) {
        issues.push({ path: 'velocity.per', message: 'must be ip, subject, or pair' });
      }
    }
  }

  if (input.anomaly !== undefined) {
    if (!isPlainObject(input.anomaly)) {
      issues.push({ path: 'anomaly', message: 'must be an object' });
    } else {
      if (typeof input.anomaly.threshold !== 'number') {
        issues.push({ path: 'anomaly.threshold', message: 'must be a number' });
      }
      issues.push(...validateWindowSpec(input.anomaly.window, 'anomaly.window'));
    }
  }

  if (input.authFreshness !== undefined) {
    if (!isPlainObject(input.authFreshness)) {
      issues.push({ path: 'authFreshness', message: 'must be an object' });
    } else if (
      typeof input.authFreshness.maxAgeMs !== 'number' ||
      input.authFreshness.maxAgeMs < 0
    ) {
      issues.push({ path: 'authFreshness.maxAgeMs', message: 'must be a non-negative number' });
    }
  }

  if (input.quotas !== undefined) {
    if (!Array.isArray(input.quotas)) {
      issues.push({ path: 'quotas', message: 'must be an array' });
    } else {
      for (let i = 0; i < input.quotas.length; i++) {
        const q = input.quotas[i];
        if (!isPlainObject(q)) {
          issues.push({ path: `quotas[${i}]`, message: 'must be an object' });
          continue;
        }
        if (typeof q.max !== 'number' || !Number.isInteger(q.max) || q.max < 0) {
          issues.push({ path: `quotas[${i}].max`, message: 'must be a non-negative integer' });
        }
        if (typeof q.per !== 'string' || !['subject', 'ip', 'pair'].includes(q.per)) {
          issues.push({ path: `quotas[${i}].per`, message: 'must be subject, ip, or pair' });
        }
        issues.push(...validateWindowSpec(q.window, `quotas[${i}].window`));
      }
    }
  }

  if (input.tags !== undefined) {
    if (!Array.isArray(input.tags) || !input.tags.every((t) => typeof t === 'string')) {
      issues.push({ path: 'tags', message: 'must be an array of strings' });
    }
  }

  if (input.decisionOverrides !== undefined) {
    if (!isPlainObject(input.decisionOverrides)) {
      issues.push({ path: 'decisionOverrides', message: 'must be an object' });
    } else {
      const d = input.decisionOverrides;
      if (
        d.rateLimitAt !== undefined &&
        (typeof d.rateLimitAt !== 'number' || d.rateLimitAt < 0 || d.rateLimitAt > 100)
      ) {
        issues.push({
          path: 'decisionOverrides.rateLimitAt',
          message: 'must be a number in [0, 100]',
        });
      }
      if (
        d.challengeAt !== undefined &&
        (typeof d.challengeAt !== 'number' || d.challengeAt < 0 || d.challengeAt > 100)
      ) {
        issues.push({
          path: 'decisionOverrides.challengeAt',
          message: 'must be a number in [0, 100]',
        });
      }
      if (
        d.denyAt !== undefined &&
        (typeof d.denyAt !== 'number' || d.denyAt < 0 || d.denyAt > 100)
      ) {
        issues.push({ path: 'decisionOverrides.denyAt', message: 'must be a number in [0, 100]' });
      }
      if (
        d.challengeKind !== undefined &&
        !['reauth', 'captcha', 'mfa'].includes(d.challengeKind as string)
      ) {
        issues.push({
          path: 'decisionOverrides.challengeKind',
          message: 'must be reauth, captcha, or mfa',
        });
      }
      if (
        d.challengeTtlMs !== undefined &&
        d.challengeTtlMs !== null &&
        (typeof d.challengeTtlMs !== 'number' || d.challengeTtlMs < 0)
      ) {
        issues.push({
          path: 'decisionOverrides.challengeTtlMs',
          message: 'must be a non-negative number or null',
        });
      }
      if (
        d.denyStatus !== undefined &&
        (typeof d.denyStatus !== 'number' ||
          !Number.isInteger(d.denyStatus) ||
          d.denyStatus < 400 ||
          d.denyStatus > 599)
      ) {
        issues.push({
          path: 'decisionOverrides.denyStatus',
          message: 'must be an HTTP status code (400–599)',
        });
      }
      if (
        d.limit !== undefined &&
        (typeof d.limit !== 'number' || !Number.isInteger(d.limit) || d.limit < 1)
      ) {
        issues.push({ path: 'decisionOverrides.limit', message: 'must be a positive integer' });
      }
    }
  }

  return issues;
}

export function isIntentOptions(input: unknown): input is IntentOptions {
  return validateIntentOptions(input).length === 0;
}
