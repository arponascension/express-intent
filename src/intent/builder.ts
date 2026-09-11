import type { Intent, IntentOptions } from '../domain/index.js';
import { validateIntentOptions } from '../domain/index.js';
import { IntentValidationError } from '../errors.js';

export function defineIntent<TKey extends string = string>(
  key: TKey,
  options: IntentOptions = {},
): Intent<TKey> {
  if (typeof key !== 'string' || key.trim().length === 0) {
    throw new IntentValidationError(
      'Intent key must be a non-empty string (e.g. "payment.create").',
    );
  }
  const issues = validateIntentOptions(options);
  if (issues.length > 0) {
    const detail = issues.map((i) => `${i.path}: ${i.message}`).join('; ');
    throw new IntentValidationError(`Invalid IntentOptions for "${key}": ${detail}`, issues);
  }
  return Object.freeze({
    key,
    auth: options.auth ?? 'required',
    sensitivity: options.sensitivity ?? 'internal',
    mutation: options.mutation ?? 'read',
    velocity: options.velocity ?? null,
    anomaly: options.anomaly ?? null,
    authFreshness: options.authFreshness ?? null,
    quotas: options.quotas ?? [],
    tags: options.tags ?? [],
    decisionOverrides: Object.freeze({ ...(options.decisionOverrides ?? {}) }),
  } as Intent<TKey>);
}

export { IntentValidationError };
export type { Intent, IntentOptions };
