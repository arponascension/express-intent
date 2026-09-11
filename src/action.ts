import { defineIntent } from './intent/builder.js';
import type { Intent, IntentOptions } from './types.js';
import { IntentValidationError } from './errors.js';

export interface ActionConfig {
  readonly action?: string;
  readonly intent?: string | Intent | ActionDescriptor;
  readonly options?: IntentOptions;
  readonly auth?: IntentOptions['auth'];
  readonly sensitivity?: IntentOptions['sensitivity'];
  readonly mutation?: IntentOptions['mutation'];
  readonly velocity?: IntentOptions['velocity'];
  readonly anomaly?: IntentOptions['anomaly'];
  readonly authFreshness?: IntentOptions['authFreshness'];
  readonly quotas?: IntentOptions['quotas'];
  readonly tags?: IntentOptions['tags'];
  readonly decisionOverrides?: IntentOptions['decisionOverrides'];
}

export interface ActionDescriptor {
  readonly action: string;
  readonly intent: Intent;
}

const MAX_ACTION_LENGTH = 128;
const ACTION_PATTERN = /^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$/;

export function isIntent(obj: unknown): obj is Intent {
  return Boolean(
    obj &&
    typeof obj === 'object' &&
    'key' in obj &&
    typeof (obj as Intent).key === 'string' &&
    'auth' in obj &&
    'mutation' in obj,
  );
}

export function isActionDescriptor(obj: unknown): obj is ActionDescriptor {
  return Boolean(
    obj &&
    typeof obj === 'object' &&
    'action' in obj &&
    typeof (obj as ActionDescriptor).action === 'string' &&
    'intent' in obj &&
    typeof (obj as ActionDescriptor).intent === 'object',
  );
}

function validateActionPattern(action: string): void {
  if (action.length === 0 || action.length > MAX_ACTION_LENGTH) {
    throw new IntentValidationError(
      `Invalid action: must be between 1 and ${MAX_ACTION_LENGTH} characters, got length ${action.length}.`,
    );
  }
  if (!ACTION_PATTERN.test(action)) {
    let hint = '';
    if (action.includes('..')) {
      hint = ' (consecutive dots are not allowed)';
    } else if (/[A-Z]/.test(action)) {
      hint = ` (action names must be lowercase, try "${action.toLowerCase()}")`;
    } else if (action.includes(':') || action.includes('/')) {
      hint = ` (use dot notation, e.g. "${action.replace(/[:/]/g, '.')}")`;
    } else if (!action.includes('.')) {
      hint = ` (must contain at least two dot-separated segments, e.g. "${action}.read" or "${action}.create")`;
    } else if (/^[0-9]/.test(action)) {
      hint = ' (action segments must start with a lowercase letter)';
    }
    throw new IntentValidationError(
      `Invalid action "${action}". Expected dotted form like "payment.create" (lowercase, segments joined with ".").${hint}`,
    );
  }
}

function extractInlineOptions(input: Record<string, unknown>): IntentOptions {
  const opts: Record<string, unknown> = {};
  if ('auth' in input) opts.auth = input.auth;
  if ('sensitivity' in input) opts.sensitivity = input.sensitivity;
  if ('mutation' in input) opts.mutation = input.mutation;
  if ('velocity' in input) opts.velocity = input.velocity;
  if ('anomaly' in input) opts.anomaly = input.anomaly;
  if ('authFreshness' in input) opts.authFreshness = input.authFreshness;
  if ('quotas' in input) opts.quotas = input.quotas;
  if ('tags' in input) opts.tags = input.tags;
  if ('decisionOverrides' in input) opts.decisionOverrides = input.decisionOverrides;
  return opts as IntentOptions;
}

export function parseAction(
  input: string | ActionConfig | Intent | ActionDescriptor,
): ActionDescriptor {
  if (typeof input === 'string') {
    validateActionPattern(input);
    return { action: input, intent: defineIntent(input, {}) };
  }

  if (isActionDescriptor(input)) {
    return input;
  }

  if (isIntent(input)) {
    return { action: input.key, intent: input };
  }

  if (!input || typeof input !== 'object') {
    throw new IntentValidationError('Action config must include a string `action` field.');
  }

  // Handle { intent: Intent | ActionDescriptor }
  if ('intent' in input && isActionDescriptor((input as { intent: unknown }).intent)) {
    return (input as { intent: ActionDescriptor }).intent;
  }

  const actionName =
    typeof input.action === 'string'
      ? input.action
      : typeof (input as { intent?: unknown }).intent === 'string'
        ? (input as { intent: string }).intent
        : null;

  if (actionName === null) {
    throw new IntentValidationError('Action config must include a string `action` field.');
  }

  validateActionPattern(actionName);
  const inline = extractInlineOptions(input as Record<string, unknown>);
  const mergedOptions: IntentOptions = {
    ...inline,
    ...(input.options ?? {}),
  };
  const intent = defineIntent(actionName, mergedOptions);
  return { action: actionName, intent };
}

export function defineAction(action: string, options?: IntentOptions): ActionDescriptor {
  return parseAction(options === undefined ? action : { action, options });
}
