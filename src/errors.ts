import type { ValidationIssue } from './domain/index.js';

export class IntentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IntentError';
  }
}

export class IntentValidationError extends IntentError {
  readonly issues: ReadonlyArray<string>;
  readonly rawIssues: ReadonlyArray<ValidationIssue>;

  constructor(message: string, rawIssues: ReadonlyArray<ValidationIssue | string> = []) {
    super(message);
    this.name = 'IntentValidationError';
    this.rawIssues = rawIssues.map((i) => (typeof i === 'string' ? { path: '', message: i } : i));
    this.issues = rawIssues.map((i) =>
      typeof i === 'string' ? i : i.path ? `${i.path}: ${i.message}` : i.message,
    );
  }
}

export class IntentDeniedError extends IntentError {
  readonly status: number;
  readonly reason: string;
  readonly action?: string;

  constructor(reason: string, status = 403, action?: string) {
    super(`Intent denied${action ? ` for "${action}"` : ''}: ${reason} (HTTP ${status})`);
    this.name = 'IntentDeniedError';
    this.status = status;
    this.reason = reason;
    this.action = action;
  }
}

export class MalformedActorError extends IntentError {
  constructor(
    message: string,
    readonly source: string = 'actor-provider',
  ) {
    super(message);
    this.name = 'MalformedActorError';
  }
}
