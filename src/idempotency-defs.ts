export type IdempotencyState = 'new' | 'in-flight' | 'done';

export interface StoredResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export interface IdempotencySnapshot {
  readonly key: string;
  readonly state: IdempotencyState;
  readonly fingerprint: string;
  readonly response: StoredResponse | null;
  readonly error: string | null;
  readonly inFlightSince: number | null;
  readonly completedAt: number | null;
  readonly expiresAt: number;
  readonly version: number;
}

export interface AcquireResult {
  readonly acquired: boolean;
  readonly current: IdempotencySnapshot | null;
}

export interface IdempotencyProvider {
  readonly name: string;
  readonly version: number;
  lookup(key: string, now?: number): Promise<IdempotencySnapshot | null>;
  acquire(key: string, fingerprint: string, ttlMs: number, now?: number): Promise<AcquireResult>;
  complete(key: string, response: StoredResponse, ttlMs: number, now?: number): Promise<void>;
  release(key: string, now?: number): Promise<void>;
  waitForCompletion(
    key: string,
    deadlineMs: number,
    now?: number,
  ): Promise<IdempotencySnapshot | null>;
  shutdown?(): Promise<void>;
}

export const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_\-:.]{1,255}$/;
export const DEFAULT_IDEMPOTENCY_TTL_MS = 24 * 60 * 60_000;
export const DEFAULT_WAIT_DEADLINE_MS = 30_000;

export function isValidIdempotencyKey(key: string): boolean {
  return IDEMPOTENCY_KEY_PATTERN.test(key);
}
