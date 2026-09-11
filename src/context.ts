import { createHash } from 'node:crypto';
import type { Request } from 'express';

import type { IntentContext } from './types.js';
import { freezeContext } from './types.js';
import type { Intent } from './types.js';
import type { Actor } from './types.js';
import { resolveActor, defaultActorProvider, normalizeActor, type ActorProvider } from './actor.js';
import { safeOwnEntries } from './safe-object.js';

const EMPTY_HEADERS: Readonly<Record<string, string>> = Object.freeze({}) as Readonly<
  Record<string, string>
>;

export interface BuildContextOptions {
  readonly intent: Intent;
  readonly requestId?: string;
  readonly actorProvider?: ActorProvider;
  readonly timeoutMs?: number;
  readonly source?: string;
}

function toHeaderRecord(headers: Request['headers']): Readonly<Record<string, string>> {
  // Fast path: empty/undefined headers
  if (!headers) return EMPTY_HEADERS;
  const entries = safeOwnEntries(headers as unknown as object);
  if (entries.length === 0) return EMPTY_HEADERS;
  const out: Record<string, string> = {};
  for (let i = 0; i < entries.length; i++) {
    const k = entries[i]![0];
    const v = entries[i]![1];
    const lk = k.toLowerCase();
    if (typeof v === 'string') out[lk] = v;
    else if (Array.isArray(v) && typeof v[0] === 'string') out[lk] = v[0];
  }
  return out;
}

function bodyShapeHash(req: Request): string | null {
  const body = (req as Request & { body?: unknown }).body;
  if (body === undefined || body === null) return null;
  const state = { n: 0, bytes: 0, truncated: false };
  const shape = shapeOf(body, 0, state);
  const payload = `n=${state.n};b=${state.bytes};t=${state.truncated ? 'truncated' : 'ok'};s=${stableStringify(shape, state)}`;
  return createHash('sha256').update(payload).digest('hex').slice(0, 16);
}

const MAX_BODY_NODE_COUNT = 256;
const MAX_BODY_KEYS = 128;
const MAX_BODY_BYTES = 64 * 1024;

function shapeOf(
  value: unknown,
  depth: number,
  state: { n: number; bytes: number; truncated: boolean },
): unknown {
  if (state.bytes > MAX_BODY_BYTES) {
    state.truncated = true;
    return '…';
  }
  if (state.n > MAX_BODY_NODE_COUNT) {
    state.truncated = true;
    return '…';
  }
  state.n++;
  if (depth > 6) return '…';
  if (value === null) return null;
  if (typeof value !== 'object') {
    try {
      state.bytes += JSON.stringify(value).length;
    } catch {
      state.truncated = true;
      return 't';
    }
    return 't';
  }
  if (Array.isArray(value))
    return value.length === 0 ? '[]' : [shapeOf(value[0], depth + 1, state)];
  const out: Record<string, unknown> = {};
  let i = 0;
  for (const [k, v] of safeOwnEntries(value as object)) {
    if (i >= MAX_BODY_KEYS) {
      state.truncated = true;
      break;
    }
    out[k] = shapeOf(v, depth + 1, state);
    i++;
  }
  return out;
}

function stableStringify(value: unknown, state: { bytes: number; truncated: boolean }): string {
  if (state.bytes > MAX_BODY_BYTES * 2) return '"…"';
  if (value === null) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => stableStringify(v, state)).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort();
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v, state)}`).join(',')}}`;
}

export async function buildRequestContext(
  req: Request,
  options: BuildContextOptions,
): Promise<IntentContext> {
  const { intent, requestId, actorProvider, timeoutMs, source } = options;
  const provider: ActorProvider = actorProvider ?? defaultActorProvider;
  const actor: Actor = await resolveActor(req, provider, {
    requirement: intent.auth,
    timeoutMs,
    source,
  });

  return freezeSyncContext(req, requestId ?? '', intent, actor);
}

export function buildRequestContextSync(
  req: Request,
  intent: Intent,
  requestId?: string,
): IntentContext {
  const actor: Actor = normalizeActor(defaultActorProvider(req), intent.auth, 'actor-provider');
  return freezeSyncContext(req, requestId ?? '', intent, actor);
}

function freezeSyncContext(
  req: Request,
  requestId: string,
  intent: Intent,
  actor: Actor,
): IntentContext {
  const method = req.method;
  const path = req.path ?? req.url ?? '';
  const ip = typeof req.ip === 'string' ? req.ip : null;
  const headers = toHeaderRecord(req.headers);
  const hasBody = (req as Request & { body?: unknown }).body !== undefined;
  const ctx: IntentContext = {
    requestId,
    intent,
    actor,
    method,
    path,
    ip,
    headers,
    params: {},
    query: {},
    bodyShapeHash: hasBody ? bodyShapeHash(req) : null,
    receivedAt: Date.now(),
    extras: {},
  };
  return freezeContext(ctx, req);
}
