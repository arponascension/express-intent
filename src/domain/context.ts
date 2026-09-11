import type { Request } from 'express';

import type { Intent } from './intent.js';
import type { Actor } from './actor.js';

export interface IntentContext {
  readonly requestId: string;
  readonly intent: Intent;
  readonly actor: Actor;
  readonly method: string;
  readonly path: string;
  readonly ip: string | null;
  readonly headers: Readonly<Record<string, string>>;
  readonly params: Readonly<Record<string, string>>;
  readonly query: Readonly<Record<string, string>>;
  readonly bodyShapeHash: string | null;
  readonly receivedAt: number;
  readonly extras: Readonly<Record<string, unknown>>;
}

const EMPTY_PARAMS: Readonly<Record<string, string>> = Object.freeze({}) as Readonly<
  Record<string, string>
>;
const EMPTY_QUERY: Readonly<Record<string, string>> = Object.freeze({}) as Readonly<
  Record<string, string>
>;

function snapshotParams(req: Request | undefined): Readonly<Record<string, string>> {
  if (!req) return EMPTY_PARAMS;
  const params = req.params as Record<string, unknown> | undefined;
  if (!params || typeof params !== 'object') return EMPTY_PARAMS;
  let out: Record<string, string> | null = null;
  for (const k of Object.keys(params)) {
    const v = params[k];
    let s: string | undefined;
    if (typeof v === 'string') s = v;
    else if (Array.isArray(v) && typeof v[0] === 'string') s = v[0];
    if (s !== undefined) {
      if (out === null) out = {};
      out[k] = s;
    }
  }
  return out === null ? EMPTY_PARAMS : (Object.freeze(out) as Readonly<Record<string, string>>);
}

function snapshotQuery(req: Request | undefined): Readonly<Record<string, string>> {
  if (!req) return EMPTY_QUERY;
  const query = req.query as Record<string, unknown> | undefined;
  if (!query || typeof query !== 'object') return EMPTY_QUERY;
  let out: Record<string, string> | null = null;
  for (const k of Object.keys(query)) {
    const v = query[k];
    let s: string;
    if (typeof v === 'string') s = v;
    else if (Array.isArray(v)) {
      s = v.length === 0 ? '' : String(v[0] ?? '');
    } else if (v === null || v === undefined) continue;
    else s = String(v);
    if (out === null) out = {};
    out[k] = s;
  }
  return out === null ? EMPTY_QUERY : (Object.freeze(out) as Readonly<Record<string, string>>);
}

export function freezeContext(ctx: IntentContext, req?: Request): IntentContext {
  const base: IntentContext = {
    requestId: ctx.requestId,
    intent: Object.freeze(ctx.intent) as Intent,
    actor: Object.freeze({
      ...ctx.actor,
      roles: Object.freeze([...ctx.actor.roles]) as ReadonlyArray<string>,
      scopes: Object.freeze([...ctx.actor.scopes]) as ReadonlyArray<string>,
      claims: Object.freeze({ ...ctx.actor.claims }) as Readonly<Record<string, unknown>>,
    }) as Actor,
    method: ctx.method,
    path: ctx.path,
    ip: ctx.ip,
    headers: Object.freeze({ ...ctx.headers }) as Readonly<Record<string, string>>,
    params: req
      ? EMPTY_PARAMS
      : (Object.freeze({ ...ctx.params }) as Readonly<Record<string, string>>),
    query: req
      ? EMPTY_QUERY
      : (Object.freeze({ ...ctx.query }) as Readonly<Record<string, string>>),
    bodyShapeHash: ctx.bodyShapeHash,
    receivedAt: ctx.receivedAt,
    extras: Object.freeze({ ...ctx.extras }) as Readonly<Record<string, unknown>>,
  };

  let object: IntentContext = base;

  if (req) {
    // Lazy + cached: req.params and req.query are populated by the express
    // router AFTER this middleware runs. Snapshot once on first read and
    // cache the frozen result, so subsequent reads are O(1). Using a
    // computed property keeps this cheaper than Object.defineProperty.
    let paramsCache: Readonly<Record<string, string>> | null = null;
    let queryCache: Readonly<Record<string, string>> | null = null;
    const params = {
      get params(): Readonly<Record<string, string>> {
        if (paramsCache === null) paramsCache = snapshotParams(req);
        return paramsCache;
      },
    };
    const query = {
      get query(): Readonly<Record<string, string>> {
        if (queryCache === null) queryCache = snapshotQuery(req);
        return queryCache;
      },
    };
    object = Object.create(base, {
      params: Object.getOwnPropertyDescriptor(params, 'params')!,
      query: Object.getOwnPropertyDescriptor(query, 'query')!,
    }) as IntentContext;
  }

  return Object.freeze(object) as IntentContext;
}

export interface RequestSnapshot {
  readonly requestId: string;
  readonly action: string;
  readonly actorSubject: string | null;
  readonly startedAt: number;
}
