import type { Request } from 'express';

import { MalformedActorError } from './errors.js';
import type { Actor, AuthMethod } from './types.js';
import type { AuthRequirement } from './types.js';
import { safeSpread } from './safe-object.js';

export type { Actor, AuthMethod };

export interface AnonymousActor {
  readonly subject: null;
  readonly authenticated: false;
  readonly authMethod: null;
  readonly roles: readonly never[];
  readonly scopes: readonly never[];
  readonly claims: Readonly<Record<string, never>>;
  readonly authenticatedAt: null;
}

export type ActorLike = Partial<Actor> | AnonymousActor | null | undefined;

export interface ActorProviderOptions {
  readonly timeoutMs?: number;
  readonly trustHeaderSubject?: boolean;
}

export type ActorProvider = (req: Request) => ActorLike | Promise<ActorLike>;

export type ActorExtractor = ActorProvider;

export const ANONYMOUS_ACTOR: AnonymousActor = {
  subject: null,
  authenticated: false,
  authMethod: null,
  roles: [],
  scopes: [],
  claims: {},
  authenticatedAt: null,
};

export function anonymousActor(): AnonymousActor {
  return ANONYMOUS_ACTOR;
}

function toString(value: unknown): string | null {
  if (typeof value === 'string' && value.length > 0 && value.length <= 1024) return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (
    Array.isArray(value) &&
    typeof value[0] === 'string' &&
    value[0].length > 0 &&
    value[0].length <= 1024
  )
    return value[0];
  return null;
}

function inferAuthMethod(authHeader: string | null, hint: unknown): AuthMethod | null {
  if (typeof hint === 'string') {
    const normalized = hint.toLowerCase();
    if (normalized === 'password' || normalized === 'oauth2' || normalized === 'sso') {
      return normalized;
    }
    if (normalized === 'api-key' || normalized === 'apikey') return 'api-key';
    if (normalized === 'mfa') return 'mfa';
    if (normalized === 'passkey') return 'passkey';
  }
  if (!authHeader) return null;
  const lower = authHeader.toLowerCase();
  if (lower.length > 1024) return 'unknown';
  if (lower.startsWith('bearer ')) return 'oauth2';
  if (lower.startsWith('basic ')) return 'password';
  if (lower.startsWith('apikey ')) return 'api-key';
  return 'unknown';
}

export function defaultActorProvider(req: Request): ActorLike {
  const subjectHeader =
    toString(req.headers['x-user-subject']) ?? toString(req.headers['x-subject']);
  const authHeader = toString(req.headers.authorization);
  const user = (req as Request & { user?: unknown }).user as
    | {
        sub?: unknown;
        subject?: unknown;
        id?: unknown;
        username?: unknown;
        email?: unknown;
        roles?: unknown;
        scopes?: unknown;
        method?: unknown;
      }
    | undefined;

  const subject =
    subjectHeader ??
    toString(user?.sub) ??
    toString(user?.subject) ??
    toString(user?.id) ??
    toString(user?.username) ??
    toString(user?.email);
  const authMethod = inferAuthMethod(authHeader, user?.method);
  const roles = Array.isArray(user?.roles)
    ? (user!.roles as ReadonlyArray<unknown>).filter(
        (r): r is string => typeof r === 'string' && r.length <= 256,
      )
    : [];
  const scopes = Array.isArray(user?.scopes)
    ? (user!.scopes as ReadonlyArray<unknown>).filter(
        (s): s is string => typeof s === 'string' && s.length <= 256,
      )
    : [];

  if (subject === null) return ANONYMOUS_ACTOR;

  return {
    subject,
    authenticated: true,
    authMethod,
    roles,
    scopes,
  };
}

export const defaultActorExtractor: ActorProvider = defaultActorProvider;

function isAnonymous(value: ActorLike): value is AnonymousActor {
  return value !== null && value !== undefined && value === ANONYMOUS_ACTOR;
}

function filterStringArray(value: unknown, maxLen: number = 256): ReadonlyArray<string> {
  if (!Array.isArray(value)) return [];
  return value.filter(
    (v): v is string => typeof v === 'string' && v.length > 0 && v.length <= maxLen,
  );
}

export function normalizeActor(
  value: ActorLike,
  requirement: AuthRequirement,
  source: string = 'actor-provider',
): Actor {
  if (value === null || value === undefined) {
    return freezeActor({ ...ANONYMOUS_ACTOR, authRequirement: requirement });
  }
  if (isAnonymous(value)) {
    return freezeActor({ ...ANONYMOUS_ACTOR, authRequirement: requirement });
  }

  if (typeof value !== 'object') {
    throw new MalformedActorError(
      `Actor from ${source} must be an object, got ${typeof value}`,
      source,
    );
  }

  const obj = value as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
      throw new MalformedActorError(`Actor from ${source} contains forbidden key "${k}"`, source);
    }
  }
  const subject = obj.subject;
  const authenticated = obj.authenticated;

  if (
    subject !== null &&
    (typeof subject !== 'string' || subject.length > 1024 || subject.length === 0)
  ) {
    throw new MalformedActorError(
      `Actor from ${source} has invalid subject: must be non-empty string up to 1024 chars or null`,
      source,
    );
  }
  if (typeof authenticated !== 'boolean') {
    throw new MalformedActorError(
      `Actor from ${source} is missing required boolean "authenticated" field`,
      source,
    );
  }

  const claims = obj.claims;
  if (
    claims !== undefined &&
    (claims === null || typeof claims !== 'object' || Array.isArray(claims))
  ) {
    throw new MalformedActorError(
      `Actor from ${source} has invalid claims: must be a plain object`,
      source,
    );
  }

  const authMethod = obj.authMethod;
  if (authMethod !== null && authMethod !== undefined && typeof authMethod !== 'string') {
    throw new MalformedActorError(
      `Actor from ${source} has invalid authMethod: must be string or null`,
      source,
    );
  }

  const authenticatedAt = obj.authenticatedAt;
  if (
    authenticatedAt !== null &&
    authenticatedAt !== undefined &&
    (typeof authenticatedAt !== 'number' || !Number.isFinite(authenticatedAt))
  ) {
    throw new MalformedActorError(
      `Actor from ${source} has invalid authenticatedAt: must be finite number or null`,
      source,
    );
  }

  return freezeActor({
    subject,
    authenticated,
    authMethod: (authMethod ?? null) as AuthMethod | null,
    authRequirement: requirement,
    roles: Object.freeze(filterStringArray(obj.roles)) as ReadonlyArray<string>,
    scopes: Object.freeze(filterStringArray(obj.scopes)) as ReadonlyArray<string>,
    claims: Object.freeze(safeSpread(claims as object | null | undefined)) as Readonly<
      Record<string, unknown>
    >,
    authenticatedAt: (authenticatedAt ?? null) as number | null,
  });
}

function freezeActor(a: Actor): Actor {
  return {
    ...a,
    roles: Object.freeze([...a.roles]) as ReadonlyArray<string>,
    scopes: Object.freeze([...a.scopes]) as ReadonlyArray<string>,
    claims: Object.freeze({ ...a.claims }) as Readonly<Record<string, unknown>>,
  };
}

export interface ResolveActorOptions {
  readonly requirement: AuthRequirement;
  readonly timeoutMs?: number;
  readonly source?: string;
}

export async function resolveActor(
  req: Request,
  provider: ActorProvider,
  options: ResolveActorOptions,
): Promise<Actor> {
  const { requirement, timeoutMs = 50, source = 'actor-provider' } = options;
  const providerResult = provider(req);
  // Fast path: provider returned a non-Promise value (sync actor providers
  // are extremely common — e.g. defaultActorProvider, header inspection).
  // Avoids creating a setTimeout + Promise wrapper on every request.
  if (!(providerResult instanceof Promise)) {
    return normalizeActor(providerResult as ActorLike, requirement, source);
  }
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await new Promise<ActorLike | 'timeout'>((resolve, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        resolve('timeout');
      }, timeoutMs);
      providerResult
        .then((value) => {
          if (!timedOut) resolve(value);
        })
        .catch(reject);
    });

    if (result === 'timeout') {
      return freezeActor({ ...ANONYMOUS_ACTOR, authRequirement: requirement });
    }
    return normalizeActor(result, requirement, source);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
