import type { Request, Response, NextFunction } from 'express';

import { allow, deny } from './decision/helpers.js';
import {
  parseAction,
  defineAction,
  isIntent,
  type ActionDescriptor,
  type ActionConfig,
} from './action.js';
import { buildRequestContext, buildRequestContextSync } from './context.js';
import {
  getRequestSnapshot,
  getIntentContext as getAlsIntentContext,
  enterRequestScope,
  runWithRequest,
} from './als.js';
import { generateRequestId } from './request-id.js';
import type { ActorProvider, ResolveActorOptions } from './actor.js';
import type {
  Actor,
  Decision,
  IntentContext,
  Intent,
  IntentOptions,
  DenyDecision,
  ChallengeDecision,
  RateLimitDecision,
} from './types.js';
import type { BuiltPolicy, PolicyDefinition } from './policy-engine.js';
import { evaluatePolicies, toBuiltPolicy } from './policy-engine.js';
import { evaluateDecision } from './decision/engine.js';
import { IntentError, IntentDeniedError } from './errors.js';

export interface IntentPayload<TAction extends string = string> {
  readonly requestId: string;
  readonly action: TAction;
  readonly context: IntentContext;
  readonly decision: Decision;
  readonly startedAt: number;
  readonly actor: Actor;
  readonly isAllowed: boolean;
  readonly isDenied: boolean;
}

declare module 'express-serve-static-core' {
  interface Request {
    intent?: IntentPayload;
  }
}

export interface IntentRequest<TAction extends string = string> extends Request {
  readonly intent: IntentPayload<TAction>;
}

export type IntentRequestHandler<TAction extends string = string> = (
  req: IntentRequest<TAction>,
  res: Response,
  next: NextFunction,
) => void | Promise<void>;

export interface IntentMiddlewareOptions
  extends IntentOptions, Omit<ResolveActorOptions, 'requirement'> {
  readonly action?: string | Intent | ActionDescriptor;
  readonly intent?: string | Intent | ActionDescriptor;
  readonly actor?: ActorProvider;
  readonly enforce?: boolean;
  readonly throwOnDeny?: boolean;
  readonly policies?: ReadonlyArray<BuiltPolicy | PolicyDefinition>;
  readonly decisionEngine?: (input: {
    readonly intent: Intent;
    readonly context: IntentContext;
    readonly req: Request;
  }) => Decision | Promise<Decision>;
  readonly onDecision?: (req: Request, decision: Decision, action: string) => void;
  readonly onDeny?: (req: Request, res: Response, decision: DenyDecision) => void;
  readonly onChallenge?: (req: Request, res: Response, decision: ChallengeDecision) => void;
  readonly onRateLimit?: (req: Request, res: Response, decision: RateLimitDecision) => void;
}

export type IntentMiddleware = (req: Request, res: Response, next: NextFunction) => void;

export function getIntent<TAction extends string = string>(req: Request): IntentPayload<TAction> {
  const payload = (req as { intent?: IntentPayload<TAction> }).intent;
  if (!payload) {
    throw new IntentError(
      'Intent context not found on request. Ensure `intent()` middleware is mounted before calling `getIntent(req)` or accessing `req.intent`.',
    );
  }
  return payload;
}

export function getIntentContext(req?: Request): IntentContext | undefined {
  if (req) {
    const payload = (req as { intent?: IntentPayload }).intent;
    if (payload) {
      return payload.context;
    }
  }
  return getAlsIntentContext();
}

function setReqIdHeader(res: Response, requestId: string): void {
  const r = res as { setHeader?: (k: string, v: string) => void };
  if (typeof r.setHeader === 'function') r.setHeader('x-request-id', requestId);
}

function computeDecision(
  context: IntentContext,
  opts: IntentMiddlewareOptions,
  req: Request,
): Decision | Promise<Decision> {
  if (opts.decisionEngine) {
    return opts.decisionEngine({ intent: context.intent, context, req });
  }

  if (opts.policies && opts.policies.length > 0) {
    const builtPolicies: BuiltPolicy[] = opts.policies.map((p) =>
      'when' in p ? toBuiltPolicy(p as PolicyDefinition) : (p as BuiltPolicy),
    );
    const result = evaluatePolicies(
      {
        intent: context.intent,
        context,
        actor: context.actor,
        score: 0,
        severity: 'low',
      },
      { policies: builtPolicies },
    );
    return result.decision;
  }

  if (opts.enforce) {
    if (context.intent.auth === 'mfa-required' && !context.actor.authenticated) {
      return {
        kind: 'challenge',
        reason: 'MFA authentication required for this intent',
        challenge: 'mfa',
        ttlMs: null,
      };
    }
    if (context.intent.auth === 'required' && !context.actor.authenticated) {
      return deny('Authentication required for this intent', 401);
    }
    if (context.intent.mutation === 'destructive' && !context.actor.authenticated) {
      return deny('Destructive mutation requires authentication', 403);
    }
    const evalResult = evaluateDecision({
      intent: context.intent,
      actor: context.actor,
    });
    return evalResult.decision;
  }

  return allow();
}

function isEnforcementActive(opts: IntentMiddlewareOptions): boolean {
  if (opts.enforce !== undefined) return opts.enforce;
  if (opts.policies && opts.policies.length > 0) return true;
  if (opts.decisionEngine !== undefined) return true;
  return false;
}

function handleEnforcement(
  req: Request,
  res: Response,
  decision: Decision,
  descriptor: ActionDescriptor,
  requestId: string,
  opts: IntentMiddlewareOptions,
  next?: NextFunction,
): boolean {
  if (!isEnforcementActive(opts)) return false;

  if (decision.kind === 'deny') {
    if (opts.throwOnDeny && next) {
      next(new IntentDeniedError(decision.reason, decision.status || 403, descriptor.action));
      return true;
    }
    if (opts.onDeny) {
      opts.onDeny(req, res, decision);
      return true;
    }
    const status = decision.status || 403;
    res.status(status).json({
      error: status === 401 ? 'Unauthorized' : 'Forbidden',
      reason: decision.reason,
      requestId,
      action: descriptor.action,
    });
    return true;
  }

  if (decision.kind === 'challenge') {
    if (opts.onChallenge) {
      opts.onChallenge(req, res, decision);
      return true;
    }
    res.status(401).json({
      error: 'Challenge Required',
      challenge: decision.challenge,
      reason: decision.reason,
      requestId,
      action: descriptor.action,
    });
    return true;
  }

  if (decision.kind === 'rate_limit') {
    if (opts.onRateLimit) {
      opts.onRateLimit(req, res, decision);
      return true;
    }
    const retrySec = Math.max(1, Math.ceil(decision.retryAfterMs / 1000));
    const r = res as { setHeader?: (k: string, v: string) => void };
    if (typeof r.setHeader === 'function') {
      r.setHeader('Retry-After', String(retrySec));
    }
    res.status(429).json({
      error: 'Too Many Requests',
      reason: decision.reason,
      retryAfterMs: decision.retryAfterMs,
      requestId,
      action: descriptor.action,
    });
    return true;
  }

  return false;
}

function finalizeAttachAndProceed(
  req: Request,
  res: Response,
  next: NextFunction,
  requestId: string,
  descriptor: ActionDescriptor,
  context: IntentContext,
  startedAt: number,
  decision: Decision,
  opts: IntentMiddlewareOptions,
): void {
  const intentPayload: IntentPayload = {
    requestId,
    action: descriptor.action,
    context,
    decision,
    startedAt,
    get actor(): Actor {
      return context.actor;
    },
    get isAllowed(): boolean {
      return decision.kind === 'allow';
    },
    get isDenied(): boolean {
      return decision.kind === 'deny';
    },
  };
  (req as { intent?: IntentPayload }).intent = intentPayload;
  setReqIdHeader(res, requestId);
  enterRequestScope(context);
  if (opts.onDecision) opts.onDecision(req, decision, descriptor.action);

  if (handleEnforcement(req, res, decision, descriptor, requestId, opts, next)) {
    return;
  }

  runWithRequest(context, () => next());
}

function attachAndProceed(
  req: Request,
  res: Response,
  next: NextFunction,
  requestId: string,
  descriptor: ActionDescriptor,
  context: IntentContext,
  startedAt: number,
  opts: IntentMiddlewareOptions,
): void {
  const decisionOrPromise = computeDecision(context, opts, req);
  if (decisionOrPromise instanceof Promise) {
    decisionOrPromise
      .then((decision) => {
        finalizeAttachAndProceed(
          req,
          res,
          next,
          requestId,
          descriptor,
          context,
          startedAt,
          decision,
          opts,
        );
      })
      .catch(next);
    return;
  }
  finalizeAttachAndProceed(
    req,
    res,
    next,
    requestId,
    descriptor,
    context,
    startedAt,
    decisionOrPromise,
    opts,
  );
}

export interface IntentMiddlewareCreator {
  <TAction extends string = string>(action: TAction): IntentMiddleware;
  <TAction extends string = string>(
    action: TAction,
    options: IntentMiddlewareOptions,
  ): IntentMiddleware;
  <TAction extends string = string>(
    intent: Intent<TAction>,
    options?: IntentMiddlewareOptions,
  ): IntentMiddleware;
  (options: IntentMiddlewareOptions): IntentMiddleware;
}

function createIntentMiddleware(
  actionOrIntentOrOptions: string | Intent | ActionDescriptor | IntentMiddlewareOptions,
  maybeOptions?: IntentMiddlewareOptions,
): IntentMiddleware {
  let descriptor: ActionDescriptor;
  let opts: IntentMiddlewareOptions;

  if (typeof actionOrIntentOrOptions === 'string') {
    const baseOpts = maybeOptions ?? {};
    descriptor = parseAction({
      ...baseOpts,
      action: actionOrIntentOrOptions,
    });
    opts = baseOpts;
  } else if (isIntent(actionOrIntentOrOptions)) {
    descriptor = {
      action: actionOrIntentOrOptions.key,
      intent: actionOrIntentOrOptions,
    };
    opts = maybeOptions ?? {};
  } else {
    opts = {
      ...(actionOrIntentOrOptions as IntentMiddlewareOptions),
      ...(maybeOptions ?? {}),
    };
    descriptor = parseAction(actionOrIntentOrOptions as unknown as ActionConfig);
  }

  const { actor: actorProvider, timeoutMs, source } = opts;

  return function intentMiddleware(req: Request, res: Response, next: NextFunction): void {
    const requestId = generateRequestId();
    const startedAt = Date.now();

    if (actorProvider === undefined) {
      const context = buildRequestContextSync(req, descriptor.intent, requestId);
      attachAndProceed(req, res, next, requestId, descriptor, context, startedAt, opts);
      return;
    }

    buildRequestContext(req, {
      intent: descriptor.intent,
      requestId,
      actorProvider,
      timeoutMs,
      source,
    })
      .then((context) => {
        attachAndProceed(req, res, next, requestId, descriptor, context, startedAt, opts);
      })
      .catch(next);
  };
}

export const intent: IntentMiddlewareCreator = function intent(
  actionOrIntentOrOptions: string | Intent | ActionDescriptor | IntentMiddlewareOptions,
  maybeOptions?: IntentMiddlewareOptions,
): IntentMiddleware {
  return createIntentMiddleware(actionOrIntentOrOptions, maybeOptions);
} as IntentMiddlewareCreator;

export { parseAction, defineAction };
export { getRequestSnapshot };
export { generateRequestId };
export type { ActorProvider, ResolveActorOptions };
