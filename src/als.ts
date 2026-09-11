import { AsyncLocalStorage } from 'node:async_hooks';

import type { IntentContext, RequestSnapshot } from './domain/index.js';

const storage = new AsyncLocalStorage<IntentContext>();

export function runWithRequest<T>(context: IntentContext, fn: () => T): T {
  return storage.run(context, fn);
}

export function getRequestSnapshot(): RequestSnapshot | undefined {
  const ctx = storage.getStore();
  if (!ctx) return undefined;
  return Object.freeze({
    requestId: ctx.requestId,
    action: ctx.intent.key,
    actorSubject: ctx.actor.subject,
    startedAt: ctx.receivedAt,
  });
}

export function getIntentContext(): IntentContext | undefined {
  return storage.getStore();
}

export function enterRequestScope(context: IntentContext): void {
  storage.enterWith(context);
}
