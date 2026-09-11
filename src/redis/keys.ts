import { createHash } from 'node:crypto';

export type RedisNamespace = 'rl' | 'sig' | 'obs' | 'idem' | 'notify';

const ROOT = 'ei:v1';
const MAX_RAW_LEN = 128;

function hashSegment(input: string): string {
  return createHash('sha256').update(input).digest('hex').slice(0, 32);
}

function sanitizeRaw(input: string): string {
  if (input.length > MAX_RAW_LEN) {
    return input.slice(0, MAX_RAW_LEN) + '~' + hashSegment(input);
  }
  if (/^[A-Za-z0-9_\-:.]+$/.test(input)) return input;
  return hashSegment(input);
}

export function buildRedisKey(
  namespace: RedisNamespace,
  parts: ReadonlyArray<string>,
  suffix?: string,
): string {
  if (!['rl', 'sig', 'obs', 'idem', 'notify'].includes(namespace)) {
    throw new Error(`Invalid Redis namespace: ${namespace}`);
  }
  const safe = parts.map((p) => sanitizeRaw(p));
  const tail = suffix === undefined ? '' : ':' + sanitizeRaw(suffix);
  return `${ROOT}:${namespace}:${safe.join(':')}${tail}`;
}

export function buildRedisChannel(namespace: RedisNamespace, parts: ReadonlyArray<string>): string {
  if (namespace !== 'notify') {
    throw new Error('Channels must use the notify namespace');
  }
  return buildRedisKey(namespace, parts);
}

export function hashActor(actorSubject: string | null | undefined): string {
  if (actorSubject === null || actorSubject === undefined) return 'anon';
  return hashSegment(actorSubject.toLowerCase());
}

export function hashIp(ip: string | null | undefined): string {
  if (ip === null || ip === undefined) return 'noip';
  return hashSegment(ip);
}

export function hashString(input: string): string {
  return hashSegment(input);
}
