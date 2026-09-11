import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { createHash } from 'node:crypto';
import {
  DEFAULT_IDEMPOTENCY_TTL_MS,
  DEFAULT_WAIT_DEADLINE_MS,
  IDEMPOTENCY_KEY_PATTERN,
  isValidIdempotencyKey,
  type IdempotencyProvider,
  type StoredResponse,
} from './idempotency-defs.js';
import { InMemoryIdempotencyProvider } from './idempotency-memory.js';
import { safeOwnKeys } from './safe-object.js';

export interface IdempotencyMiddlewareOptions {
  readonly provider?: IdempotencyProvider;
  readonly headerName?: string;
  readonly ttlMs?: number;
  readonly waitDeadlineMs?: number;
  readonly replayHeaderName?: string;
  readonly includeBodyInFingerprint?: boolean;
  readonly maxReplayBodyBytes?: number;
}

export interface IdempotencyContext {
  readonly key: string;
  readonly replayed: boolean;
}

declare module 'express-serve-static-core' {
  interface Request {
    idempotency?: IdempotencyContext;
  }
}

const REPLAYED_HEADER = 'Idempotency-Replayed';
const STATUS_REPLAYED = 'true';
const DEFAULT_HEADER = 'idempotency-key';
const MAX_REPLAY_BODY_BYTES = 64 * 1024;
const MAX_BODY_HASH_INPUT = 64 * 1024;
const MAX_BODY_HASH_NODES = 256;
const SAFE_HEADER_NAME = /^[A-Za-z0-9-]{1,256}$/;
const SAFE_REPLAY_HEADERS = new Set([
  'content-type',
  'cache-control',
  'etag',
  'vary',
  'x-request-id',
]);

function safeBodyShapeHash(req: Request): string {
  const b = req.body as unknown;
  if (b === undefined || b === null) return 'empty';
  const state = { n: 0, bytes: 0, truncated: false };
  const shape = shapeOfBounded(b, 0, state);
  const payload = `n=${state.n};b=${state.bytes};t=${state.truncated ? 'truncated' : 'ok'};s=${stableStringifyBounded(shape, state)}`;
  return createHash('sha256').update(payload).digest('hex').slice(0, 16);
}

function shapeOfBounded(
  value: unknown,
  depth: number,
  state: { n: number; bytes: number; truncated: boolean },
): unknown {
  if (state.bytes > MAX_BODY_HASH_INPUT) {
    state.truncated = true;
    return '…';
  }
  if (state.n > MAX_BODY_HASH_NODES) {
    state.truncated = true;
    return '…';
  }
  state.n++;
  if (depth > 6) return '…';
  if (value === null) return null;
  if (typeof value === 'string') {
    state.bytes += value.length;
    return `s${value.length}`;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    state.bytes += 24;
    return `n${value}`;
  }
  if (typeof value === 'boolean') return `b${value}`;
  if (typeof value === 'bigint') return `bi${value.toString(16)}`;
  if (typeof value === 'undefined') return 'u';
  if (typeof value !== 'object') return 't';
  if (Array.isArray(value)) {
    return value.length === 0 ? '[]' : value.map((v) => shapeOfBounded(v, depth + 1, state));
  }
  const out: Record<string, unknown> = {};
  const keys = safeOwnKeys(value as object).sort();
  for (const k of keys) {
    if (Object.keys(out).length >= 128) {
      state.truncated = true;
      break;
    }
    const v = (value as Record<string, unknown>)[k];
    out[k] = shapeOfBounded(v, depth + 1, state);
  }
  return out;
}

function stableStringifyBounded(
  value: unknown,
  state: { bytes: number; truncated: boolean },
): string {
  if (state.bytes > MAX_BODY_HASH_INPUT * 2) return '"…"';
  if (value === null) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value))
    return `[${value.map((v) => stableStringifyBounded(v, state)).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort();
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringifyBounded(v, state)}`).join(',')}}`;
}

function computeFingerprint(req: Request, includeBody: boolean): string {
  const parts = [req.method.toUpperCase(), req.path];
  if (includeBody) parts.push(safeBodyShapeHash(req));
  return createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 32);
}

function serializeBody(res: Response, maxBytes: number): string {
  const buf = (res as unknown as { body?: unknown }).body;
  if (typeof buf === 'string') return buf.length > maxBytes ? buf.slice(0, maxBytes) : buf;
  if (Buffer.isBuffer(buf))
    return buf.length > maxBytes
      ? buf.subarray(0, maxBytes).toString('utf8')
      : buf.toString('utf8');
  const captured = (res as unknown as { __idempCaptured?: Buffer[] }).__idempCaptured;
  if (Array.isArray(captured) && captured.length > 0) {
    const total = captured.reduce((s, c) => s + c.length, 0);
    if (total <= maxBytes) return Buffer.concat(captured).toString('utf8');
    let remaining = maxBytes;
    const parts: Buffer[] = [];
    for (const c of captured) {
      if (remaining <= 0) break;
      parts.push(c.length <= remaining ? c : c.subarray(0, remaining));
      remaining -= Math.min(c.length, remaining);
    }
    return Buffer.concat(parts).toString('utf8');
  }
  if (buf === undefined || buf === null) {
    const chunks: Buffer[] = [];
    const writable = res as unknown as {
      writableBuffer?: Buffer[];
      outputData?: { data: Buffer }[];
    };
    if (Array.isArray(writable.outputData)) {
      for (const d of writable.outputData) {
        if (Buffer.isBuffer(d.data)) chunks.push(d.data);
      }
    }
    if (chunks.length === 0 && Array.isArray(writable.writableBuffer)) {
      for (const d of writable.writableBuffer) {
        if (Buffer.isBuffer(d)) chunks.push(d);
      }
    }
    const total = chunks.reduce((s, c) => s + c.length, 0);
    if (total <= maxBytes) return Buffer.concat(chunks).toString('utf8');
    let remaining = maxBytes;
    const parts: Buffer[] = [];
    for (const c of chunks) {
      if (remaining <= 0) break;
      parts.push(c.length <= remaining ? c : c.subarray(0, remaining));
      remaining -= Math.min(c.length, remaining);
    }
    return Buffer.concat(parts).toString('utf8');
  }
  try {
    const s = JSON.stringify(buf);
    if (typeof s === 'string') return s.length > maxBytes ? s.slice(0, maxBytes) : s;
    return '';
  } catch {
    return '';
  }
}

function isWritableEnded(res: Response): boolean {
  return (res as unknown as { writableEnded?: boolean }).writableEnded === true;
}

function sendStoredResponse(res: Response, stored: StoredResponse, replayHeader: string): void {
  for (const [name, value] of Object.entries(stored.headers)) {
    const lower = name.toLowerCase();
    if (lower === 'content-length') continue;
    if (lower === 'transfer-encoding') continue;
    if (lower === 'set-cookie') continue;
    if (lower === 'authorization') continue;
    if (lower === 'cookie') continue;
    if (lower === replayHeader.toLowerCase()) continue;
    if (!SAFE_HEADER_NAME.test(name)) continue;
    if (!SAFE_REPLAY_HEADERS.has(lower)) continue;
    if (typeof value !== 'string') continue;
    res.setHeader(name, value);
  }
  res.setHeader(replayHeader, STATUS_REPLAYED);
  res.status(stored.status);
  res.send(stored.body);
}

export function createIdempotencyMiddleware(
  options: IdempotencyMiddlewareOptions = {},
): RequestHandler {
  const provider = options.provider ?? new InMemoryIdempotencyProvider();
  const headerName = options.headerName ?? DEFAULT_HEADER;
  const ttlMs = options.ttlMs ?? DEFAULT_IDEMPOTENCY_TTL_MS;
  const waitDeadlineMs = options.waitDeadlineMs ?? DEFAULT_WAIT_DEADLINE_MS;
  const replayHeader = options.replayHeaderName ?? REPLAYED_HEADER;
  const includeBody = options.includeBodyInFingerprint ?? true;
  const maxReplayBytes = options.maxReplayBodyBytes ?? MAX_REPLAY_BODY_BYTES;

  return async function idempotencyMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> {
    try {
      const raw = req.headers[headerName.toLowerCase()];
      const key = Array.isArray(raw) ? raw[0] : raw;
      if (key === undefined || key === '') return next();
      if (typeof key !== 'string' || !isValidIdempotencyKey(key)) {
        res.status(400);
        res.setHeader('content-type', 'application/json');
        res.send(JSON.stringify({ error: 'invalid_idempotency_key' }));
        return;
      }

      const fingerprint = computeFingerprint(req, includeBody);
      const lookup = await provider.lookup(key);
      if (lookup !== null) {
        if (lookup.fingerprint !== fingerprint) {
          res.status(422);
          res.setHeader('content-type', 'application/json');
          res.send(JSON.stringify({ error: 'idempotency_key_mismatch' }));
          return;
        }
        if (lookup.state === 'done' && lookup.response !== null) {
          req.idempotency = { key, replayed: true };
          sendStoredResponse(res, lookup.response, replayHeader);
          return;
        }
        if (lookup.state === 'in-flight') {
          try {
            const completed = await provider.waitForCompletion(key, waitDeadlineMs);
            if (completed !== null && completed.state === 'done' && completed.response !== null) {
              req.idempotency = { key, replayed: true };
              sendStoredResponse(res, completed.response, replayHeader);
              return;
            }
            res.status(409);
            res.setHeader('content-type', 'application/json');
            res.send(JSON.stringify({ error: 'idempotency_request_in_flight' }));
            return;
          } catch {
            res.status(504);
            res.setHeader('content-type', 'application/json');
            res.send(JSON.stringify({ error: 'idempotency_wait_timeout' }));
            return;
          }
        }
      }

      const acquire = await provider.acquire(key, fingerprint, ttlMs);
      if (!acquire.acquired) {
        const current = acquire.current;
        if (current !== null && current.state === 'done' && current.response !== null) {
          req.idempotency = { key, replayed: true };
          sendStoredResponse(res, current.response, replayHeader);
          return;
        }
        if (current !== null && current.state === 'in-flight') {
          try {
            const completed = await provider.waitForCompletion(key, waitDeadlineMs);
            if (completed !== null && completed.state === 'done' && completed.response !== null) {
              req.idempotency = { key, replayed: true };
              sendStoredResponse(res, completed.response, replayHeader);
              return;
            }
            res.status(409);
            res.setHeader('content-type', 'application/json');
            res.send(JSON.stringify({ error: 'idempotency_request_in_flight' }));
            return;
          } catch {
            res.status(504);
            res.setHeader('content-type', 'application/json');
            res.send(JSON.stringify({ error: 'idempotency_wait_timeout' }));
            return;
          }
        }
      }

      req.idempotency = { key, replayed: false };

      let capturedBytes = 0;
      let captureTruncated = false;
      const capturedChunks: Buffer[] = [];
      (res as unknown as { __idempCaptured?: Buffer[] }).__idempCaptured = capturedChunks;
      const origWrite = res.write.bind(res);
      const origEnd = res.end.bind(res);
      (res as unknown as { write: typeof res.write }).write = function patchedWrite(
        chunk: unknown,
        ...rest: unknown[]
      ): boolean {
        if (!captureTruncated && chunk !== undefined && chunk !== null) {
          let buf: Buffer;
          if (Buffer.isBuffer(chunk)) buf = chunk;
          else if (typeof chunk === 'string') buf = Buffer.from(chunk, 'utf8');
          else buf = Buffer.from(String(chunk), 'utf8');
          if (capturedBytes + buf.length <= maxReplayBytes) {
            capturedChunks.push(buf);
            capturedBytes += buf.length;
          } else {
            const remaining = maxReplayBytes - capturedBytes;
            if (remaining > 0) {
              capturedChunks.push(buf.subarray(0, remaining));
              capturedBytes = maxReplayBytes;
            }
            captureTruncated = true;
          }
        }
        return (origWrite as (...a: unknown[]) => boolean)(chunk, ...rest);
      } as typeof res.write;
      (res as unknown as { end: typeof res.end }).end = function patchedEnd(
        chunk: unknown,
        ...rest: unknown[]
      ): Response {
        if (!captureTruncated && chunk !== undefined && chunk !== null) {
          let buf: Buffer;
          if (Buffer.isBuffer(chunk)) buf = chunk;
          else if (typeof chunk === 'string') buf = Buffer.from(chunk, 'utf8');
          else buf = Buffer.from(String(chunk), 'utf8');
          if (capturedBytes + buf.length <= maxReplayBytes) {
            capturedChunks.push(buf);
            capturedBytes += buf.length;
          } else {
            const remaining = maxReplayBytes - capturedBytes;
            if (remaining > 0) {
              capturedChunks.push(buf.subarray(0, remaining));
              capturedBytes = maxReplayBytes;
            }
            captureTruncated = true;
          }
        }
        return (origEnd as (...a: unknown[]) => Response)(chunk, ...rest);
      } as typeof res.end;

      let captured = false;
      const capture = async (): Promise<void> => {
        if (captured) return;
        captured = true;
        if (!isWritableEnded(res)) {
          await provider.release(key);
          return;
        }
        const headers: Record<string, string> = {};
        for (const [name, value] of Object.entries(res.getHeaders())) {
          if (Array.isArray(value)) headers[name] = value.join(', ');
          else if (typeof value === 'string') headers[name] = value;
          else if (typeof value === 'number') headers[name] = String(value);
        }
        const body = serializeBody(res, maxReplayBytes);
        await provider.complete(key, { status: res.statusCode, headers, body }, ttlMs);
      };

      res.on('close', () => {
        void capture();
      });
      res.on('finish', () => {
        void capture();
      });

      next();
    } catch (err) {
      next(err);
    }
  };
}

export function getIdempotency(req: Request): IdempotencyContext | undefined {
  return (req as { idempotency?: IdempotencyContext }).idempotency;
}

export { IDEMPOTENCY_KEY_PATTERN };
export const idempotency = createIdempotencyMiddleware;
