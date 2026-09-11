import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { AuditEvent, AuditEventType, AuditSeverity, AuditSink } from './audit-defs.js';
import { NullAuditSink } from './audit-defs.js';
import { RedactionEngine, type RedactionConfig } from './redaction.js';

export interface AttachAuditOptions {
  readonly sink?: AuditSink;
  readonly redaction?: RedactionConfig;
  readonly includeBody?: boolean;
  readonly decisionResolver?: (
    req: Request,
    res: Response,
  ) => {
    readonly kind: 'allow' | 'monitor' | 'challenge' | 'rate_limit' | 'deny' | 'error';
    readonly severity?: AuditSeverity;
    readonly type?: AuditEventType;
    readonly risk?: { readonly score: number | null; readonly severity: string | null };
    readonly matchedPolicies?: ReadonlyArray<string>;
    readonly evaluatedPolicies?: ReadonlyArray<string>;
    readonly missingSignals?: ReadonlyArray<string>;
    readonly signalsPresent?: ReadonlyArray<string>;
    readonly anomalies?: ReadonlyArray<{
      readonly type: string;
      readonly confidence: number;
      readonly reasons: ReadonlyArray<string>;
    }>;
    readonly tags?: Record<string, string>;
  };
}

function truncatedUserAgent(v: unknown): string | null {
  if (v === undefined || v === null) return null;
  if (Array.isArray(v)) {
    if (v.length === 0) return null;
    const first = v[0];
    if (typeof first !== 'string' || first.length === 0) return null;
    return first.length > 256 ? first.slice(0, 256) : first;
  }
  if (typeof v !== 'string') return null;
  if (v.length === 0) return null;
  return v.length > 256 ? v.slice(0, 256) : v;
}

function extractHeaders(req: Request): Record<string, string | string[] | undefined> {
  return req.headers as Record<string, string | string[] | undefined>;
}

function extractQuery(req: Request): Record<string, unknown> {
  return (req.query ?? {}) as Record<string, unknown>;
}

function extractBodyKeys(req: Request): string[] {
  const b = req.body as unknown;
  if (b === null || b === undefined) return [];
  if (typeof b !== 'object') return [];
  if (Array.isArray(b))
    return b.length <= 100 ? b.map((_v, i) => `[${i}]`) : [`[0..${b.length - 1}]`];
  return Object.keys(b as Record<string, unknown>).sort();
}

function getRequestIp(req: Request): string | null {
  const v = (req as unknown as { ip?: string }).ip;
  if (typeof v === 'string' && v.length > 0 && v.length <= 64) return v;
  const sock = (req as unknown as { socket?: { remoteAddress?: string } }).socket;
  const remote = sock?.remoteAddress;
  if (typeof remote === 'string' && remote.length > 0) return remote;
  return null;
}

export function attachAudit(options: AttachAuditOptions = {}): RequestHandler {
  const sink: AuditSink = options.sink ?? new NullAuditSink();
  const redactor = new RedactionEngine({
    ...(options.redaction ?? {}),
    includeBody: options.includeBody ?? options.redaction?.includeBody ?? false,
  });

  return function auditMiddleware(req: Request, res: Response, next: NextFunction): void {
    const startedAt = Date.now();
    const url = req.originalUrl ?? req.url ?? '';
    const qIdx = url.indexOf('?');
    const path = qIdx >= 0 ? url.slice(0, qIdx) : url;

    let finalized = false;
    const finalize = (): void => {
      if (finalized) return;
      finalized = true;
      try {
        const duration = Date.now() - startedAt;
        const decision = options.decisionResolver?.(req, res) ?? { kind: 'allow' as const };
        const kind = decision.kind;
        const severity: AuditSeverity = decision.severity ?? severityFromKind(kind);
        const type: AuditEventType = decision.type ?? typeFromKind(kind);

        const redactedHeaders = redactor.redactHeaders(extractHeaders(req));
        const redactedQuery = redactor.redactQuery(extractQuery(req));
        const bodyKeys = extractBodyKeys(req);
        const { body } = redactor.redactBody(req.body, bodyKeys);

        const intentContext = (req.intent?.context ?? null) as null | {
          actor?: {
            subject?: string | null;
            roles?: ReadonlyArray<string>;
            authenticated?: boolean;
          };
        };
        const actorSubject = intentContext?.actor?.subject ?? null;
        const actorRoles = intentContext?.actor?.roles ?? [];
        const actorAuth = intentContext?.actor?.authenticated ?? false;

        const event: AuditEvent = {
          type,
          severity,
          requestId: req.intent?.requestId ?? '',
          action: req.intent?.action ?? '',
          intentKey: req.intent?.action ?? '',
          outcome: kind,
          decisionKind: kind,
          actor: { subject: actorSubject, authenticated: actorAuth, roles: actorRoles },
          request: {
            method: req.method,
            path,
            ip: getRequestIp(req),
            userAgent: truncatedUserAgent(req.headers['user-agent']),
            headers: redactedHeaders,
            query: redactedQuery,
            bodyKeys,
            body,
          },
          response: { status: res.statusCode, durationMs: duration },
          risk: decision.risk ?? { score: null, severity: null },
          signals: {
            present: decision.signalsPresent ?? [],
            missing: decision.missingSignals ?? [],
          },
          anomalies: decision.anomalies ?? [],
          policy: {
            evaluated: decision.evaluatedPolicies ?? [],
            matched: decision.matchedPolicies ?? [],
          },
          tags: decision.tags ?? {},
          emittedAt: Date.now(),
        };
        const frozen = Object.freeze(event) as AuditEvent;
        void sink.emit(frozen);
      } catch {
        /* never let audit failure propagate */
      }
    };

    res.on('finish', finalize);
    res.on('close', finalize);
    next();
  };
}

function severityFromKind(k: AuditEvent['decisionKind']): AuditSeverity {
  switch (k) {
    case 'deny':
    case 'error':
      return 'error';
    case 'challenge':
    case 'rate_limit':
      return 'warn';
    case 'monitor':
      return 'info';
    case 'allow':
    default:
      return 'debug';
  }
}

function typeFromKind(k: AuditEvent['decisionKind']): AuditEventType {
  switch (k) {
    case 'deny':
      return 'security.denied';
    case 'challenge':
      return 'security.challenged';
    case 'rate_limit':
      return 'security.rate_limited';
    case 'error':
      return 'security.error';
    case 'allow':
    case 'monitor':
    default:
      return 'intent.evaluated';
  }
}

export const audit = attachAudit;
