import type { AuditEvent, AuditSink, AuditSeverity } from './audit-defs.js';

export class InMemoryAuditSink implements AuditSink {
  readonly name = 'in-memory';
  private readonly events: AuditEvent[] = [];
  private readonly maxEvents: number;

  constructor(options: { maxEvents?: number } = {}) {
    this.maxEvents = options.maxEvents ?? 1000;
  }

  emit(event: AuditEvent): void {
    this.events.push(event);
    if (this.events.length > this.maxEvents) this.events.shift();
  }

  all(): ReadonlyArray<AuditEvent> {
    return this.events.slice();
  }

  clear(): void {
    this.events.length = 0;
  }

  size(): number {
    return this.events.length;
  }

  byType(type: AuditEvent['type']): ReadonlyArray<AuditEvent> {
    return this.events.filter((e) => e.type === type);
  }

  bySeverity(severity: AuditSeverity): ReadonlyArray<AuditEvent> {
    return this.events.filter((e) => e.severity === severity);
  }
}

export interface ConsoleAuditSinkOptions {
  readonly stream?: { log(line: string): void };
  readonly json?: boolean;
}

export class ConsoleAuditSink implements AuditSink {
  readonly name = 'console';
  private readonly stream: { log(line: string): void };
  private readonly json: boolean;

  constructor(options: ConsoleAuditSinkOptions = {}) {
    this.stream = options.stream ?? { log: (l) => process.stdout.write(l + '\n') };
    this.json = options.json ?? true;
  }

  emit(event: AuditEvent): void {
    if (this.json) this.stream.log(JSON.stringify(event));
    else
      this.stream.log(
        `[audit] ${event.type} ${event.outcome} ${event.action} actor=${event.actor.subject} req=${event.requestId}`,
      );
  }
}
