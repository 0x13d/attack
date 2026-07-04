import { Rule, Signal, Signature } from '0x13d-attack-rules-community';

/**
 * The event trace — the replay foundation (ADR-001). The engine records the ordered `Signal`s it processed
 * and the `Hit`s they produced into a bounded, append-only ring buffer, and exports a serializable, versioned
 * `TraceDocument`. This is **data, not code**: the brochure's Gantt/timeline (ATK-203/204/205) and the admin
 * dashboard replay it; the extension carries no visualization. Zero dependencies.
 *
 * Determinism: every event carries a monotonic `seq` (replay orders by it) and a wall-clock `t`. The clock is
 * injectable so the trace is unit-testable without timing flake.
 */
export const TRACE_SCHEMA_VERSION = 1;

export interface SignalTraceEvent {
  seq: number;
  t: number;
  kind: 'signal';
  signalId: string;
  name: string;
  scope: string;
  tabId: number;
}

export interface HitTraceEvent {
  seq: number;
  t: number;
  kind: 'hit';
  signalId: string;
  ruleId: string;
  ruleName: string;
  signatureId: string;
  technique: string;
  reasons?: string[];
}

export type TraceEvent = SignalTraceEvent | HitTraceEvent;

export interface TraceDocument {
  version: number;
  generatedAt: number;
  events: TraceEvent[];
}

export class Tracer {
  private buf: TraceEvent[] = [];
  private seq = 0;

  constructor(
    private readonly max = 500,
    private readonly now: () => number = Date.now,
  ) {}

  recordSignal(signal: Signal<unknown>): void {
    this.push({
      seq: this.seq++,
      t: this.now(),
      kind: 'signal',
      signalId: signal.id,
      name: signal.name,
      scope: signal.scope,
      tabId: signal.tabId,
    });
  }

  recordHit(signal: Signal<unknown>, rule: Rule<unknown>, signature: Signature<unknown>): void {
    const reasons = signal.meta?.reasons as string[] | undefined;
    // Omit `reasons` when absent so the trace JSON round-trips cleanly (no `undefined` keys).
    this.push({
      seq: this.seq++,
      t: this.now(),
      kind: 'hit',
      signalId: signal.id,
      ruleId: rule.id,
      ruleName: rule.name,
      signatureId: signature.id,
      technique: rule.technique,
      ...(reasons ? { reasons } : {}),
    });
  }

  /** A serializable snapshot — what a consumer replays. Defensive copy; safe to JSON.stringify. */
  snapshot(): TraceDocument {
    return { version: TRACE_SCHEMA_VERSION, generatedAt: this.now(), events: [...this.buf] };
  }

  clear(): void {
    this.buf = [];
  }

  private push(event: TraceEvent): void {
    this.buf.push(event);
    if (this.buf.length > this.max) this.buf.shift();
  }
}
