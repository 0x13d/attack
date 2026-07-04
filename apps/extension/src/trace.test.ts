import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Engine } from './engine';
import { Tracer, TRACE_SCHEMA_VERSION, HitTraceEvent } from './trace';
import { Rule, Scope, Signal } from '0x13d-attack-rules-community';

// A synthetic, chrome-free rule: matches when payload.n > 0; no-op response.
const rule: Rule<{ n: number }> = {
  id: 'rule.test',
  name: 'Test rule',
  technique: 'T9999',
  scope: [Scope.MANAGEMENT],
  signatures: [
    {
      id: 'sig.test',
      name: 'positive n',
      scope: Scope.MANAGEMENT,
      process: (s: Signal<{ n: number }>) => s.payload.n > 0,
    },
  ],
  responses: [{ id: 'resp.noop', name: 'noop', action: () => {} }],
  timeToLive: 1000,
  cascade: { enabled: false, ruleIds: [] },
};

function signal(id: string, n: number): Signal<{ n: number }> {
  return { id, name: 'management.installed', tabId: -1, windowId: -1, payload: { n }, scope: Scope.MANAGEMENT, timestamp: 0, hits: [] };
}

function fixedClockEngine() {
  let tick = 0;
  const tracer = new Tracer(500, () => ++tick); // deterministic monotonic clock
  const engine = new Engine(tracer);
  engine.registerRules([rule as unknown as Rule<unknown>]);
  return engine;
}

test('records a signal event for every processed signal', () => {
  const engine = fixedClockEngine();
  engine.processSignal(signal('a', 0) as unknown as Signal<unknown>); // no match
  const doc = engine.getTrace();
  assert.equal(doc.version, TRACE_SCHEMA_VERSION);
  assert.equal(doc.events.length, 1);
  assert.equal(doc.events[0].kind, 'signal');
  assert.equal(doc.events[0].signalId, 'a');
});

test('records a hit event after the signal that produced it', () => {
  const engine = fixedClockEngine();
  engine.processSignal(signal('hit-1', 5) as unknown as Signal<unknown>); // matches
  const doc = engine.getTrace();
  assert.deepEqual(doc.events.map((e) => e.kind), ['signal', 'hit']);
  const hit = doc.events[1] as HitTraceEvent;
  assert.equal(hit.signalId, 'hit-1');
  assert.equal(hit.technique, 'T9999');
  assert.equal(hit.ruleId, 'rule.test');
});

test('replay order is deterministic by monotonic seq', () => {
  const engine = fixedClockEngine();
  engine.processSignal(signal('s1', 1) as unknown as Signal<unknown>); // signal + hit
  engine.processSignal(signal('s2', 0) as unknown as Signal<unknown>); // signal only
  const doc = engine.getTrace();
  const seqs = doc.events.map((e) => e.seq);
  assert.deepEqual(seqs, [...seqs].sort((a, b) => a - b)); // strictly ordered
  assert.deepEqual(
    doc.events.map((e) => `${e.kind}:${e.signalId}`),
    ['signal:s1', 'hit:s1', 'signal:s2'],
  );
});

test('export is JSON-serializable and stable', () => {
  const engine = fixedClockEngine();
  engine.processSignal(signal('x', 1) as unknown as Signal<unknown>);
  const doc = engine.getTrace();
  const round = JSON.parse(JSON.stringify(doc));
  assert.deepEqual(round.events, doc.events);
});

test('ring buffer is bounded (oldest dropped)', () => {
  let tick = 0;
  const engine = new Engine(new Tracer(3, () => ++tick));
  engine.registerRules([rule as unknown as Rule<unknown>]);
  for (let i = 0; i < 10; i++) engine.processSignal(signal(`n${i}`, 0) as unknown as Signal<unknown>);
  const doc = engine.getTrace();
  assert.equal(doc.events.length, 3);
  assert.equal(doc.events[0].signalId, 'n7'); // oldest kept
  assert.equal(doc.events[2].signalId, 'n9');
});
