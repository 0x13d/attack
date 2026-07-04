/**
 * The detection contracts. A browser event becomes a `Signal`; a `Rule` (a scope + `Signature[]` +
 * `Response[]`) is evaluated by the `Engine`; a matched `Signature` records a `Hit` and fires the `Response`s.
 *
 * Zero runtime deps — the engine is hand-rolled; nothing here to audit but our own code (the trust
 * signature). See ADR-001.
 */

/** The browser event source a signal/rule is scoped to. Add a member when a new signal source is wired. */
export enum Scope {
  MANAGEMENT = 'management',
  WEB_NAVIGATION = 'webNavigation',
  COOKIE = 'cookie',
  DOWNLOAD = 'download',
  TAB = 'tab',
  WINDOW = 'window',
  /** Reserved: network-request observations. No signal source feeds this scope in the community build. */
  WEB_REQUEST = 'webRequest',
  /** Reserved: page/DOM observations. No signal source feeds this scope in the community build. */
  CONTENT = 'content',
}

/** A recorded match — which signature of which rule fired on which signal. */
export interface Hit {
  ruleId: string;
  signatureId: string;
  signalId: string;
}

/**
 * A normalized browser event handed to the engine.
 * @typeParam T - the shape of the source event payload (e.g. `chrome.management.ExtensionInfo`).
 */
export interface Signal<T> {
  id: string;
  /** Event name, e.g. `management.installed`. */
  name: string;
  scope: Scope;
  payload: T;
  /** -1 when the event is not associated with a specific tab/window. */
  tabId: number;
  windowId: number;
  timestamp: number;
  hits: Hit[];
  /**
   * Detection context a matching signature attaches for the responses (and the ATK-206 event trace) to read
   * — e.g. the rogue-extension assessment + reasons. Kept serializable; no functions.
   */
  meta?: Record<string, unknown>;
}

/** A predicate over a signal — the unit of detection. Returns true on a match. */
export interface Signature<T> {
  id: string;
  name: string;
  scope: Scope;
  process: (signal: Signal<T>) => boolean;
}

/** What to do on a hit — alert (SIEM/LME) or active prevention (setEnabled/cancel/remove/block). */
export interface Response<T> {
  id: string;
  name: string;
  action: (rule: Rule<T>, signal: Signal<T>) => void;
}

/**
 * A rule: match a group of signals in `scope` against `signatures`; on a hit, run `responses`.
 * `cascade` lets a rule fire only once every correlated rule has been hit within `timeToLive` (ms).
 */
export interface Rule<T> {
  id: string;
  name: string;
  /** ATT&CK technique id this rule maps to, e.g. `T1176.001`. */
  technique: string;
  scope: Scope[];
  signatures: Signature<T>[];
  responses: Response<T>[];
  timeToLive: number;
  cascade: {
    enabled: boolean;
    ruleIds: string[];
  };
}
