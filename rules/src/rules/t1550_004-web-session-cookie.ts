import { Policy, DEFAULT_POLICY } from '../config';
import { assessSessionReuse } from '../detection/t1550_004';
import { makeAlertResponse } from '../responses/alert';
import { removeCookieResponse } from '../responses/removeCookie';
import { CookiePayload } from '../signals/cookie';
import { Response, Rule, Scope, Signal, Signature } from '../types';

/**
 * **T1550.004 — Use Alternate Authentication Material: Web Session Cookie.** Fires when a session/auth-named
 * cookie is set **persistent** (`session === false`) — the shape of a stolen session being pinned for reuse.
 * Alerts and **removes the cookie**. Like T1539 it reuses the `cookie` signal and is **dormant** until the
 * operator grants `cookies` + host access; no new permission.
 *
 * **Relationship:** distinct from T1539 (weak-flag *exposure*) — keyed on the persistence attribute (reuse).
 * Both can fire on one cookie (weak-flagged *and* persisted); two findings by design.
 */
export function makeT1550_004Rule(policy: Policy = DEFAULT_POLICY): Rule<CookiePayload> {
  const signature: Signature<CookiePayload> = {
    id: 'sig.t1550_004.persistent-session-cookie',
    name: 'Session/auth cookie made persistent (reuse/replay)',
    scope: Scope.COOKIE,
    process: (signal: Signal<CookiePayload>) => {
      const c = signal.payload.cookie;
      const assessment = assessSessionReuse(
        { name: c.name, session: c.session, expirationDate: c.expirationDate, domain: c.domain },
        policy.sessionCookiePatterns,
      );
      if (!assessment.reuse) return false;
      signal.meta = {
        technique: 'T1550.004',
        cookieName: c.name,
        domain: c.domain,
        reasons: assessment.reasons,
        relationship: 'distinct from T1539 (weak-flag exposure) — keyed on the persistence attribute (session-token reuse)',
      };
      return true;
    },
  };

  return {
    id: 'rule.t1550_004.web-session-cookie',
    name: 'Use of Web Session Cookie (persisted auth token)',
    technique: 'T1550.004',
    scope: [Scope.COOKIE],
    signatures: [signature],
    responses: [makeAlertResponse<CookiePayload>(), removeCookieResponse as unknown as Response<CookiePayload>],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}
