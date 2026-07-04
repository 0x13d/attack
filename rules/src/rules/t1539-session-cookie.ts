import { Policy, DEFAULT_POLICY } from '../config';
import { assessCookie } from '../detection/t1539';
import { makeAlertResponse } from '../responses/alert';
import { removeCookieResponse } from '../responses/removeCookie';
import { CookiePayload } from '../signals/cookie';
import { Response, Rule, Scope, Signal, Signature } from '../types';

/**
 * **T1539 — Steal Web Session Cookie.** Fires when a session/auth cookie is set with weak security flags
 * (not Secure / not HttpOnly / SameSite=None) — exposed to theft. Alerts and removes the cookie.
 * Permission-gated: dormant until the operator grants `cookies` + host access.
 */
export function makeT1539Rule(policy: Policy = DEFAULT_POLICY): Rule<CookiePayload> {
  const signature: Signature<CookiePayload> = {
    id: 'sig.t1539.weak-session-cookie',
    name: 'Session cookie exposed to theft',
    scope: Scope.COOKIE,
    process: (signal: Signal<CookiePayload>) => {
      const c = signal.payload.cookie;
      const assessment = assessCookie(
        { name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite },
        policy.sessionCookiePatterns,
      );
      if (!assessment.theftRisk) return false;
      signal.meta = {
        technique: 'T1539',
        cookieName: c.name,
        domain: c.domain,
        reasons: assessment.reasons,
      };
      return true;
    },
  };

  return {
    id: 'rule.t1539.session-cookie',
    name: 'Steal Web Session Cookie (weak flags)',
    technique: 'T1539',
    scope: [Scope.COOKIE],
    signatures: [signature],
    responses: [makeAlertResponse<CookiePayload>(), removeCookieResponse as unknown as Response<CookiePayload>],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}
