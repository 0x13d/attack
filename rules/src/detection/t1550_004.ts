/**
 * T1550.004 — Use Alternate Authentication Material: Web Session Cookie. Pure detection: a **session/auth cookie
 * made persistent** — a cookie whose name marks it as a session/auth token but which is set with an expiry
 * (`session === false`) instead of being a true (expire-on-close) session cookie. That's the shape of a stolen
 * session being **persisted for reuse/replay** (an attacker imports the cookie and pins it to survive).
 *
 * **Relationship / overlap (marked — owner 2026-06-17):** distinct from **T1539** (which flags a session cookie
 * **set with weak flags** = theft *exposure*). T1550.004 keys on the **persistence attribute** (reuse), not the
 * flags. A weak-flagged *and* persisted auth cookie fires both — two real findings on one cookie, by design.
 * Chrome-free + unit-testable.
 */
export interface SessionCookieLike {
  name: string;
  /** chrome.cookies.Cookie['session'] — true for a true session cookie (no expiry). */
  session: boolean;
  /** epoch seconds; present when the cookie is persistent. */
  expirationDate?: number;
  domain: string;
}

export interface SessionReuseAssessment {
  reuse: boolean;
  reasons: string[];
}

export function assessSessionReuse(cookie: SessionCookieLike, sessionPatterns: string[]): SessionReuseAssessment {
  const name = cookie.name.toLowerCase();
  const isSession = sessionPatterns.some((p) => name.includes(p));
  if (!isSession) return { reuse: false, reasons: [] };
  // A true session cookie (expire-on-close) is normal. The reuse signal is an auth token made *persistent*.
  if (cookie.session !== false) return { reuse: false, reasons: [] };

  const expiry = cookie.expirationDate ? new Date(cookie.expirationDate * 1000).toISOString().slice(0, 10) : 'a future date';
  return {
    reuse: true,
    reasons: [`session/auth cookie "${cookie.name}" made persistent (expires ${expiry}) on ${cookie.domain} — web-session-cookie reuse/persistence`],
  };
}
