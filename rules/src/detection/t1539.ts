/**
 * T1539 — Steal Web Session Cookie. Pure detection: a **session/auth cookie set with weak security flags**
 * is exposed to theft (plaintext interception, JS/XSS read, cross-site send). Chrome-free + unit-testable.
 */
export interface CookieLike {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  /** chrome.cookies.Cookie['sameSite']: 'no_restriction' | 'lax' | 'strict' | 'unspecified'. */
  sameSite: string;
}

export interface CookieAssessment {
  theftRisk: boolean;
  isSession: boolean;
  reasons: string[];
}

export function assessCookie(cookie: CookieLike, sessionPatterns: string[]): CookieAssessment {
  const name = cookie.name.toLowerCase();
  const isSession = sessionPatterns.some((p) => name.includes(p));
  if (!isSession) return { theftRisk: false, isSession: false, reasons: [] };

  const reasons: string[] = [];
  if (!cookie.secure) reasons.push('session cookie is not Secure (can ride plaintext HTTP — interceptable)');
  if (!cookie.httpOnly) reasons.push('session cookie is not HttpOnly (readable by page JavaScript — XSS-exfiltratable)');
  if (cookie.sameSite === 'no_restriction') reasons.push('session cookie is SameSite=None (sent on cross-site requests)');

  return { theftRisk: reasons.length > 0, isSession: true, reasons };
}
