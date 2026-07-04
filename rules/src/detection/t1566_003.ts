import { hostnameOf } from './t1566';

/**
 * T1566.003 — Spearphishing via Service. Pure detection: a navigation **laundered through a trusted service's
 * open-redirect** — a URL on one domain carrying a redirect parameter (`?url=`, `?next=`, `?redirect_uri=`, …)
 * whose value points to an **off-domain** destination. Attackers abuse a reputable service's redirect to deliver
 * a phishing link that survives URL-reputation checks (the "via service" delivery vector).
 *
 * **Relationship / overlap (marked deliberately — overlap is a product feature, owner 2026-06-17):**
 *  - vs **T1566.002** (lookalike login): .002 = the *destination domain mimics a brand*; .003 = a *legitimate
 *    service is abused* to redirect off-domain — no lookalike required.
 *  - vs **T1204.001** (malicious link / blocklist): T1204.001 = *destination is known-bad*; .003 = the *delivery
 *    mechanism* (off-domain open-redirect) is the signal, destination may be unknown.
 *  A single URL could trip more than one (e.g. an open-redirect *to* a lookalike) — that's two real findings, by
 *  design; a client mixes/tunes which to enable. Chrome-free + unit-testable.
 */
export interface ViaServiceAssessment {
  viaService: boolean;
  reasons: string[];
  /** The off-domain destination host the redirect points to; null when no match. */
  redirectTo: string | null;
}

export function assessViaService(url: string, redirectParams: string[]): ViaServiceAssessment {
  const host = hostnameOf(url);
  if (!host || host === 'localhost') return { viaService: false, reasons: [], redirectTo: null };

  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return { viaService: false, reasons: [], redirectTo: null };
  }

  const wanted = new Set(redirectParams.map((p) => p.toLowerCase()));
  const hostReg = registrable(host);

  for (const [key, value] of u.searchParams) {
    if (!wanted.has(key.toLowerCase())) continue;
    const destHost = hostnameOf(value); // value is auto percent-decoded; non-absolute-URLs → null
    if (!destHost || destHost === host) continue;
    if (registrable(destHost) !== hostReg) {
      return {
        viaService: true,
        reasons: [`open-redirect via ${host}: "${key}=" points off-domain to ${destHost} (link laundered through a trusted service)`],
        redirectTo: destHost,
      };
    }
  }

  return { viaService: false, reasons: [], redirectTo: null };
}

/** Registrable domain — same "last two labels" approximation the rest of the engine uses (no PSL). */
function registrable(host: string): string {
  return host.split('.').slice(-2).join('.');
}
