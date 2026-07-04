import { hostnameOf } from './t1566';

/**
 * T1656 — Impersonation. Pure detection: a page **impersonating a protected brand's login** on a domain that is
 * **not** the brand's — a protected brand term appears in the host/path **together with an auth-context keyword**
 * (login / verify / secure / account / …), while the registrable domain isn't the brand.
 *
 * **Relationship / overlap (marked, not avoided — owner 2026-06-17):** implementation-distinct from T1566.002,
 * which inspects the **host** (homoglyph / typosquat / brand-as-subdomain-label). T1656 inspects the **path +
 * host substring + auth context**, so it catches e.g. `paypal-login.evil.com/verify` or `evil.net/paypal/signin`
 * that .002's exact-label logic misses. A URL can trip both (e.g. a brand-subdomain *and* an auth path) — two
 * real findings by design; clients tune which to enable. Chrome-free + unit-testable.
 */
export interface ImpersonationAssessment {
  impersonation: boolean;
  reasons: string[];
  matchedBrand?: string;
}

export function assessImpersonation(
  url: string,
  protectedDomains: string[],
  authKeywords: string[],
): ImpersonationAssessment {
  const host = hostnameOf(url);
  if (!host || host === 'localhost') return { impersonation: false, reasons: [] };

  const reg = host.split('.').slice(-2).join('.');
  // Legit brand site (the brand's own registrable domain) — never flag.
  if (protectedDomains.includes(reg)) return { impersonation: false, reasons: [] };

  const surface = `${host} ${pathAndQuery(url)}`.toLowerCase();
  const brandLabel = protectedDomains.map((d) => d.split('.')[0]).find((label) => surface.includes(label));
  if (!brandLabel) return { impersonation: false, reasons: [] };

  const authHit = authKeywords.find((k) => surface.includes(k.toLowerCase()));
  if (!authHit) return { impersonation: false, reasons: [] };

  return {
    impersonation: true,
    reasons: [`brand "${brandLabel}" + auth context "${authHit}" on non-brand domain ${host} — login-page impersonation`],
    matchedBrand: brandLabel,
  };
}

function pathAndQuery(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return '';
  }
}
