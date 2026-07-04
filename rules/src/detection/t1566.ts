/**
 * T1566.002 — Spearphishing Link. Pure detection logic for **lookalike / typosquat login domains**, isolated
 * from any `chrome.*` API so it is fully unit-testable (ATK-101). The signature calls {@link assessNavigation}.
 *
 * Heuristics against a list of protected brand domains:
 *  - **homoglyph** — the registrable label normalizes to a brand label but isn't the brand (paypa1.com → paypal)
 *  - **typosquat** — small edit distance to a brand label (paypall.com, paypl.com)
 *  - **subdomain impersonation** — a brand label appears as a non-registrable label (paypal.com.evil.net)
 *
 * Registrable domain here is a simple "last two labels" approximation (no public-suffix list) — good for the
 * demo; multi-part TLDs (`co.uk`) are a documented limitation.
 */
export interface NavigationAssessment {
  phishing: boolean;
  reasons: string[];
  matchedBrand?: string;
}

const HOMOGLYPHS: Record<string, string> = { '1': 'l', '0': 'o', '5': 's', '3': 'e', '4': 'a', '$': 's', '@': 'a' };

export function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return null;
  }
}

function normalizeHomoglyphs(s: string): string {
  return s
    .split('')
    .map((c) => HOMOGLYPHS[c] ?? c)
    .join('')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
}

function registrable(host: string): { domain: string; label: string } {
  const parts = host.split('.');
  const domain = parts.slice(-2).join('.');
  return { domain, label: parts.length >= 2 ? parts[parts.length - 2] : parts[0] };
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
    }
  }
  return d[m][n];
}

export function assessNavigation(url: string, protectedDomains: string[]): NavigationAssessment {
  const host = hostnameOf(url);
  if (!host || host === 'localhost') return { phishing: false, reasons: [] };

  const { domain, label } = registrable(host);
  const hostLabels = host.split('.');
  const reasons: string[] = [];
  let matchedBrand: string | undefined;

  for (const brandDomain of protectedDomains) {
    const brandLabel = brandDomain.split('.')[0];

    // Legitimate brand domain — never flag.
    if (domain === brandDomain) return { phishing: false, reasons: [] };

    if (normalizeHomoglyphs(label) === brandLabel) {
      reasons.push(`homoglyph lookalike of ${brandDomain} (${host})`);
      matchedBrand = brandDomain;
      continue;
    }
    const dist = levenshtein(label, brandLabel);
    if (dist >= 1 && dist <= 2) {
      reasons.push(`typosquat of ${brandDomain} (edit distance ${dist})`);
      matchedBrand = brandDomain;
      continue;
    }
    // Brand label appears as a non-registrable (sub)domain label.
    const subLabels = hostLabels.slice(0, -2);
    if (subLabels.includes(brandLabel)) {
      reasons.push(`brand "${brandLabel}" used as a subdomain of ${domain} (possible impersonation)`);
      matchedBrand = brandDomain;
    }
  }

  return { phishing: reasons.length > 0, reasons, matchedBrand };
}
