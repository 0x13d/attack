/**
 * T1528 — Steal Application Access Token, via **illicit OAuth consent** ("consent phishing"). Pure,
 * chrome-free, unit-testable. A navigation to an OAuth **authorize** endpoint requesting **high-risk scopes**
 * (and, when an allowlist is set, from an **unknown client_id**) is the consent-grab signal.
 */
export interface OAuthAssessment {
  risk: boolean;
  reasons: string[];
  riskyScopes: string[];
}

// Authorize endpoints across the common IdPs (Microsoft, Google, Okta, generic OIDC).
const AUTHORIZE_RE = /\/(oauth2?\/(v2\.0\/)?authorize|o\/oauth2\/(v2\/)?auth|connect\/authorize|authorize)(\/|$|\?)/i;

export function assessOAuthConsent(url: string, highRiskScopes: string[], approvedClients: string[]): OAuthAssessment {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return { risk: false, reasons: [], riskyScopes: [] };
  }
  if (!AUTHORIZE_RE.test(u.pathname + (u.search ? '?' : ''))) return { risk: false, reasons: [], riskyScopes: [] };

  const scopes = (u.searchParams.get('scope') ?? '').split(/[\s+]+/).filter(Boolean);
  const clientId = u.searchParams.get('client_id') ?? '';

  const riskyScopes = scopes.filter((s) => highRiskScopes.some((h) => s.toLowerCase().includes(h.toLowerCase())));
  const reasons: string[] = [];
  if (riskyScopes.length > 0) reasons.push(`OAuth consent requests high-risk scopes: ${riskyScopes.join(', ')}`);
  if (approvedClients.length > 0 && clientId && !approvedClients.includes(clientId)) {
    reasons.push(`unknown OAuth client_id: ${clientId}`);
  }

  return { risk: riskyScopes.length > 0, reasons, riskyScopes };
}
