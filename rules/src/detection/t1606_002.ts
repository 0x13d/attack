import { hostnameOf } from './t1566';

/**
 * T1606.002 — Forge Web Credentials: SAML Tokens. Pure detection: a navigation carrying a **SAML assertion
 * indicator** (a `SAMLResponse`/`SAMLRequest`/`SAMLart` query param, or an ACS/SSO endpoint path) to a host that
 * is **not** in the operator's SAML allowlist. Golden-/forged-SAML deliver an assertion to a service provider
 * through the browser; a SAML flow to an *unexpected* endpoint is worth SOC scrutiny.
 *
 * **Honest framing:** heuristic + visibility-oriented. The browser can't *validate* an assertion (that's
 * server-side / out of scope), and POST-binding assertions aren't in the URL — so this catches redirect-binding
 * flows + ACS-path navigations. With an **empty `samlTrustedHosts` (default) it flags all SAML flows** for
 * visibility; operators allowlist their IdP/SP to tune. Distinct from the phishing-nav rules (a credential-
 * forging/SSO signal, not a lookalike/redirect). Chrome-free + unit-testable.
 */
const SAML_PARAMS = ['samlresponse', 'samlrequest', 'samlart'];
const SAML_PATHS = ['/saml', '/sso', '/acs', '/adfs/ls', '/saml2', '/simplesaml'];

export interface SamlAssessment {
  saml: boolean;
  reasons: string[];
}

export function assessSamlFlow(url: string, trustedHosts: string[]): SamlAssessment {
  const host = hostnameOf(url);
  if (!host || host === 'localhost') return { saml: false, reasons: [] };
  if (trustedHosts.some((h) => host === h.toLowerCase() || host.endsWith(`.${h.toLowerCase()}`))) {
    return { saml: false, reasons: [] };
  }

  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return { saml: false, reasons: [] };
  }

  const paramHit = [...u.searchParams.keys()].find((k) => SAML_PARAMS.includes(k.toLowerCase()));
  const path = u.pathname.toLowerCase();
  const pathHit = SAML_PATHS.find((p) => path.includes(p));
  if (!paramHit && !pathHit) return { saml: false, reasons: [] };

  const detail = paramHit ? `SAML assertion param "${paramHit}"` : `SAML/SSO endpoint path "${pathHit}"`;
  return {
    saml: true,
    reasons: [`SAML-token flow to non-allowlisted host ${host} (${detail}) — scrutinize for forged / golden-SAML assertion`],
  };
}
