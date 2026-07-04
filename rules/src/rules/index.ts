import { DEFAULT_POLICY, Policy } from '../config';
import { Rule } from '../types';
import { makeT1176Rule } from './t1176-browser-extensions';
import { makeT1566Rule } from './t1566-spearphishing-link';
import { makeT1539Rule } from './t1539-session-cookie';
import { makeT1185Rule } from './t1185-reverse-tabnabbing';
import { makeT1528Rule } from './t1528-oauth-consent';
import { makeT1105Rule } from './t1105-ingress-tool-transfer';
import { makeT1204_002Rule } from './t1204_002-malicious-file';
import { makeT1566_001Rule } from './t1566_001-spearphishing-attachment';
import { makeT1176TamperRule } from './t1176-tamper';
import { makeT1566_003Rule } from './t1566_003-spearphishing-via-service';
import { makeT1204_001Rule } from './t1204_001-malicious-link';
import { makeT1189Rule } from './t1189-drive-by';
import { makeT1656Rule } from './t1656-impersonation';
import { makeT1550_004Rule } from './t1550_004-web-session-cookie';
import { makeT1606_002Rule } from './t1606_002-saml-tokens';
import { makeT1217Rule } from './t1217-browser-info-discovery';

/**
 * Build the active built-in rule set for an effective policy (ADR-001; the policy may be overridden by an
 * enterprise managed policy, ATK-208). Registering a rule here is what brings its technique online — keep
 * this in lockstep with the manifest's permission set.
 *
 * - **T1176.001** Browser Extensions — needs `management` (+ `notifications` for the alert). ✓ shipped.
 * - **T1566.002** Spearphishing Link — needs `webNavigation` (tabs.remove needs no extra permission). ✓ shipped.
 * - **T1539** Steal Web Session Cookie — needs `cookies` + host access; **dormant** until the operator grants
 *   host_permissions (kept out of the default manifest). The rule + detection ship; live monitoring is gated.
 * - **T1185** Browser Session Hijacking (reverse tabnabbing) — **cross-tab**; needs `webNavigation`. ✓ shipped.
 * - **T1528** Illicit OAuth Consent — high-risk-scope consent grab; reuses `webNavigation` (no new perm). ✓ shipped.
 * - **T1105** Ingress Tool Transfer — risky download; needs `downloads` (cancel needs no host_permissions). ✓ shipped (ATK-103).
 * - **T1204.002** User Execution: Malicious File — user-execution lure download (container/shortcut/installer);
 *   reuses `downloads`, detect+alert. ✓ shipped (ATK-221). Disjoint lure set from T1105.
 * - **T1566.001** Spearphishing Attachment — attachment-lure download from a phishing-delivery context (referrer);
 *   reuses `downloads`, detect+alert. ✓ shipped (ATK-222). Keyed on delivery vector, disjoint file class.
 * - **T1176** Browser Extensions (tamper) — re-enable of an EDR-disabled extension (persistence); reuses
 *   `management`, alert + re-disable. ✓ shipped (ATK-223). Keyed on state transition; .001 defers (no double-fire).
 * - **T1566.003** Spearphishing via Service — off-domain open-redirect laundered through a trusted service;
 *   reuses `webNavigation`, detect+alert. ✓ shipped (ATK-224). Distinct signal from T1566.002 (brand lookalike).
 * - **T1204.001** User Execution: Malicious Link — navigation to a threat-blocklist (known-bad IOC) destination;
 *   reuses `webNavigation`, alert + close tab. ✓ shipped (ATK-225). Keyed on destination IOC, not heuristic.
 * - **T1189** Drive-by Compromise — automatic client-redirect chain (≥ threshold hops); reuses `webNavigation`,
 *   alert + close tab. ✓ shipped (ATK-226). Keyed on redirect *behavior*, not destination.
 * - **T1656** Impersonation — brand term + auth-context keyword on a non-brand domain; reuses `webNavigation`,
 *   detect+alert. ✓ shipped (ATK-227). Path/keyword angle, complements T1566.002's host-lookalike.
 * - **T1550.004** Use of Web Session Cookie — session/auth cookie made persistent (reuse); reuses `cookie`
 *   (dormant w/o host access), alert + cookies.remove. ✓ shipped (ATK-228). Persistence attribute, distinct from T1539.
 * - **T1606.002** Forge Web Credentials: SAML — SAML-token flow to a non-allowlisted host; reuses `webNavigation`,
 *   detect+alert. ✓ shipped (ATK-229). SSO/credential-forging visibility signal.
 * - **T1217** Browser Information Discovery — non-approved extension holding recon perms (bookmarks/history/
 *   topSites); reuses `management`, detect+alert. ✓ shipped (ATK-230). Capability angle, distinct from T1176.001.
 *
 * **The community slate: 16 techniques, zero host permissions, no egress.**
 */
export function buildRules(policy: Policy = DEFAULT_POLICY): Rule<unknown>[] {
  // The 16 community rules. Source of truth for the community count.
  const rules: Rule<unknown>[] = [
    makeT1176Rule(policy) as unknown as Rule<unknown>,
    makeT1566Rule(policy) as unknown as Rule<unknown>,
    makeT1539Rule(policy) as unknown as Rule<unknown>,
    makeT1185Rule(policy) as unknown as Rule<unknown>,
    makeT1528Rule(policy) as unknown as Rule<unknown>,
    makeT1105Rule(policy) as unknown as Rule<unknown>,
    makeT1204_002Rule(policy) as unknown as Rule<unknown>,
    makeT1566_001Rule(policy) as unknown as Rule<unknown>,
    makeT1176TamperRule(policy) as unknown as Rule<unknown>,
    makeT1566_003Rule(policy) as unknown as Rule<unknown>,
    makeT1204_001Rule(policy) as unknown as Rule<unknown>,
    makeT1189Rule(policy) as unknown as Rule<unknown>,
    makeT1656Rule(policy) as unknown as Rule<unknown>,
    makeT1550_004Rule(policy) as unknown as Rule<unknown>,
    makeT1606_002Rule(policy) as unknown as Rule<unknown>,
    makeT1217Rule(policy) as unknown as Rule<unknown>,
  ];

  return rules;
}
