import { Policy, DEFAULT_POLICY } from '../config';
import { assessMaliciousLink } from '../detection/t1204_001';
import { makeAlertResponse } from '../responses/alert';
import { closeTabResponse } from '../responses/closeTab';
import { Response, Rule, Scope, Signal, Signature } from '../types';

type Nav = { url: string; transitionType: string };

/**
 * **T1204.001 — User Execution: Malicious Link.** Fires when a top-frame navigation lands on a destination on
 * the **threat blocklist** (operator/feed-supplied known-bad IOCs). On a hit it **alerts** and **closes the tab**
 * (active prevention — the destination is explicitly known-bad). Reuses `webNavigation`; no new permission.
 *
 * **Relationship:** keyed on *destination identity* (a known-bad IOC), distinct from T1566.002 (brand-lookalike
 * heuristic), T1566.003 (open-redirect delivery), and T1189 (redirect-chain behavior). Overlaps fire by design.
 */
export function makeT1204_001Rule(policy: Policy = DEFAULT_POLICY): Rule<Nav> {
  const signature: Signature<Nav> = {
    id: 'sig.t1204_001.malicious-link',
    name: 'Navigation to a blocklisted (known-bad) destination',
    scope: Scope.WEB_NAVIGATION,
    process: (signal: Signal<Nav>) => {
      const assessment = assessMaliciousLink(signal.payload.url, policy.threatBlocklist);
      if (!assessment.malicious) return false;
      signal.meta = {
        technique: 'T1204.001',
        url: signal.payload.url,
        matchedIndicator: assessment.matchedIndicator,
        reasons: assessment.reasons,
        relationship: 'keyed on a known-bad IOC (blocklist) — distinct from T1566.002 lookalike heuristic / T1566.003 open-redirect',
      };
      return true;
    },
  };

  return {
    id: 'rule.t1204_001.malicious-link',
    name: 'User Execution: Malicious Link (blocklisted destination)',
    technique: 'T1204.001',
    scope: [Scope.WEB_NAVIGATION],
    signatures: [signature],
    responses: [makeAlertResponse<Nav>(), closeTabResponse as unknown as Response<Nav>],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}
