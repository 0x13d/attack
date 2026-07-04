import { hostnameOf } from './t1566';

/**
 * T1204.001 — User Execution: Malicious Link. Pure detection: a navigation whose destination host matches a
 * **threat blocklist** (operator/feed-supplied known-bad indicators) — the user followed a link to a
 * known-malicious destination.
 *
 * **Relationship / overlap (marked, not avoided — owner 2026-06-17):**
 *  - vs **T1566.002** (lookalike login): .002 is a *heuristic* (brand similarity, no prior knowledge);
 *    T1204.001 is *explicit known-bad* (an IOC/blocklist). A known-bad host that is *also* a lookalike fires
 *    both — two real findings a client can tune independently.
 *  - vs **T1566.003** (open-redirect) / **T1189** (drive-by): those key on the *delivery mechanism / redirect
 *    behavior*; T1204.001 keys on the *destination identity* (the IOC).
 *
 * Blocklist entries are host/registrable-domain IOCs; a match is the host itself or any subdomain of it.
 * Default ships sample reserved-TLD indicators — operators replace `policy.threatBlocklist` with their feed.
 * Chrome-free + unit-testable.
 */
export interface MaliciousLinkAssessment {
  malicious: boolean;
  reasons: string[];
  matchedIndicator: string | null;
}

export function assessMaliciousLink(url: string, blocklist: string[]): MaliciousLinkAssessment {
  const host = hostnameOf(url);
  if (!host || host === 'localhost') return { malicious: false, reasons: [], matchedIndicator: null };

  for (const raw of blocklist) {
    const ioc = raw.toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '');
    if (!ioc) continue;
    if (host === ioc || host.endsWith(`.${ioc}`)) {
      return {
        malicious: true,
        reasons: [`navigation to a blocklisted destination ${host} (threat-IOC match: ${ioc})`],
        matchedIndicator: ioc,
      };
    }
  }

  return { malicious: false, reasons: [], matchedIndicator: null };
}
