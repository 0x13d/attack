/**
 * T1189 — Drive-by Compromise. Pure detection: an **automatic client-redirect chain** — N consecutive
 * client-side redirects (meta-refresh / `location` rewrites) in a tab with **no user interaction** — the
 * delivery pattern of drive-by / exploit-kit landing pages that bounce a victim through redirectors.
 *
 * **Relationship / overlap (marked — owner 2026-06-17):** keyed on **redirect *behavior*** (chain length),
 * distinct from the destination-keyed webNavigation rules — T1566.002 (lookalike *domain*), T1204.001 (known-bad
 * *IOC*), T1566.003 (open-redirect *param*). A drive-by chain landing on a blocklisted/lookalike host fires more
 * than one, by design. **Heuristic only** — real exploit/payload analysis is out of scope (bucket D, would need
 * heavy in-page WASM-class inspection). Chrome-free + unit-testable.
 */
export interface DriveByAssessment {
  driveBy: boolean;
  reasons: string[];
}

export function assessDriveBy(redirectChainLength: number, threshold: number): DriveByAssessment {
  if (!Number.isFinite(redirectChainLength) || redirectChainLength < threshold) {
    return { driveBy: false, reasons: [] };
  }
  return {
    driveBy: true,
    reasons: [`automatic client-redirect chain of ${redirectChainLength} hops with no user interaction — drive-by delivery pattern`],
  };
}
