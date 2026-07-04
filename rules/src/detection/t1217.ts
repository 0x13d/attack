/**
 * T1217 — Browser Information Discovery. Pure detection, chrome-free + unit-testable.
 *
 * **Signal note (resolved at planning, owner 2026-06-17):** the `bookmarks`/`history` APIs let *us* read those
 * stores but emit **no event when another actor reads them** — so a scrape isn't directly observable. The
 * browser-observable proxy is **capability**: a non-approved extension that *holds* browser-data-discovery
 * permissions (`bookmarks`/`history`/`topSites`) is positioned to enumerate them for recon. Reuses the
 * `management` signal (no new permission).
 *
 * **Relationship / overlap (marked — owner 2026-06-17):** distinct from **T1176.001** — those recon permissions
 * are **not** in `highRiskPermissions`, so .001 doesn't flag an extension for holding them. A sideloaded ext
 * with recon perms fires *both* (one cause, two angles), by design. Heuristic + tunable: legit extensions hold
 * these too, so it's detect-only and operators allowlist via `approvedExtensionIds`.
 */
export interface ReconAssessable {
  id: string;
  name: string;
  permissions: string[];
}

export interface ReconExtensionAssessment {
  recon: boolean;
  reasons: string[];
  reconPermissions: string[];
}

export function assessReconExtension(
  ext: ReconAssessable,
  reconPermissions: string[],
  approvedIds: string[],
  selfId: string,
): ReconExtensionAssessment {
  if (ext.id === selfId || approvedIds.includes(ext.id)) return { recon: false, reasons: [], reconPermissions: [] };

  const hit = ext.permissions.filter((p) => reconPermissions.includes(p));
  if (hit.length === 0) return { recon: false, reasons: [], reconPermissions: [] };

  return {
    recon: true,
    reasons: [`extension "${ext.name}" holds browser-data-discovery permissions (${hit.join(', ')}) — positioned to enumerate bookmarks/history (recon)`],
    reconPermissions: hit,
  };
}
