/**
 * T1204.002 — User Execution: Malicious File. Pure detection: a downloaded artifact whose type is a
 * **user-executable lure** — a container / shortcut / installer the victim is socially-engineered into opening
 * (double-click to run).
 *
 * **Separable from T1105 (Ingress Tool Transfer), by design (honest-framing gate):** T1105 flags raw
 * script/quasi-executable transfers (`hta`/`scr`/`vbs`/…) and double-extension masks; T1204.002 flags the
 * *lure-container* class (`iso`/`img`/`vhd`, `lnk`, `msi`/`msix`/`appx`, `chm`). The two extension sets are
 * **disjoint**, so a single artifact never trips both rules. T1204.002 is **detect + alert** (we observe the
 * lure arriving; the *execution* is a user action outside the browser we can't see or stop — T1105 owns the
 * transfer-stage cancel). Chrome-free + unit-testable.
 */
export interface FileLike {
  filename: string;
  url: string;
}

export interface MaliciousFileAssessment {
  malicious: boolean;
  reasons: string[];
  /** The triggering lure extension (lowercased, no dot); null when no match. */
  extension: string | null;
}

/** Lure types that mount/run and bypass mark-of-the-web — called out specially in the reason. */
const MOTW_BYPASS = new Set(['iso', 'img', 'vhd', 'vhdx']);

export function assessMaliciousFile(item: FileLike, lureExtensions: string[]): MaliciousFileAssessment {
  const name = basename(item.filename || pathOf(item.url)).toLowerCase();
  const parts = name.split('.').filter(Boolean);
  const ext = parts.length > 1 ? parts[parts.length - 1] : '';
  const lures = new Set(lureExtensions.map((e) => e.toLowerCase().replace(/^\./, '')));

  if (ext === '' || !lures.has(ext)) return { malicious: false, reasons: [], extension: null };

  const detail = MOTW_BYPASS.has(ext)
    ? `mounts/opens to run, bypassing mark-of-the-web`
    : `commonly double-clicked to run`;
  return {
    malicious: true,
    reasons: [`user-execution lure: .${ext} (container/shortcut/installer — ${detail})`],
    extension: ext,
  };
}

function basename(path: string): string {
  const cut = path.replace(/\\/g, '/');
  return cut.slice(cut.lastIndexOf('/') + 1);
}

function pathOf(rawUrl: string): string {
  try {
    return new URL(rawUrl).pathname;
  } catch {
    return rawUrl;
  }
}
