/**
 * Tracks the extension ids the EDR has **disabled**, so the T1176 tamper rule (`ATK-223`) can detect a
 * **re-enable** — an attacker or another extension turning a killed rogue back on (persistence / EDR-evasion) —
 * without T1176.001 double-firing on it.
 *
 * The in-memory `Set` is the live source during a worker lifetime (signature reads are **synchronous**); it is
 * mirrored to `chrome.storage.local` so it survives the ephemeral MV3 service worker. Persistence is async and
 * best-effort; reads never block.
 */
const STORAGE_KEY = 'attack:edrDisabledExtensionIds';
const disabledByEdr = new Set<string>();

/** Record that the EDR disabled this extension (called by the disable response on success). */
export function markDisabledByEdr(id: string): void {
  if (!id) return;
  disabledByEdr.add(id);
  void persist();
}

/** Synchronous check used by the rule signatures. */
export function wasDisabledByEdr(id: string): boolean {
  return disabledByEdr.has(id);
}

/** Live read-only view of the set (passed to the pure detection helper). */
export function getEdrDisabledIds(): ReadonlySet<string> {
  return disabledByEdr;
}

/** Load the persisted ids into memory at worker startup. */
export async function hydrateDisabledByEdr(): Promise<void> {
  if (typeof chrome === 'undefined' || !chrome.storage?.local) return;
  try {
    const got = await chrome.storage.local.get(STORAGE_KEY);
    const ids = got?.[STORAGE_KEY];
    if (Array.isArray(ids)) for (const id of ids) if (typeof id === 'string') disabledByEdr.add(id);
  } catch {
    /* start empty on any read error */
  }
}

async function persist(): Promise<void> {
  if (typeof chrome === 'undefined' || !chrome.storage?.local) return;
  try {
    await chrome.storage.local.set({ [STORAGE_KEY]: [...disabledByEdr] });
  } catch {
    /* best-effort */
  }
}

/** Test-only: reset the in-memory set. */
export function __resetTamperState(): void {
  disabledByEdr.clear();
}
