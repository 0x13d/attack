/**
 * T1185 — Browser Session Hijacking, via **reverse tabnabbing**. Pure, chrome-free, unit-testable.
 *
 * Reverse tabnabbing is cross-tab: a page opened in a new tab (via `target=_blank` without `rel=noopener`)
 * uses `window.opener` to **rewrite the original (opener) tab** to a phishing page. We detect the tell-tale:
 * an **opener tab** is navigated by a **client (script) redirect** to a **different origin** — i.e., its tab
 * changed origins without a user gesture, driven from another tab it spawned.
 */
export interface TabnabInput {
  /** Was this tab an opener (it spawned another tab via target=_blank)? */
  isOpener: boolean;
  /** The opener tab's origin before this navigation. */
  fromOrigin: string | null;
  /** The origin it just navigated to. */
  toOrigin: string;
  /** Did the navigation come from a client/script redirect (no user gesture)? */
  isClientRedirect: boolean;
}

export interface TabnabAssessment {
  detected: boolean;
  reason?: string;
}

export function detectReverseTabnab(input: TabnabInput): TabnabAssessment {
  if (!input.isOpener) return { detected: false };
  if (!input.isClientRedirect) return { detected: false };
  if (!input.fromOrigin || input.fromOrigin === input.toOrigin) return { detected: false };
  return {
    detected: true,
    reason: `opener tab was script-redirected from ${input.fromOrigin} to ${input.toOrigin} (reverse tabnabbing)`,
  };
}

export function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}
