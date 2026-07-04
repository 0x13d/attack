import { Policy } from '0x13d-attack-rules-community';

/**
 * Managed policy. Two operating modes:
 *  - **Individual** — no managed policy; the user controls rules + settings.
 *  - **Managed** — an org pushes policy via `chrome.storage.managed` (Chrome/Edge enterprise policy +
 *    `managed_schema.json`). It **overrides** local settings and **locks** the UI: end users can't edit
 *    rules; a "Settings controlled by <orgName>" banner is shown.
 *
 * The merge is a pure function so it's unit-testable without `chrome`.
 */
export interface ManagedPolicy {
  orgName?: string;
  /** Default true. When false: user rules are disabled (not loaded) and the admin editor is locked. */
  allowUserRules?: boolean;
  protectedDomains?: string[];
}

/** Read the org policy. Returns null in individual mode (no managed policy present). */
export async function getManagedPolicy(): Promise<ManagedPolicy | null> {
  try {
    const m = await chrome.storage.managed.get(null);
    if (!m || Object.keys(m).length === 0) return null;
    return m as ManagedPolicy;
  } catch {
    return null; // managed storage unavailable → individual mode
  }
}

/** Produce the effective detection policy by overlaying managed overrides on the local base. Pure. */
export function mergePolicy(base: Policy, managed: ManagedPolicy | null): Policy {
  if (!managed) return base;
  return {
    ...base,
    protectedDomains: managed.protectedDomains ?? base.protectedDomains,
  };
}

/** Whether end users may author/load their own rules (default true). */
export function userRulesAllowed(managed: ManagedPolicy | null): boolean {
  return managed?.allowUserRules !== false;
}
