/**
 * T1176 — Browser Extensions (tamper variant). Pure detection, chrome-free + unit-testable.
 *
 * **Separable from T1176.001 (honest-framing gate):** T1176.001 flags a *rogue* extension being installed or
 * enabled (sideloaded / high-risk perms / broad host). This variant fires on a different signal entirely — an
 * extension the **EDR itself disabled** being **re-enabled** (a persistence / EDR-evasion state transition),
 * regardless of the extension's current rogue-ness. The two never fire on the same event: T1176.001 defers
 * (returns false) for a re-enable of an EDR-disabled id, and this rule owns that case.
 */
export function isReEnableTamper(signalName: string, extId: string, edrDisabledIds: ReadonlySet<string>): boolean {
  return signalName === 'management.enabled' && !!extId && edrDisabledIds.has(extId);
}
