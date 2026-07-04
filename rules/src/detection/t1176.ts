import { Policy } from '../config';

/**
 * T1176.001 — Browser Extensions. Pure detection logic, isolated from any `chrome.*` API so it is fully
 * unit-testable (ATK-004). The signature and the responses both call {@link assessExtension}; the responses
 * re-derive the assessment to attach human-readable reasons to the alert.
 *
 * Heuristic (defensible, low-false-positive): an extension being installed/enabled is **rogue** when it is
 * neither approved nor our own *and* carries at least one risk signal — sideloaded/unpacked install,
 * high-risk permissions, or broad host access. A plain Web-Store extension with ordinary permissions does
 * not trip it.
 */
export interface ExtensionAssessment {
  rogue: boolean;
  reasons: string[];
  riskyPermissions: string[];
}

/** The subset of `chrome.management.ExtensionInfo` the assessment needs (keeps tests chrome-free). */
export interface AssessableExtension {
  id: string;
  name: string;
  /** `chrome.management.ExtensionInfo['installType']` — 'normal' | 'development' | 'sideload' | 'admin' | 'other'. */
  installType: string;
  permissions: string[];
  hostPermissions: string[];
}

export function assessExtension(
  ext: AssessableExtension,
  policy: Policy,
  selfId: string,
): ExtensionAssessment {
  // Never flag ourselves or an approved extension.
  if (ext.id === selfId || policy.approvedExtensionIds.includes(ext.id)) {
    return { rogue: false, reasons: [], riskyPermissions: [] };
  }

  const reasons: string[] = [];

  // Sideloaded / unpacked — 'normal' means installed from the Web Store; everything else is suspect.
  if (ext.installType !== 'normal' && ext.installType !== 'admin') {
    reasons.push(`unmanaged install source (installType=${ext.installType})`);
  }

  const riskyPermissions = ext.permissions.filter((p) => policy.highRiskPermissions.includes(p));
  if (riskyPermissions.length > 0) {
    reasons.push(`requests high-risk permissions: ${riskyPermissions.join(', ')}`);
  }

  const broadHost = ext.hostPermissions.some((h) => policy.broadHostPatterns.includes(h));
  if (broadHost) {
    reasons.push('broad host access (all-URLs)');
  }

  return { rogue: reasons.length > 0, reasons, riskyPermissions };
}
