import { Response, Rule, Signal } from '../types';
import { markDisabledByEdr } from '../tamperState';

/**
 * The "R" of EDR for T1176.001: actively **disable** the offending extension via
 * `chrome.management.setEnabled(id, false)` — a real MV3 prevention lever (ADR-001). Never disables itself.
 *
 * Scope: management signals whose payload is the offending `ExtensionInfo`.
 */
export const disableExtensionResponse: Response<chrome.management.ExtensionInfo> = {
  id: 'response.disableExtension',
  name: 'Disable the offending extension (management.setEnabled false)',
  action: (_rule: Rule<chrome.management.ExtensionInfo>, signal: Signal<chrome.management.ExtensionInfo>) => {
    const ext = signal.payload;
    if (!ext?.id) return;
    if (ext.id === chrome.runtime.id) {
      console.warn('[attack] refusing to disable self');
      return;
    }
    if (!chrome.management?.setEnabled) {
      console.warn('[attack] management.setEnabled unavailable — cannot prevent');
      return;
    }
    chrome.management.setEnabled(ext.id, false, () => {
      if (chrome.runtime.lastError) {
        console.error(`[attack] failed to disable ${ext.id}`, chrome.runtime.lastError);
        return;
      }
      // Remember we disabled it, so a later re-enable is caught as T1176 tamper (ATK-223) — not re-flagged by .001.
      markDisabledByEdr(ext.id);
      console.warn(`[attack] PREVENTED — disabled rogue extension "${ext.name}" (${ext.id})`);
    });
  },
};
