import { Engine } from '../engine';
import { Scope, Signal } from '0x13d-attack-rules-community';

/**
 * Signal source for `chrome.management` — the browser-EDR view a host agent can't see: other extensions
 * being installed or enabled. Feeds the **T1176.001 Browser Extensions** rule (ATK-003).
 *
 * Scaffold note (ATK-001): this wires the events into normalized signals. The signature + responses (alert +
 * `setEnabled(false)`) land in ATK-003.
 */
const managementSignals = {
  init(engine: Engine): void {
    if (!chrome.management?.onInstalled) {
      console.warn('[attack] management API unavailable — check the "management" permission');
      return;
    }

    chrome.management.onInstalled.addListener((info) => {
      engine.processSignal(toSignal('management.installed', info));
    });

    chrome.management.onEnabled.addListener((info) => {
      engine.processSignal(toSignal('management.enabled', info));
    });
  },
};

function toSignal(name: string, info: chrome.management.ExtensionInfo): Signal<chrome.management.ExtensionInfo> {
  return {
    id: crypto.randomUUID(),
    name,
    scope: Scope.MANAGEMENT,
    payload: info,
    tabId: -1,
    windowId: -1,
    timestamp: Date.now(),
    hits: [],
  };
}

export default managementSignals;
