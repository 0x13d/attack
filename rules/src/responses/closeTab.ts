import { Response, Rule, Signal } from '../types';

/**
 * Active prevention for T1566.002: close the tab that navigated to a lookalike login domain
 * (`chrome.tabs.remove`). `tabs.remove` needs no extra permission — we already have the tab id from the
 * webNavigation event. A redirect-to-warning variant can replace this later.
 */
export const closeTabResponse: Response<{ url: string }> = {
  id: 'response.closeTab',
  name: 'Close the phishing tab (tabs.remove)',
  action: (_rule: Rule<{ url: string }>, signal: Signal<{ url: string }>) => {
    if (signal.tabId < 0 || !chrome.tabs?.remove) return;
    chrome.tabs.remove(signal.tabId, () => {
      if (chrome.runtime.lastError) return;
      console.warn(`[attack] PREVENTED — closed phishing tab ${signal.tabId} (${signal.payload.url})`);
    });
  },
};
