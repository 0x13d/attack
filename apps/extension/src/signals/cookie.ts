import { Engine } from '../engine';
import { CookiePayload, Scope, Signal } from '0x13d-attack-rules-community';

/**
 * Signal source for `chrome.cookies` — feeds the T1539 session-cookie rule. Dormant unless the operator
 * grants the `cookies` permission **and** host access (cookie events only arrive for hosts you can access).
 * Kept host-permission-free by default; enabling live monitoring is a deliberate operator/enterprise choice.
 */
const cookieSignals = {
  init(engine: Engine): void {
    if (!chrome.cookies?.onChanged) {
      console.warn('[attack] cookies API unavailable — T1539 dormant (needs "cookies" + host access)');
      return;
    }
    chrome.cookies.onChanged.addListener((changeInfo) => {
      if (changeInfo.removed) return; // assess only sets/updates
      const signal: Signal<CookiePayload> = {
        id: crypto.randomUUID(),
        name: 'cookie.set',
        scope: Scope.COOKIE,
        payload: { cookie: changeInfo.cookie, cause: changeInfo.cause },
        tabId: -1,
        windowId: -1,
        timestamp: Date.now(),
        hits: [],
      };
      engine.processSignal(signal);
    });
  },
};

export default cookieSignals;
