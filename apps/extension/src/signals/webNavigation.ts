import { Engine } from '../engine';
import { detectReverseTabnab, originOf } from '0x13d-attack-rules-community/detection/t1185';
import { Scope, Signal } from '0x13d-attack-rules-community';

/**
 * Signal source for `chrome.webNavigation` — feeds T1566.002 (lookalike login), T1566.003 (open-redirect),
 * T1204.001 (blocklist), T1185 reverse tabnabbing (cross-tab opener tracking), and T1189 drive-by (per-tab
 * **client-redirect chain** length). It keeps a small per-tab origin map, an opener set, and a per-tab
 * consecutive-client-redirect counter.
 */
const tabOrigin = new Map<number, string>();
const openerTabs = new Set<number>();
const redirectChain = new Map<number, number>(); // tabId → consecutive client-redirect hops (T1189)

const webNavigationSignals = {
  init(engine: Engine): void {
    if (!chrome.webNavigation?.onCommitted) {
      console.warn('[attack] webNavigation API unavailable — check the "webNavigation" permission');
      return;
    }

    // A tab spawned another (target=_blank). The source becomes a tracked opener (reverse-tabnabbing candidate).
    chrome.webNavigation.onCreatedNavigationTarget?.addListener((details) => {
      openerTabs.add(details.sourceTabId);
    });

    chrome.webNavigation.onCommitted.addListener((details) => {
      if (details.frameId !== 0) return; // top frame only
      const newOrigin = originOf(details.url);
      const isClientRedirect = (details.transitionQualifiers ?? []).includes('client_redirect');

      // Cross-tab: did an opener tab just get script-rewritten to a new origin? → reverse tabnabbing (T1185).
      const fromOrigin = tabOrigin.get(details.tabId) ?? null;
      if (openerTabs.has(details.tabId) && newOrigin) {
        const verdict = detectReverseTabnab({ isOpener: true, fromOrigin, toOrigin: newOrigin, isClientRedirect });
        if (verdict.detected) {
          engine.processSignal(toSignal('webNavigation.reverseTabnab', details, { fromOrigin, toOrigin: newOrigin }));
        }
      }
      if (newOrigin) tabOrigin.set(details.tabId, newOrigin);

      // T1189: count consecutive auto client-redirects per tab; a user-initiated navigation resets the chain.
      const chainLength = isClientRedirect ? (redirectChain.get(details.tabId) ?? 0) + 1 : 0;
      redirectChain.set(details.tabId, chainLength);

      engine.processSignal(toSignal('webNavigation.committed', details, { isClientRedirect, redirectChainLength: chainLength }));
    });
  },
};

type NavExtra = { fromOrigin?: string | null; toOrigin?: string; isClientRedirect?: boolean; redirectChainLength?: number };

function toSignal(name: string, details: chrome.webNavigation.WebNavigationTransitionCallbackDetails, extra: NavExtra): Signal<{ url: string; transitionType: string } & NavExtra> {
  return {
    id: crypto.randomUUID(),
    name,
    scope: Scope.WEB_NAVIGATION,
    payload: { url: details.url, transitionType: details.transitionType, ...extra },
    tabId: details.tabId,
    windowId: -1,
    timestamp: Date.now(),
    hits: [],
  };
}

export default webNavigationSignals;
