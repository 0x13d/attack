import { Engine } from '../engine';
import { Scope, Signal } from '0x13d-attack-rules-community';

/**
 * Signal source for `chrome.downloads` — the browser-EDR view of an artifact arriving on disk: feeds the
 * **T1105 Ingress Tool Transfer** rule (ATK-103). `onCreated` fires as a download begins — while it can still
 * be cancelled — carrying the `url`/`finalUrl`/`filename`/`mime`/`referrer` the signature judges.
 *
 * Permission rationale (ATK-103a, scoped-manifest decision): needs **`downloads`** to observe + cancel. It does
 * **not** need `host_permissions` — `downloads.cancel`/`.erase` (the active response, ATK-103b) work on the
 * download id alone.
 *
 * Scaffold note (ATK-103a): this wires the event into a normalized signal. The signature (risky artifact from a
 * suspicious origin) + the `downloads.cancel`/`.erase` response land in ATK-103b.
 */
const downloadSignals = {
  init(engine: Engine): void {
    if (!chrome.downloads?.onCreated) {
      console.warn('[attack] downloads API unavailable — check the "downloads" permission');
      return;
    }

    chrome.downloads.onCreated.addListener((item) => {
      engine.processSignal(toSignal('download.created', item));
    });
  },
};

function toSignal(name: string, item: chrome.downloads.DownloadItem): Signal<chrome.downloads.DownloadItem> {
  return {
    id: crypto.randomUUID(),
    name,
    scope: Scope.DOWNLOAD,
    payload: item,
    tabId: -1,
    windowId: -1,
    timestamp: Date.now(),
    hits: [],
  };
}

export default downloadSignals;
