import { Response, Rule, Signal } from '../types';

/**
 * Active prevention for T1105: cancel the in-flight download (`chrome.downloads.cancel`) and erase its record
 * (`chrome.downloads.erase`) — stop the tool/payload before it lands. `onCreated` fires while the download can
 * still be cancelled. Needs only `downloads` — **no `host_permissions`** (operates on the download id).
 */
export const cancelDownloadResponse: Response<chrome.downloads.DownloadItem> = {
  id: 'response.cancelDownload',
  name: 'Cancel + erase the malicious download (downloads.cancel/.erase)',
  action: (_rule: Rule<chrome.downloads.DownloadItem>, signal: Signal<chrome.downloads.DownloadItem>) => {
    const id = signal.payload?.id;
    if (!chrome.downloads?.cancel || typeof id !== 'number') return;
    chrome.downloads.cancel(id, () => {
      if (chrome.runtime.lastError) return; // already complete / canceled — nothing to do
      console.warn(`[attack] PREVENTED — cancelled malicious download #${id} (${signal.payload.filename})`);
      chrome.downloads.erase?.({ id }, () => void chrome.runtime.lastError);
    });
  },
};
