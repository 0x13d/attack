import { Policy, DEFAULT_POLICY } from '../config';
import { assessDownload } from '../detection/t1105';
import { makeAlertResponse } from '../responses/alert';
import { cancelDownloadResponse } from '../responses/cancelDownload';
import { Response, Rule, Scope, Signal, Signature } from '../types';

/**
 * **T1105 — Ingress Tool Transfer.** Fires when a download looks like a tool/payload being pulled onto the host
 * — a rarely-legitimate script/quasi-executable artifact, an executable masked by a double extension, and/or
 * delivery from a suspicious origin. Alerts and cancels the download (`downloads.cancel`/`.erase`). Needs
 * `downloads`; **no `host_permissions`**.
 */
export function makeT1105Rule(policy: Policy = DEFAULT_POLICY): Rule<chrome.downloads.DownloadItem> {
  const signature: Signature<chrome.downloads.DownloadItem> = {
    id: 'sig.t1105.risky-download',
    name: 'Risky artifact download (ingress tool transfer)',
    scope: Scope.DOWNLOAD,
    process: (signal: Signal<chrome.downloads.DownloadItem>) => {
      const item = signal.payload;
      const assessment = assessDownload(
        { filename: item.filename, url: item.finalUrl || item.url, mime: item.mime },
        policy.riskyDownloadExtensions,
      );
      if (!assessment.transferRisk) return false;
      signal.meta = {
        technique: 'T1105',
        filename: item.filename,
        url: item.finalUrl || item.url,
        extension: assessment.extension,
        reasons: assessment.reasons,
      };
      return true;
    },
  };

  return {
    id: 'rule.t1105.ingress-tool-transfer',
    name: 'Ingress Tool Transfer (malicious download)',
    technique: 'T1105',
    scope: [Scope.DOWNLOAD],
    signatures: [signature],
    responses: [
      makeAlertResponse<chrome.downloads.DownloadItem>(),
      cancelDownloadResponse as unknown as Response<chrome.downloads.DownloadItem>,
    ],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}
