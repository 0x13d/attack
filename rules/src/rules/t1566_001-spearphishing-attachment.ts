import { Policy, DEFAULT_POLICY } from '../config';
import { assessAttachment } from '../detection/t1566_001';
import { makeAlertResponse } from '../responses/alert';
import { Rule, Scope, Signal, Signature } from '../types';

/**
 * **T1566.001 — Spearphishing Attachment.** Fires when a download is an **attachment lure** (macro-enabled
 * office doc or a smuggling-prone web format) **delivered from a phishing context** — a webmail / file-share /
 * messaging referrer, or an otherwise suspicious referring origin. Keyed on the **delivery vector** (referrer),
 * which separates it from T1105 (raw transfer) and T1204.002 (lure containers); the file classes are disjoint
 * too. **Detect + alert** (the attachment arriving is the signal; opening it is the user's action). Reuses the
 * `downloads` signal; no new permission.
 */
export function makeT1566_001Rule(policy: Policy = DEFAULT_POLICY): Rule<chrome.downloads.DownloadItem> {
  const signature: Signature<chrome.downloads.DownloadItem> = {
    id: 'sig.t1566_001.spearphishing-attachment',
    name: 'Spearphishing attachment (lure file from a delivery context)',
    scope: Scope.DOWNLOAD,
    process: (signal: Signal<chrome.downloads.DownloadItem>) => {
      const item = signal.payload;
      const assessment = assessAttachment(
        { filename: item.filename, url: item.finalUrl || item.url, referrer: item.referrer ?? '' },
        policy.attachmentExtensions,
        policy.attachmentDeliveryOrigins,
      );
      if (!assessment.spearphish) return false;
      signal.meta = {
        technique: 'T1566.001',
        filename: item.filename,
        url: item.finalUrl || item.url,
        referrer: item.referrer ?? '',
        extension: assessment.extension,
        reasons: assessment.reasons,
      };
      return true;
    },
  };

  return {
    id: 'rule.t1566_001.spearphishing-attachment',
    name: 'Spearphishing Attachment (lure download from a delivery context)',
    technique: 'T1566.001',
    scope: [Scope.DOWNLOAD],
    signatures: [signature],
    responses: [makeAlertResponse<chrome.downloads.DownloadItem>()],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}
