import { Policy, DEFAULT_POLICY } from '../config';
import { assessMaliciousFile } from '../detection/t1204_002';
import { makeAlertResponse } from '../responses/alert';
import { Rule, Scope, Signal, Signature } from '../types';

/**
 * **T1204.002 — User Execution: Malicious File.** Fires when a download is a **user-execution lure** — a
 * container/shortcut/installer (`iso`/`img`/`vhd`, `lnk`, `msi`/`msix`/`appx`, `chm`) the victim is tricked into
 * opening. **Detect + alert only:** the execution itself is a user action outside the browser we can't observe
 * or stop; T1105 owns the transfer-stage cancel. The lure set is **disjoint** from T1105's risky set, so a
 * single artifact never trips both (honest-framing gate — no relabeling the same hit). Reuses the `downloads`
 * signal; no new permission.
 */
export function makeT1204_002Rule(policy: Policy = DEFAULT_POLICY): Rule<chrome.downloads.DownloadItem> {
  const signature: Signature<chrome.downloads.DownloadItem> = {
    id: 'sig.t1204_002.malicious-file',
    name: 'User-execution lure download (container/shortcut/installer)',
    scope: Scope.DOWNLOAD,
    process: (signal: Signal<chrome.downloads.DownloadItem>) => {
      const item = signal.payload;
      const assessment = assessMaliciousFile(
        { filename: item.filename, url: item.finalUrl || item.url },
        policy.userExecutionLureExtensions,
      );
      if (!assessment.malicious) return false;
      signal.meta = {
        technique: 'T1204.002',
        filename: item.filename,
        url: item.finalUrl || item.url,
        extension: assessment.extension,
        reasons: assessment.reasons,
      };
      return true;
    },
  };

  return {
    id: 'rule.t1204_002.malicious-file',
    name: 'User Execution: Malicious File (lure download)',
    technique: 'T1204.002',
    scope: [Scope.DOWNLOAD],
    signatures: [signature],
    responses: [makeAlertResponse<chrome.downloads.DownloadItem>()],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}
