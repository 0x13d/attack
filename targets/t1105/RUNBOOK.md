# Runbook — T1105 Ingress Tool Transfer (malicious download)

**Proves:** the EDR detects a **risky artifact download** — a rarely-legitimate script/quasi-executable
(`.hta`) or an executable masked by a **double extension** (`.jpg.scr`) — **alerts**, and **cancels the
download** (active prevention). Everything is benign, local, and plain text — nothing runs.

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as in the [T1176 runbook](../t1176/RUNBOOK.md). The build now also
   registers the `downloads` rule (the manifest gained the `downloads` permission).
2. Serve the benign target locally:
   ```bash
   python3 -m http.server 8000 --directory targets/t1105/ingress-download
   ```

## Trigger

3. In the browser with the EDR loaded, open **`http://localhost:8000/`** and click either download link:
   - **`invoice.hta`** — a standalone rarely-legitimate artifact.
   - **`holiday-photo.jpg.scr`** — an executable extension hidden behind a benign-looking `.jpg`.

## Expected result (the proof)

- The **download is cancelled and erased immediately** (prevention). Because the response calls
  `downloads.cancel` **then `downloads.erase`**, the artifact **does not remain** in the browser's downloads
  list — that's intended (the malicious file is kept out of the list). The detection record below is the
  evidence that it fired.
- The EDR records a detection: the toolbar **badge** increments and the **popup** shows
  *T1105 — Ingress Tool Transfer (malicious download)* with a reason such as
  *rarely-legitimate executable/script artifact (.hta)* or
  *double extension masks an executable (.jpg.scr)*.
- In the EDR service-worker console:
  ```
  [attack] ALERT { technique: 'T1105', meta: { reasons: ['rarely-legitimate executable/script artifact (.hta)', ...] } }
  [attack] PREVENTED — cancelled malicious download #<id> (.../invoice.hta)
  ```

## Control (no false positive)

4. Click the **`report.pdf`** control link — it downloads normally, with **no badge increment and no alert**.
   A plain `.exe`/`.msi` from `https` is likewise **not** flagged on its own (too common); only a
   double-extension mask or a suspicious origin escalates it.

## Cleanup

5. Stop the server (Ctrl-C). Delete any cancelled entries from the browser's downloads list if you like
   (nothing was written to disk — the download was cancelled before completion).

## Notes

- **Tune the artifact set** in `policy.riskyDownloadExtensions` (config): the standalone-risky default is
  `hta/scr/pif/vbs/vbe/jse/wsf/bat/cmd/ps1/com/jar`. `.exe`/`.msi` are intentionally excluded as standalone
  triggers (too common) — caught only via a double-extension mask or a suspicious origin.
- **Suspicious origins** (insecure HTTP, a bare-IP host, embedded `user:pw@` userinfo) add an aggravating
  reason but do **not** trigger on their own. Serving over `http://localhost` will add the insecure-HTTP reason.
- **Active response needs no `host_permissions`** — `downloads.cancel`/`.erase` operate on the download id.
