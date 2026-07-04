# Runbook — T1204.002 User Execution: Malicious File

**Proves:** the EDR detects a **user-execution lure** download — a container / shortcut / installer
(`.iso`/`.img`/`.vhd`, `.lnk`, `.msi`, `.chm`) the victim is socially-engineered into double-clicking to run —
and **alerts**. This is **detect + alert only**: the *execution* is a user action outside the browser we can't
observe or stop (T1105 owns the transfer-stage cancel). All artifacts are benign plain text. Distinct from
T1105 by a **disjoint file class** — the two never fire on one artifact.

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as in the [T1176 runbook](../t1176/RUNBOOK.md). The `downloads` rule is
   registered (shipped since v0.8.0).
2. Serve the benign target:
   ```bash
   python3 -m http.server 8000 --directory targets/t1204_002/lure-download
   ```

## Trigger

3. Open **`http://localhost:8000/`** and click **`invoice.iso`** (or `shortcut.lnk`).

## Expected result (the proof)

- The EDR records a detection: the toolbar **badge** increments and the **popup** shows
  *T1204.002 — User Execution: Malicious File* with a reason like
  *user-execution lure: .iso (container/shortcut/installer — mounts/opens to run, bypassing mark-of-the-web)*.
- The download **completes** (it is **not** cancelled — detect + alert). In the EDR service-worker console:
  ```
  [attack] ALERT { technique: 'T1204.002', meta: { reasons: ['user-execution lure: .iso ...'] } }
  ```

## Control (no false positive)

4. The **`report.pdf`** link downloads with **no alert**. A plain `.exe`/`.hta` is **not** flagged here either —
   `.exe`/`.hta` belong to T1105's class (script/quasi-exe + double-extension), which is **disjoint** from this
   rule's lure-container set. A single artifact never trips both rules.

## Cleanup

5. Stop the server (Ctrl-C); delete the downloaded demo files.

## Notes

- **Tune** the lure set in `policy.userExecutionLureExtensions`
  (`lnk`/`iso`/`img`/`vhd`/`vhdx`/`msi`/`msix`/`appx`/`chm`).
