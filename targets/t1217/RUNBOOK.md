# Runbook — T1217 Browser Information Discovery

**Proves:** the EDR detects a **non-approved extension holding browser-data-discovery permissions**
(`bookmarks`/`history`/`topSites`) — positioned to enumerate them for recon — and **alerts**. Detect + alert
(legit extensions hold these too; operators allowlist via `policy.approvedExtensionIds`). Reuses the `management`
signal — **no new permission**.

> **Signal note (honest framing).** The `bookmarks`/`history` APIs let an extension *read* those stores but emit
> **no event when another actor reads them**, so a scrape isn't directly observable. T1217 here detects the
> **capability** (the permission grant), not the act. Deeper detection would need a content-script (Bucket C).

> **Overlap (by design).** Loaded **unpacked**, this target is `installType: development` → it *also* trips
> **T1176.001** (sideload) which disables it. That's the intended mix-and-match overlap: one extension, two
> findings — T1176.001 (rogue install) **and** T1217 (recon capability). T1217's reason names the recon perms.

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as in the [T1176 runbook](../t1176/RUNBOOK.md). (`management` is already
   granted; no host access needed.)

## Trigger

2. **Load unpacked** the demo target — select the `recon-extension/` folder (the one with `manifest.json`):
   `targets/t1217/recon-extension/`

## Expected result (the proof)

- Badge increments; the popup shows **T1217 — Browser Information Discovery** with the reason
  *extension "Bookmark Helper (attack T1217 demo target)" holds browser-data-discovery permissions
  (bookmarks, history, topSites) — positioned to enumerate bookmarks/history (recon)* —
  **and** a T1176.001 detection (sideload), which disables the extension.
- EDR service-worker console:
  ```
  [attack] ALERT { technique: 'T1217', meta: { reconPermissions: ['bookmarks','history','topSites'] } }
  [attack] ALERT { technique: 'T1176.001', ... }
  [attack] PREVENTED — disabled rogue extension "Bookmark Helper (attack T1217 demo target)" (<id>)
  ```

## Control (no false positive)

3. Add the extension's id to `policy.approvedExtensionIds` (rebuild) — T1217 (and T1176.001) then ignore it. A
   benign extension with **no** recon permissions never trips T1217.

## Cleanup

4. Remove the demo target (**Remove** on its card).

## Notes

- **Tune** `policy.reconPermissions` (default `bookmarks`/`history`/`topSites`) and allowlist legit extensions
  via `policy.approvedExtensionIds`. Detect-only by design — a recon *permission* isn't proof of malice.
