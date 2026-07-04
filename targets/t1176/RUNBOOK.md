# Runbook — T1176.001 Browser Extensions (flagship demo)

**Proves:** the `attack` EDR detects a rogue/sideloaded browser extension being installed or enabled, **alerts**
(desktop notification + structured console record), and **actively prevents** it by disabling the extension
(`management.setEnabled(id, false)`).

**Everything here is benign and local.** The "evil" target ([`evil-extension/`](evil-extension/)) does nothing
harmful — it only *requests* the permissions a rogue extension would, so the rule trips. Safe to load and delete.

## Setup

1. Build the EDR:
   ```bash
   cd src
   npm install && npm run build      # → apps/extension/dist/
   ```
2. Load the EDR unpacked. **"Load unpacked" must point at the folder that directly contains `manifest.json`** —
   for the EDR that is **`apps/extension/dist/`** (the built output), not `src/`:
   - **Chrome:** `chrome://extensions/` → enable **Developer mode** → **Load unpacked** → select
     `apps/extension/dist/`.
   - **Edge:** `edge://extensions/` → **Developer mode** → **Load unpacked** → select the same `apps/extension/dist/`.
3. Open the EDR's service-worker console: on `chrome://extensions/`, find **attack — Browser EDR** →
   **Inspect views: service worker**. You'll see `[attack] Browser EDR engine started — 1 rule(s), 1 signal source(s)`.

## Trigger (the detection + prevention)

4. **Load unpacked** the demo target. Select the **`evil-extension/` subfolder** (the one with `manifest.json`),
   **not** the parent `t1176/` folder (that holds this runbook):
   `targets/t1176/evil-extension/`

## Expected result (the proof)

Three independent signals — so the demo lands even if an endpoint has OS notifications disabled:

1. **Toolbar badge** — the attack icon shows a red **`1`** (count of unacknowledged detections).
2. **Click the attack icon → popup** — a table of detections; this one in **red** (unacknowledged) with the
   technique (T1176.001), the extension name, and the reasons. **Acknowledge** clears the red + decrements the
   badge; **Acknowledge all** / **Clear** also work.
3. **Desktop notification** *"attack — T1176.001 detected"* (now that a real icon ships — if you still don't
   see it, your OS/Chrome notification settings are suppressing it; the badge + popup are the reliable proof).

Plus the prevention + telemetry:

- On `chrome://extensions/`, the **target is toggled OFF** (disabled) — the EDR prevented it.
- In the EDR service-worker console:
  ```
  [attack] ALERT { kind: 'attack.alert', technique: 'T1176.001', ... meta: { reasons: [...] } }
  [attack] PREVENTED — disabled rogue extension "Totally Not Evil (attack T1176 demo target)" (<id>)
  ```

## Re-enable → T1176 tamper (a *second*, distinct technique)

5. Toggle the target back **on** in `chrome://extensions/`. Because the EDR previously disabled it, this
   re-enable is caught as **T1176 — Browser Extensions (tamper / persistence)**, *not* a fresh T1176.001 hit
   (T1176.001 **defers** this case, so the two never double-fire on one event). The EDR alerts and
   **re-disables** it:
   ```
   [attack] ALERT { technique: 'T1176', meta: { reasons: ['an extension the EDR disabled was re-enabled — persistence / EDR-evasion'] } }
   [attack] PREVENTED — disabled rogue extension "Totally Not Evil (attack T1176 demo target)" (<id>)
   ```
   This models an attacker (or another extension) reviving a killed rogue to keep persistence. The set of
   EDR-disabled ids is mirrored to `chrome.storage.local`, so the tamper detection survives the ephemeral
   service worker.

## Cleanup

6. Remove the demo target (**Remove** on its card). Optionally remove the EDR too.

## Notes

- **No network egress in this demo.** The alert ships to a SIEM/LME sink only if an operator sets
  `policy.sinkUrl` (and adds that origin to `host_permissions`). By default it's null → notification + console only.
- **Tuning:** add an extension's ID to `policy.approvedExtensionIds` to allowlist it; the rule then ignores it.
  Managed (`admin`) and Web Store (`normal`) installs are not flagged on install-source alone.
