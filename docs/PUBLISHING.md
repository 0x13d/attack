# Publishing — Chrome Web Store + Edge Add-ons

> **Listing prep.** Submission is **maintainer-run**: no store API token or publisher key lives in this repo,
> ever. This file is the checklist + the copy/justifications a store reviewer (and an org admin) will want.

Market: **Chrome + Edge.** Both are Chromium; one MV3 build (`apps/extension/dist/`) targets both the
**Chrome Web Store** and **Microsoft Edge Add-ons**.

## Listing copy

- **Name:** 0x13d::att&ck — Browser EDR  _(brand/display name; the repo/dir + URL stay `attack`)_
- **Summary (≤132 chars):** Browser Endpoint Detection & Response. Matches browser events to MITRE ATT&CK
  signatures and responds — detect & disable rogue extensions.
- **Category:** Developer Tools / Productivity
- **Description (draft):**
  > 0x13d::att&ck is a Browser Endpoint Detection & Response extension. It watches browser events, matches them to
  > MITRE ATT&CK techniques, and responds — for example, detecting a rogue or sideloaded extension and
  > disabling it. It surfaces detections as a toolbar badge, desktop notifications, and an in-extension
  > alert table.
  >
  > Built to be trustworthy itself: a small, auditable Manifest V3 service worker with **zero runtime
  > dependencies**, a **least-privilege** permission set (no host permissions, no content scripts), and
  > **no telemetry**. Detection runs entirely locally — this edition makes **no network calls at all**, and
  > the build fails if one is introduced.

## Permissions justification (for the store privacy review)

Least privilege — each permission maps to a shipped capability:

| Permission | Why | Without it |
|---|---|---|
| `management` | Detect a rogue extension being installed/enabled (T1176.001) and disable it (`setEnabled`). | No rogue-extension detection or response. |
| `notifications` | Surface a detection as a desktop notification. | Detections only show in the badge/popup. |
| `storage` | Persist the local alert log + acknowledge state across the ephemeral MV3 worker; drives the badge. Also stores user-authored rules. | Alerts/badge wouldn't survive a worker restart; no user-authored rules. |
| `webNavigation` | Detect navigation to a lookalike/typosquat login domain (T1566.002), open-redirect abuse, drive-by redirect chains, and related techniques; close the tab where prevention applies. | No navigation-based detections. |
| `cookies` | Detect a session cookie set with weak flags (T1539) or made persistent (T1550.004) and remove it. **Dormant without host access** (granted by the operator/org — see below). | No session-cookie detection. |
| `downloads` | Detect a risky artifact or lure-container download (T1105, T1204.002, T1566.001) and cancel/erase it. | No download-based detections. |

- **No `host_permissions`.** No content scripts. No remote code (`eval`/`new Function`) — ever (authored
  rules are declarative data, see ADR-0002).
- Any new permission is a reviewed change with a documented rationale, and this table is updated. Permissions
  that would cross the zero-host-permission / no-egress line are out of scope for this edition (ADR-0005).

## Privacy / data handling (single purpose)

- **Single purpose:** detect and respond to malicious activity in the browser (a security tool).
- **Data collected:** none. Detection records (the technique, the offending extension's name/id, the reasons,
  a timestamp) are stored **locally** in `chrome.storage.local`.
- **Data transmitted:** none. This edition makes **no network calls** — no analytics, no telemetry, no third
  parties. The build self-check fails if network-egress code appears in the shipped worker.
- **Trust evidence:** `reports/trust/summary.md` — SBOM, `npm audit` 0, and a static network-call inventory
  showing zero egress.

## Assets checklist

- [x] Icons 16/48/128 (generated in build; ship a designed mark before public listing).
- [ ] Store icon 128×128 (designed) + promo tile(s) (440×280 / marquee).
- [ ] 1–5 screenshots (1280×800): the popup alert table, a detection notification, the badge, the demo site.
- [ ] A short demo capture of the T1176 flagship (optional but compelling).
- [x] Privacy policy text (the section above) + a public privacy URL (point at the project site, 0x13d.app).

## Managed deployment (orgs)

- **Chrome:** force-install / allowlist via Chrome Enterprise policy (`ExtensionInstallForcelist`); managed
  configuration delivers org policy to the extension via `chrome.storage.managed`.
- **Edge:** Microsoft Edge for Business — `ExtensionInstallForcelist` equivalent; same managed config.
- In the **"Settings controlled by your org"** managed-policy mode, the org controls the ruleset and end
  users can't disable protected settings.

## Submission steps (maintainer-run)

1. `npm run build --workspace apps/extension` → zip `apps/extension/dist/`.
2. Chrome Web Store Developer Dashboard → upload zip → fill listing from this file → submit for review.
3. Partner Center (Edge Add-ons) → upload the same zip → submit.
4. Record the listing URLs back here.

No automated publish; the maintainer submits by hand from a machine holding the store credentials. No token
in the repo.
