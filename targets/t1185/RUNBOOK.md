# Runbook — T1185 Browser Session Hijacking (reverse tabnabbing) · cross-tab

**Proves:** the EDR detects a **cross-tab** attack — an attacker tab using `window.opener` to **rewrite the
trusted opener tab** to a different origin (reverse tabnabbing) — **alerts**, and **closes** the hijacked tab.
All benign and local. No new permission (uses `webNavigation`, already granted).

The two origins are `localhost` and `127.0.0.1` (same server, different host = different origin), so **one
static server** is enough.

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as before.
2. Serve the target dir:
   ```bash
   python3 -m http.server 8001 --directory targets/t1185
   ```

## Trigger

3. Open the **opener** tab at **`http://localhost:8001/opener.html`**.
4. Click **"Open the (benign) attacker tab →"** (opens `http://127.0.0.1:8001/attacker.html` with
   `target=_blank`, no `rel=noopener`). The attacker tab immediately rewrites the opener via
   `window.opener.location` to `http://127.0.0.1:8001/phish.html` — a **different origin** than the opener's.

## Expected result (the proof)

- The opener tab (the one at `localhost:8001`) is **closed** by the EDR before it lands on the phishing page.
- The toolbar **badge** increments; the **popup** shows *T1185 — Browser Session Hijacking (reverse
  tabnabbing)* with the reason (opener tab rewritten `http://localhost:8001` → `http://127.0.0.1:8001`).
- Service-worker console:
  ```
  [attack] ALERT { technique: 'T1185', meta: { reasons: ['opener tab rewritten ... via client redirect'] } }
  [attack] PREVENTED — closed phishing tab <id>
  ```

## Notes

- **Why cross-tab:** the detection only fires for a tab that **opened another** (tracked via
  `onCreatedNavigationTarget`) and is then **script-redirected** (client redirect) to a **new origin** — a
  relationship that only exists *across* tabs. Same heuristic powers the cross-tab **Sankey** on the brochure.
