# Runbook — T1539 Steal Web Session Cookie (weak flags)

**Proves:** the EDR detects a **session cookie set with weak security flags** (not Secure / not HttpOnly /
SameSite=None) — the shape a stealable session takes — **alerts**, and **removes** the cookie.

> **Permission gate.** Observing/removing cookies needs the `cookies` permission **and host access**. The
> shipped manifest has `cookies` but **no `host_permissions`** (our exemplary-minimal default), so T1539 is
> **dormant** until you grant host access. Granting broad cookie access is a deliberate operator/enterprise
> choice (ideally via managed policy) — this runbook does it temporarily for the demo.

## Setup

1. Build the EDR (`cd src && npm run build`).
2. **Grant host access for the demo:** edit **`apps/extension/dist/manifest.json`** and add a top-level key:
   ```json
   "host_permissions": ["http://localhost/*"],
   ```
   (Remove it after the demo to restore the minimal default.)
3. Load `apps/extension/dist/` unpacked (or reload it) in Chrome/Edge. The service-worker console should show
   3 signal sources (cookie monitoring now active).
4. Serve the benign target:
   ```bash
   python3 -m http.server 8055 --directory targets/t1539/weak-session
   ```

## Trigger

5. Visit **`http://localhost:8055/`** — the page sets `sessionid=…` without Secure/HttpOnly.

## Expected result (the proof)

- The toolbar **badge** increments; the **popup** shows *T1539 — Steal Web Session Cookie (weak flags)* with
  the reasons (not Secure · not HttpOnly).
- Service-worker console:
  ```
  [attack] ALERT { technique: 'T1539', meta: { cookieName: 'sessionid', reasons: [...] } }
  [attack] PREVENTED — removed weak session cookie "sessionid" for localhost
  ```
- Reload the page — the "Cookie set" line reads back empty/replaced: the EDR removed it.

## Cleanup

6. Remove the `host_permissions` line from `dist/manifest.json` and reload, to restore the minimal default.

## Notes

- **Tune** `policy.sessionCookiePatterns` (config) to your session-cookie names. Non-session cookies and
  properly-secured session cookies (Secure + HttpOnly) are never flagged.
- In production an enterprise grants host access via **managed policy** (`ATK-208`) — not a manual manifest edit.
