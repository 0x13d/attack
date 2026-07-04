# Runbook — T1550.004 Use of Web Session Cookie (persisted auth token)

**Proves:** the EDR detects a **session/auth-named cookie set persistent** (a far-future expiry instead of an
expire-on-close session cookie) — the shape of a stolen session being **pinned for reuse/replay** — **alerts**,
and **removes** the cookie. **Distinct from T1539**, which flags a session cookie's *weak flags* (theft
exposure); T1550.004 keys on the *persistence attribute* (reuse). Both can fire on one cookie.

> **Permission gate (same as T1539).** Observing/removing cookies needs `cookies` **+ host access**. The shipped
> manifest has `cookies` but **no `host_permissions`** (minimal default), so this is **dormant** until you grant
> host access — a deliberate operator/enterprise choice (ideally via managed policy). This runbook grants it
> temporarily for the demo.

## Setup

1. Build the EDR (`cd src && npm run build`).
2. **Grant host access for the demo:** edit `apps/extension/dist/manifest.json`, add a top-level key:
   ```json
   "host_permissions": ["http://localhost/*"],
   ```
   (Remove it afterward to restore the minimal default.)
3. Load/reload `apps/extension/dist/` unpacked. The service-worker console shows cookie monitoring active.
4. Serve the benign target:
   ```bash
   python3 -m http.server 8056 --directory targets/t1550_004/persisted-session
   ```

## Trigger

5. Visit **`http://localhost:8056/`** — the page sets `authtoken=…` with a far-future `expires`.

## Expected result (the proof)

- Badge increments; popup shows *T1550.004 — Use of Web Session Cookie* with the reason
  *session/auth cookie "authtoken" made persistent (expires 2099-12-31) on localhost — web-session-cookie reuse/persistence*.
- Service-worker console:
  ```
  [attack] ALERT { technique: 'T1550.004', meta: { cookieName: 'authtoken' } }
  [attack] PREVENTED — removed weak session cookie "authtoken" for localhost
  ```

## Control (no false positive)

6. A **true** session cookie (no expiry) — e.g. `document.cookie='authtoken=x; path=/'` — does **not** fire:
   T1550.004 requires the persistence attribute. A persistent **non**-session cookie (e.g. `theme`) is also ignored.

## Mix-and-match note (product nuance)

- T1539 (weak flags) and T1550.004 (persistence) **overlap by design**: a weak-flagged *and* persisted auth
  cookie fires both — the exposure signal and the reuse signal, two separately-tunable findings.

## Cleanup

7. Remove the `host_permissions` line from `dist/manifest.json` and reload. Stop the server.

## Notes

- **Tune** `policy.sessionCookiePatterns`. In production an enterprise grants host access via managed policy (`ATK-208`).
