# Runbook — T1656 Impersonation

**Proves:** the EDR detects a page **impersonating a brand login on a non-brand domain** — a protected brand
term plus an auth-context keyword (`login`/`verify`/…) in the host/path, while the registrable domain isn't the
brand — and **alerts**. **Complements T1566.002** (which inspects the *host* for lookalikes); T1656 inspects the
*path + auth context*, catching impersonation .002's exact-label logic misses. Detect + alert (heuristic). Benign + local.

The rule ignores `localhost`, so map a benign **`.test`** host to localhost.

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as in the [T1176 runbook](../t1176/RUNBOOK.md).
2. Map a stand-in host to localhost:
   ```bash
   echo "127.0.0.1 account-portal.test" | sudo tee -a /etc/hosts
   ```
3. Serve the benign pages:
   ```bash
   python3 -m http.server 8000 --directory targets/t1656/impersonation
   ```

## Trigger

4. Open **`http://account-portal.test:8000/`** and click **"Open the impersonation page"** →
   `http://account-portal.test:8000/paypal/login/verify.html` (brand `paypal` + auth `login`/`verify` on a
   non-brand domain).

## Expected result (the proof)

- Badge increments; popup shows *T1656 — Impersonation* with a reason like
  *brand "paypal" + auth context "login" on non-brand domain account-portal.test — login-page impersonation*.
- Console:
  ```
  [attack] ALERT { technique: 'T1656', meta: { matchedBrand: 'paypal', relationship: 'complements T1566.002 ...' } }
  ```

## Control (no false positive)

5. The **`/paypal/news.html`** link (brand term, **no** auth keyword) does **not** fire — T1656 requires brand +
   auth context. The legit brand's own domain (e.g. `accounts.paypal.com/login`) is never flagged.

## Mix-and-match note (product nuance)

- T1656 and T1566.002 are a **complementary pair**: a URL that is *both* a host-lookalike *and* has a brand+auth
  path fires both — the host signal and the path signal, two tunable findings. A client enables the mix that fits
  their phishing-exposure profile.

## Cleanup

6. Stop the server (Ctrl-C); remove the hosts line:
   ```bash
   sudo sed -i '' '/127.0.0.1 account-portal.test/d' /etc/hosts
   ```

## Notes

- **Tune** `policy.impersonationAuthKeywords` and `policy.protectedDomains` (brand terms are the brands' labels).
