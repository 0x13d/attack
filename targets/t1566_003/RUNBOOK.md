# Runbook — T1566.003 Spearphishing via Service

**Proves:** the EDR detects a navigation **laundered through a trusted service's open-redirect** — a URL carrying
a redirect parameter (`?url=`, `?next=`, …) that points **off-domain** — and **alerts**. Keyed on the *delivery
mechanism* (the open-redirect), which is **distinct from T1566.002** (brand-lookalike domain). Detect + alert
(benign open-redirects exist, so no auto-block). All local + benign.

Because the rule ignores `localhost`, map a benign **`.test`** host (reserved, never real) to localhost so the
navigated URL has a normal-looking service domain.

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as in the [T1176 runbook](../t1176/RUNBOOK.md).
2. Map a stand-in service host to localhost:
   ```bash
   echo "127.0.0.1 trusted-service.test" | sudo tee -a /etc/hosts
   ```
3. Serve the benign page on it:
   ```bash
   python3 -m http.server 8000 --directory targets/t1566_003/redirect-service
   ```

## Trigger

4. Open **`http://trusted-service.test:8000/`** and click **"Follow the service link"** — it navigates to
   `http://trusted-service.test:8000/?url=https://account-verify.example/login` (a redirect param pointing to a
   different registrable domain).

## Expected result (the proof)

- Badge increments; popup shows *T1566.003 — Spearphishing via Service* with a reason like
  *open-redirect via trusted-service.test: "url=" points off-domain to account-verify.example*.
- Console:
  ```
  [attack] ALERT { technique: 'T1566.003', meta: { redirectTo: 'account-verify.example', relationship: 'distinct from T1566.002 ...' } }
  ```

## Control (no false positive)

5. The **`?next=/dashboard`** (relative) and **`?q=hello`** (no redirect param) links do **not** fire — only a
   redirect param resolving to a **different registrable domain** trips it. A same-site `?next=` is benign.

## Mix-and-match note (product nuance)

- This is one of several phishing-delivery techniques on `webNavigation` (T1566.002 lookalike, T1204.001
  malicious link, T1189 drive-by). They **overlap by design** — a client enables the combination that fits their
  environment. An open-redirect *to* a lookalike domain would fire both T1566.003 **and** T1566.002: two real,
  separately-tunable findings.

## Cleanup

6. Stop the server (Ctrl-C); remove the hosts line:
   ```bash
   sudo sed -i '' '/127.0.0.1 trusted-service.test/d' /etc/hosts
   ```

## Notes

- **Tune** `policy.openRedirectParams` (the redirect-param names). Protocol-relative (`//evil`) and base64-wrapped
  redirect values are a documented v1 limitation (only absolute off-domain http(s) values are matched).
