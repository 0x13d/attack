# Runbook — T1606.002 Forge Web Credentials: SAML Tokens

**Proves:** the EDR detects a **SAML-token flow** — a navigation carrying a `SAMLResponse`/`SAMLRequest`/`SAMLart`
param or an ACS/SSO path — to a host **not** in the operator's `samlTrustedHosts` allowlist, and **alerts**.
Visibility heuristic (detect + alert): the browser can't validate the assertion, so it surfaces SAML flows to
unexpected endpoints for SOC scrutiny (forged / golden-SAML). Distinct from the phishing-nav rules. Benign + local.

The rule ignores `localhost`; map a benign `.test` host so the navigated URL has a normal-looking SP domain.

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as in the [T1176 runbook](../t1176/RUNBOOK.md). (No host_permissions needed
   — `webNavigation` sees the URL.)
2. Map a stand-in service-provider host to localhost:
   ```bash
   echo "127.0.0.1 sp.unknown.test" | sudo tee -a /etc/hosts
   ```
3. Serve the benign target:
   ```bash
   python3 -m http.server 8000 --directory targets/t1606_002/saml-flow
   ```

## Trigger

4. Open **`http://sp.unknown.test:8000/`** and click either link — a `?SAMLResponse=…` navigation, or the
   `/saml2/acs` path. The host isn't allowlisted, so the SAML flow trips the rule.

## Expected result (the proof)

- Badge increments; popup shows *T1606.002 — Forge Web Credentials: SAML Tokens* with a reason like
  *SAML-token flow to non-allowlisted host sp.unknown.test (SAML assertion param "SAMLResponse") — scrutinize
  for forged / golden-SAML assertion*.
- Console:
  ```
  [attack] ALERT { technique: 'T1606.002', meta: { url: '…/acs.html?SAMLResponse=…' } }
  ```

## Control (no false positive)

5. Add the host to the allowlist — `policy.samlTrustedHosts: ['unknown.test']` (rebuild) — and the same flow is
   **not** flagged (expected IdP/SP). A navigation with no SAML param and no ACS/SSO path never fires.

## Mix-and-match note (product nuance)

- This is the one webNavigation technique that's an **SSO/credential signal** rather than phishing. A client
  enables it where SAML matters and allowlists their IdP/SP; in a non-SAML shop they leave it off. Pure
  mix-and-match.

## Cleanup

6. Stop the server (Ctrl-C); remove the hosts line:
   ```bash
   sudo sed -i '' '/127.0.0.1 sp.unknown.test/d' /etc/hosts
   ```

## Notes

- **Tune** `policy.samlTrustedHosts` (your IdP/SP). Empty (default) flags all SAML flows for visibility.
- POST-binding assertions aren't in the URL, so this catches redirect-binding flows + ACS-path navigations
  (a documented browser-observability limit; deeper validation is server-side / out of scope).
