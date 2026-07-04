# Runbook — T1528 Illicit OAuth Consent (consent phishing)

**Proves:** the EDR detects a navigation to an **OAuth authorize** endpoint requesting **high-risk scopes**
(consent phishing — the way an adversary steals an access token without a password), **alerts**, and **closes
the tab**. Benign and local; **no new permission** (reuses `webNavigation`).

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as before.
2. Serve the target:
   ```bash
   python3 -m http.server 8528 --directory targets/t1528
   ```

## Trigger

3. Navigate to a mock consent URL (the path `/oauth/authorize` + high-risk `scope` is the signal):
   **`http://localhost:8528/oauth/authorize/?client_id=doc-sync-app&scope=offline_access%20mail.read%20files.read.all`**

## Expected result (the proof)

- The tab is **closed** before you can click "Accept".
- The toolbar **badge** increments; the **popup** shows *T1528 — Illicit OAuth Consent (steal access token)*
  with the reason (high-risk scopes: offline_access, mail.read, files.read.all).
- Service-worker console:
  ```
  [attack] ALERT { technique: 'T1528', meta: { riskyScopes: ['offline_access','mail.read','files.read.all'] } }
  [attack] PREVENTED — closed phishing tab <id>
  ```

## Notes

- **Tuning:** `policy.highRiskOAuthScopes` is the watch-list; `policy.approvedOAuthClients` allowlists known
  `client_id`s (when set, an unknown client adds a reason). Benign sign-ins (`openid profile email`) don't fire.
- Real IdP authorize endpoints (Microsoft `/oauth2/v2.0/authorize`, Google `/o/oauth2/v2/auth`, Okta, generic
  OIDC `/authorize`) are all recognized — but in production you'd allowlist your org's legitimate apps.
