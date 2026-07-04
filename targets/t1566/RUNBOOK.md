# Runbook — T1566.002 Spearphishing Link (lookalike login)

**Proves:** the EDR detects a top-frame navigation to a **lookalike / typosquat** of a protected login domain,
**alerts**, and **closes the tab** (active prevention). Everything is benign and local.

Because the detection is domain-based, the repro maps a lookalike hostname to `127.0.0.1` via your hosts file
and serves a harmless local page there. The page collects nothing.

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as in the [T1176 runbook](../t1176/RUNBOOK.md). The build now also runs
   the `webNavigation` rule.
2. Map a lookalike hostname to localhost (homoglyph of `paypal.com`):
   ```bash
   echo "127.0.0.1 paypa1.com" | sudo tee -a /etc/hosts
   ```
3. Serve the benign page on that host:
   ```bash
   python3 -m http.server 8000 --directory targets/t1566/lookalike-login
   ```

## Trigger

4. In the browser with the EDR loaded, navigate to **`http://paypa1.com:8000/`**.

## Expected result (the proof)

- The **tab closes immediately** (prevention) — you may only glimpse the page.
- The EDR records a detection: the toolbar **badge** increments and the **popup** shows
  *T1566.002 — Spearphishing Link (lookalike login)* with the reason
  *homoglyph lookalike of paypal.com (paypa1.com)*.
- In the EDR service-worker console:
  ```
  [attack] ALERT { technique: 'T1566.002', meta: { reasons: ['homoglyph lookalike of paypal.com ...'] } }
  [attack] PREVENTED — closed phishing tab <id> (http://paypa1.com:8000/)
  ```

Other lookalikes that also trip it (try via more hosts aliases): a **typosquat** (`paypall.com`), or a
**subdomain impersonation** (`github.attacker.test` → "github" used as a subdomain).

## Cleanup

5. Remove the hosts line:
   ```bash
   sudo sed -i '' '/127.0.0.1 paypa1.com/d' /etc/hosts
   ```
   Stop the server (Ctrl-C).

## Notes

- **Tune the protected brands** in `policy.protectedDomains` (config). Legit brand domains + their subdomains
  (`signin.paypal.com`) are never flagged.
- **Limitation:** the registrable-domain check is a "last two labels" approximation (no public-suffix list),
  so multi-part TLDs (`co.uk`) aren't perfectly handled yet — a documented follow-up.
