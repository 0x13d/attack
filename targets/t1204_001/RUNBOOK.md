# Runbook — T1204.001 User Execution: Malicious Link

**Proves:** the EDR detects a navigation to a destination on the **threat blocklist** (operator/feed-supplied
known-bad IOCs), **alerts**, and **closes the tab** (active prevention). Keyed on the **destination IOC** — a
distinct signal from T1566.002 (brand-lookalike heuristic), T1566.003 (open-redirect), and T1189 (redirect chain).

The default `policy.threatBlocklist` ships sample reserved-TLD IOCs (`known-bad.test`, `malware-delivery.example`)
— operators replace it with their feed. The rule ignores `localhost`, so map the sample IOC to localhost.

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as in the [T1176 runbook](../t1176/RUNBOOK.md).
2. Map the sample IOC (and a benign control host) to localhost:
   ```bash
   echo "127.0.0.1 known-bad.test safe-site.test" | sudo tee -a /etc/hosts
   ```
3. Serve the benign landing page:
   ```bash
   python3 -m http.server 8000 --directory targets/t1204_001/blocklist-link
   ```

## Trigger

4. Open **`http://safe-site.test:8000/`** (a non-blocklisted host, so the page itself doesn't trip the rule) and
   click **"Follow the malicious link"** → it navigates to `http://known-bad.test:8000/landing`.

## Expected result (the proof)

- The **tab closes** (prevention). Badge increments; popup shows *T1204.001 — User Execution: Malicious Link*
  with the reason *navigation to a blocklisted destination known-bad.test (threat-IOC match: known-bad.test)*.
- Console:
  ```
  [attack] ALERT { technique: 'T1204.001', meta: { matchedIndicator: 'known-bad.test' } }
  [attack] PREVENTED — closed phishing tab <id> (http://known-bad.test:8000/landing)
  ```

## Control (no false positive)

5. Navigating to **`safe-site.test`** (not on the blocklist) does **not** fire — only blocklisted hosts/subdomains.

## Mix-and-match note (product nuance)

- T1204.001 (IOC/feed) and T1566.002 (lookalike heuristic) **overlap by design**: a known-bad host that is also a
  brand lookalike fires both — two separately-tunable findings. A client points `threatBlocklist` at their own
  IOC feed and chooses which of the webNavigation techniques to enable for their environment.

## Cleanup

6. Stop the server (Ctrl-C); remove the hosts line:
   ```bash
   sudo sed -i '' '/127.0.0.1 known-bad.test safe-site.test/d' /etc/hosts
   ```

## Notes

- **Tune** `policy.threatBlocklist` — host / registrable-domain IOCs; a match is the host itself or any subdomain.
