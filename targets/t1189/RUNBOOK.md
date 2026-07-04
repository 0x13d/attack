# Runbook — T1189 Drive-by Compromise

**Proves:** the EDR detects an **automatic client-redirect chain** (consecutive auto-redirects with no user
click, `policy.driveByRedirectThreshold`+ hops — default 3), **alerts**, and **closes the tab**. Keyed on
**redirect behavior**, distinct from the destination-keyed webNavigation rules. All pages are benign + local.

> Heuristic only — a real drive-by lands on an exploit kit; this demo just reproduces the *redirect-chain shape*.
> Deep exploit/payload analysis is deliberately out of scope (bucket D).

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as in the [T1176 runbook](../t1176/RUNBOOK.md).
2. Serve the benign chain:
   ```bash
   python3 -m http.server 8000 --directory targets/t1189/redirect-chain
   ```

## Trigger

3. Open **`http://localhost:8000/`** and click **"Start the redirect chain"**. The click loads `hop1`
   (user-initiated → resets the chain); `hop1 → hop2 → hop3 → landing` are then **automatic meta-refreshes**
   (3 consecutive client redirects).

## Expected result (the proof)

- On the 3rd auto-redirect the **tab closes**. Badge increments; popup shows *T1189 — Drive-by Compromise* with
  *automatic client-redirect chain of 3 hops with no user interaction — drive-by delivery pattern*.
- Console:
  ```
  [attack] ALERT { technique: 'T1189', meta: { redirectChainLength: 3 } }
  [attack] PREVENTED — closed phishing tab <id> (.../landing.html)
  ```
  (Note: `localhost` is fine here — T1189 keys on the *chain*, which has no host allowlist, unlike the
  lookalike/blocklist rules.)

## Control (no false positive)

4. Reload `hop3.html` directly (or navigate to `landing.html`) — a single navigation / one redirect does **not**
   reach the threshold. A user-initiated navigation always resets the per-tab chain counter to 0.

## Mix-and-match note (product nuance)

- A drive-by chain that lands on a blocklisted or lookalike host fires **T1189 and** T1204.001/T1566.002 — the
  behavior signal plus the destination signal, two tunable findings telling the fuller story of the chain.

## Cleanup

5. Stop the server (Ctrl-C).

## Notes

- **Tune** `policy.driveByRedirectThreshold` (default 3). The webNavigation signal counts consecutive
  `client_redirect` commits per tab; any non-redirect (user) navigation resets it.
