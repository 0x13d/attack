# Runbook — T1566.001 Spearphishing Attachment

**Proves:** the EDR detects an **attachment-lure download** (macro-enabled office doc or a smuggling-prone web
format) **delivered from a phishing context** — a webmail / file-share referrer, or an otherwise suspicious
referring origin — and **alerts**. Keyed on the **delivery vector (the download's `referrer`)**, which separates
it from T1105 (raw transfer) and T1204.002 (lure containers). Benign plain-text artifact.

## Setup

1. Build + load the EDR (`apps/extension/dist/`) as in the [T1176 runbook](../t1176/RUNBOOK.md).
2. Serve the benign target over **plain HTTP** (this is what makes the download's referrer a suspicious
   delivery context):
   ```bash
   python3 -m http.server 8000 --directory targets/t1566_001/attachment
   ```

## Trigger

3. Open **`http://localhost:8000/`** and click **`invoice.docm`**. The download's referrer is
   `http://localhost:8000/` — an insecure-HTTP origin — so the delivery-context gate trips.

## Expected result (the proof)

- The EDR records a detection: badge increments, popup shows *T1566.001 — Spearphishing Attachment* with a
  reason like *spearphishing attachment: .docm delivered from an insecure-HTTP origin (localhost)*.
- Console:
  ```
  [attack] ALERT { technique: 'T1566.001', meta: { reasons: ['spearphishing attachment: .docm ...'] } }
  ```

## Control (no false positive — the delivery-context gate)

4. Download `invoice.docm` **directly** (paste `http://localhost:8000/invoice.docm` in the address bar and hit
   Enter) — with **no referrer** there's no delivery context, so it is **not** flagged as spearphishing. A plain
   `.pdf`/`.png` from the same page is likewise not this rule's lure class.

## Webmail-origin variant (optional, more realistic)

5. To demo the named-webmail path instead of insecure-HTTP, map a delivery origin from
   `policy.attachmentDeliveryOrigins` to localhost via your hosts file and serve there over HTTP, e.g.
   `127.0.0.1 wetransfer.com` → open `http://wetransfer.com:8000/`. (Don't map a host you actually use.)
   Remove the hosts line afterward.

## Cleanup

6. Stop the server (Ctrl-C); delete the downloaded file; remove any hosts-file line.

## Notes

- **Tune** `policy.attachmentExtensions` (macro office + html/svg) and `policy.attachmentDeliveryOrigins`
  (webmail / file-share hosts). A direct download with no referrer is intentionally **not** spearphishing.
