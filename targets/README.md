# targets/ — benign, reproducible demo targets

Each technique in the slate ships a **safe, local target** + a **runbook** so anyone can reproduce the
detection (and prevention) without real malware. Targets do nothing harmful — they only exhibit the *shape*
of the attack so the corresponding rule fires.

| Technique | Folder | Proves |
|---|---|---|
| **T1176.001** Browser Extensions | [`t1176/`](t1176/) | rogue extension install/enable → alert + auto-disable |
| **T1566.002** Spearphishing Link | [`t1566/`](t1566/) | navigation to a lookalike login domain → alert + close tab |
| **T1539** Steal Web Session Cookie | [`t1539/`](t1539/) | session cookie set with weak flags → alert + remove (host-access gated) |
| **T1185** Browser Session Hijacking | [`t1185/`](t1185/) | **cross-tab** reverse tabnabbing (opener-tab rewrite) → alert + close tab |
| **T1528** Illicit OAuth Consent | [`t1528/`](t1528/) | navigation to an OAuth authorize endpoint with high-risk scopes → alert + close tab |
| **T1105** Ingress Tool Transfer | [`t1105/`](t1105/) | risky artifact download (`.hta` / double-extension) → alert + cancel download |
| **T1204.002** User Execution: Malicious File | [`t1204_002/`](t1204_002/) | lure-container download (`.iso`/`.lnk`/`.msi`) → alert (detect-only; disjoint from T1105) |
| **T1566.001** Spearphishing Attachment | [`t1566_001/`](t1566_001/) | attachment lure from a phishing-delivery referrer → alert |
| **T1176** Browser Extensions (tamper) | [`t1176/`](t1176/#re-enable--t1176-tamper-a-second-distinct-technique) | re-enable of an EDR-disabled extension → alert + re-disable (see the t1176 runbook's tamper section) |
| **T1566.003** Spearphishing via Service | [`t1566_003/`](t1566_003/) | navigation through a trusted-service open-redirect (off-domain) → alert |
| **T1204.001** User Execution: Malicious Link | [`t1204_001/`](t1204_001/) | navigation to a threat-blocklist (known-bad IOC) destination → alert + close tab |
| **T1189** Drive-by Compromise | [`t1189/`](t1189/) | automatic client-redirect chain (≥ threshold hops) → alert + close tab |
| **T1656** Impersonation | [`t1656/`](t1656/) | brand term + auth keyword on a non-brand domain (path/host) → alert |
| **T1550.004** Use of Web Session Cookie | [`t1550_004/`](t1550_004/) | session/auth cookie made persistent (reuse) → alert + remove (host-access gated) |
| **T1606.002** Forge Web Credentials: SAML | [`t1606_002/`](t1606_002/) | SAML-token flow to a non-allowlisted host → alert |
| **T1217** Browser Information Discovery | [`t1217/`](t1217/) | extension holding recon perms (bookmarks/history/topSites) → alert (also trips T1176.001) |

The commercial edition's techniques (network- and page-level observation) have their own targets + runbooks
outside this repository.
