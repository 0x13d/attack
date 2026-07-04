# MITRE ATT&CK coverage — the community slate

> **What this is.** The defensible enumeration of MITRE ATT&CK (enterprise) techniques covered by this
> **browser-native MV3 extension** using **declarative rules** (field · operator · value, AND/OR) over its
> **signal sources** — with **zero host permissions and no network egress**. Source-of-truth for the count is
> the registered rule set ([`rules/src/rules/index.ts`](../rules/src/rules/index.ts)) + the manifest, not
> marketing copy.

## Headline

| Bucket | Count | What it means |
|---|---:|---|
| **A+B · Shipped (this repository)** | **16** | A registered rule + signal source detects it today (some prevent actively). All 16 reached with **zero host permissions and no network egress** — build-enforced. |
| **C · Commercial edition (not in this repository)** | 9 | Requires network- or page-level observation permissions that cross this edition's trust line. |
| **D · Out of scope (heavy / not browser-observable)** | — | Host/network-layer, or needs **WASM-class in-page binary/ML analysis**. The deliberate not-doing-it line. |

**The number: "16 browser ATT&CK techniques, zero host permissions, no egress, fully open and auditable."**
The milestone claim — *"most browser ATT&CK coverage, smallest auditable surface"* — holds because every one
of the 16 ships on the permission set below and nothing more.

## Signal sources (the columns)

| Signal source | Permission | Status |
|---|---|---|
| `cookie` | `cookies` (+ `host_permissions` for live read — operator-granted) | ✅ wired |
| `management` | `management` | ✅ wired |
| `webNavigation` | `webNavigation` | ✅ wired |
| `downloads` | `downloads` | ✅ wired |
| `tabs` / `windows` | none / `tabs` for url+title | ⚪ available (in-pattern) |
| `bookmarks` / `history` | `bookmarks` / `history` | ⚪ available (in-pattern) |
| **content-script** | `host_permissions` + (e.g.) `clipboardRead`, `scripting` | 🚫 outside this edition's trust line — scope reserved in the schema, unused here |
| **webRequest / declarativeNetRequest** | `webRequest` / `declarativeNetRequest` + host | 🚫 outside this edition's trust line — scope reserved in the schema, unused here |

## The 16 shipped techniques

| Technique | Tactic | Signal | Lever |
|---|---|---|---|
| **T1176.001** Browser Extensions | Persistence | `management` | **Prevent** — `management.setEnabled(false)` |
| **T1566.002** Spearphishing Link (lookalike login) | Initial Access | `webNavigation` | **Prevent** — `tabs.remove`/redirect |
| **T1528** Steal Application Access Token (OAuth consent) | Credential Access | `webNavigation` | **Prevent** — block tab |
| **T1185** Browser Session Hijacking (reverse tabnabbing) | Collection | `webNavigation` (cross-tab) | Detect + alert |
| **T1539** Steal Web Session Cookie | Credential Access | `cookie` | **Prevent** — `cookies.remove` *(rule ships; live monitoring **dormant** until operator grants `host_permissions`)* |
| **T1105** Ingress Tool Transfer (malicious download) | Command & Control | `downloads` | **Prevent** — `downloads.cancel`/`.erase` *(shipped v0.8.0)* |
| **T1204.002** User Execution: Malicious File | Execution | `downloads` | Detect + alert *(lure containers/shortcuts/installers — disjoint from T1105; shipped v0.10.0)* |
| **T1566.001** Spearphishing Attachment | Initial Access | `downloads` | Detect + alert *(attachment lure from a phishing-delivery referrer; shipped v0.10.0)* |
| **T1176** Browser Extensions — tamper / re-enable | Persistence | `management` | **Prevent** — re-disable *(re-enable of an EDR-disabled extension; .001 defers; shipped v0.10.0)* |
| **T1566.003** Spearphishing via Service | Initial Access | `webNavigation` | Detect + alert *(open-redirect off-domain via a trusted service; distinct from T1566.002 lookalike; shipped v0.11.0)* |
| **T1204.001** User Execution: Malicious Link | Execution | `webNavigation` | **Prevent** — close tab *(navigation to a threat-blocklist IOC; distinct from the .002 heuristic; shipped v0.11.0)* |
| **T1189** Drive-by Compromise | Initial Access | `webNavigation` | **Prevent** — close tab *(automatic client-redirect chain ≥ threshold; keyed on behavior not destination; shipped v0.11.0)* |
| **T1656** Impersonation | Initial Access | `webNavigation` | Detect + alert *(brand term + auth keyword on a non-brand domain; complements T1566.002 host-lookalike; shipped v0.11.0)* |
| **T1550.004** Use of Web Session Cookie | Defense Evasion | `cookie` | **Prevent** — `cookies.remove` *(session/auth cookie made persistent = reuse; distinct from T1539 flags; dormant w/o host access; shipped v0.12.0)* |
| **T1606.002** Forge Web Credentials: SAML | Credential Access | `webNavigation` | Detect + alert *(SAML-token flow to a non-allowlisted host; visibility heuristic; shipped v0.12.0)* |
| **T1217** Browser Information Discovery | Discovery | `management` | Detect + alert *(non-approved extension holding recon perms bookmarks/history/topSites; distinct from T1176.001; shipped v0.12.0)* |

> Reconciliation note: the shipped count is keyed to the **rules registered** in
> [`rules/src/rules/index.ts`](../rules/src/rules/index.ts). A count-guard test fails the build if the
> documented slate drifts from the engine. *(Historical note: T1217 was planned as a `bookmarks`/`history`
> signal, but those APIs can't observe another actor reading those stores; it shipped instead as a
> `management`-based recon-permission detection.)*

Overlap between rules is deliberate and documented: where two techniques observe adjacent behavior (e.g.
T1566.002 lookalike-host vs T1656 brand-term impersonation, or T1539 vs T1550.004 cookie flags), each rule
states its relationship in the table above — operators mix and match rather than getting one opaque blob.

## The 9 techniques not in this repository (commercial edition)

Nine further browser-observable techniques — **T1567/.002** (Exfiltration Over Web Service, incl. GenAI/DLP),
**T1071.001** (Web Protocols C2), **T1102** (Web Service C2), **T1557** (Adversary-in-the-Middle),
**T1204+T1059** ("ClickFix" paste-and-run), **T1056.003** (Web Portal Capture), **T1111** (MFA Interception),
**T1059.007** (Malicious in-page JavaScript), and **T1020** (Automated Exfiltration) — require network-level
(`webRequest`) or page-level (content-script + `host_permissions`) observation. Those permissions cross the
community edition's **zero-host-permission, no-egress trust line**, so these techniques ship in a separate
**commercial edition** and are not included in this repository. The `webRequest` and `content` scopes remain
reserved in the rule schema (see [ADR-0005](adr/0005-community-vs-enterprise-tiering.md)).

## Bucket D — Out of scope (the deliberate line)

Not enumerated technique-by-technique — characterized as classes, because the *point* is the boundary:

- **Heavy in-page binary/ML analysis (WASM-class):** download/content malware **scanning**, JS
  **deobfuscation** (T1140) / unpacking obfuscated payloads (T1027), in-browser sandboxing. We flag
  heuristically (URL, extension, double-extension, origin) and surface the alert; we do not run a scanner in
  the page.
- **Network-layer / encrypted-channel inspection:** packet/TLS analysis, T1573 Encrypted Channel, T1090 Proxy.
- **Host-level techniques:** the majority of Privilege Escalation, most Defense Evasion, process/memory/file-system
  Execution & Impact (T1485 Data Destruction, etc.) — a host EDR's job, not the browser's.

## Honest framing

- **"16 ATT&CK techniques in the browser, on a fully-open zero-dep engine — zero host permissions, no egress."**
- The split is the point: this edition covers the **browser-observable** slice reachable with **declarative,
  auditable, no-`eval`** rules and the smallest possible permission surface. The large bucket D — heavy WASM
  in-page analysis — is **deliberately not shipped**: *most coverage, least surface, 100% auditable.*
- Every technique claimed must trace to a row here (signal source + lever named) — no marketing inflation.
  Every shipped technique is a real rule with a distinct detection, a `targets/` runbook, and tests — no stubs.
