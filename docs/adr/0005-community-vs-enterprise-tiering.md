---
status: "accepted"
date: 2026-06-17
decision-makers: maintainer, security
consulted: architect
informed: team
---

# The community edition draws the line at zero host permissions and no network egress

## Context and Problem Statement

The 16-technique slate shipped with the defining differentiator **zero host permissions and no network
egress** ("most browser ATT&CK coverage, smallest auditable surface"). The remaining browser-observable
techniques (nine more — DLP/GenAI exfiltration, web-protocol C2, AiTM, ClickFix, credential-form capture,
MFA interception, in-page script analysis, automated exfiltration) **all require crossing that line**:
a content-script (page-content access) and/or `webRequest` + `host_permissions` (network observation).
They are still declarative, no-`eval`, auditable rules — this is not WASM-class in-page scanning — but the
permissions they need are exactly the ones this edition promises never to hold. Do we add them here?

## Decision Drivers

* **The trust posture IS the product.** "Zero host permissions, no telemetry, no egress" is only worth
  anything if it is *verifiable* — anyone can read the manifest, audit the zero-dependency engine, and confirm
  there is no network call. Adding host access or egress for *any* technique invalidates that claim for
  *every* user of this edition.
* **Honest framing.** Coverage claims must trace to real rules on the declared permission set — the count must
  not be inflated by techniques whose permissions the shipped manifest doesn't hold.

## Decision Outcome

**The open-source community edition — this repository — ships the 16 techniques achievable with zero host
permissions and no network egress, and nothing that would break that guarantee.**

- **16 techniques**, all detected (and where an MV3 lever exists, prevented) on the minimal permission set:
  `management`, `notifications`, `storage`, `webNavigation`, `cookies`, `downloads`. **No `host_permissions`,
  no content scripts, no `webRequest`.**
- **No network egress** — detect + local alert (badge / popup / notification) only. There is no telemetry and
  no remote sink of any kind.
- **The guarantee is build-enforced**: the build self-check fails if host permissions appear in the manifest
  or network-egress code (`fetch()` and friends) appears in the shipped worker. The claim is checked by the
  toolchain, not asserted by documentation.
- Techniques that require `webRequest`, content-script injection, or host access are **excluded from this
  repository**. They exist in a separate **commercial edition**; the `webRequest` and `content` scopes remain
  **reserved in the rule schema** so the schema stays a single coherent contract.

## Consequences

- Good — the trust story is unconditional: every user of this edition gets the same verifiable posture; there
  is no configuration, flag, or policy under which this build gains host access or makes a network call.
- Good — the coverage doc ([`docs/MITRE-COVERAGE.md`](../MITRE-COVERAGE.md)) stays honest: 16 claimed, 16
  registered, count-guarded; the excluded nine are named there with the permission each would have needed.
- Cost — this edition will not detect network-level or page-content techniques, and says so plainly.
- The **build fails** if `host_permissions` or `fetch()` are introduced — contributors adding a technique here
  must do it within the existing permission envelope.
- Scopes `webRequest` / `content` are reserved words in `@attack/rule-schema` and validate, but no signal
  source in this repository emits them.
