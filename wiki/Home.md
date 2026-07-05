# 0x13d::att&ck — Wiki

Browser Endpoint Detection & Response as a Manifest V3 extension: browser events → MITRE ATT&CK-mapped
signatures → local alert + bounded response. **Zero host permissions, zero network egress — enforced by the
build.**

This wiki is **version-controlled from the main repo** (the [`wiki/`](https://github.com/0x13d/attack/tree/main/wiki)
directory) and published automatically — see [Contributing to this wiki](Contributing-to-this-Wiki).

## Start here

- **[Rule Reference](Rule-Reference)** — the authored-rule format: scopes, fields, ops, responses, conditions.
- **VS Code rule builder** — author, validate, and tune rules in your editor
  ([extension README](https://github.com/0x13d/attack/blob/main/apps/vscode/README.md)).
- **Scenario harness** — drive rules against a labeled corpus, measure detection + false-positive rates
  (`npm run scenarios`, or the builder's *Tune* command).

## The two editions

| | Community (this repo, AGPL-3.0) | Enterprise (commercial) |
|---|---|---|
| Techniques | 16 | 25 |
| Host permissions | none | scoped, optional, managed-policy gated |
| Network egress | none (build-enforced) | present |

## Links

- Repo: https://github.com/0x13d/attack
- Releases: https://github.com/0x13d/attack/releases
- Rules package (npm): [`0x13d-attack-rules-community`](https://www.npmjs.com/package/0x13d-attack-rules-community)
