# Rule Reference

An authored rule is **declarative JSON** — data the engine interprets, never code it executes. It matches a
`condition` against a browser signal and, on a hit, runs one or more bounded `responses`.

## Anatomy

```json
{
  "id": "user.flag-hta",
  "name": "Flag .hta downloads",
  "technique": "T1105",
  "scope": "download",
  "condition": { "field": "payload.filename", "op": "contains", "value": ".hta" },
  "responses": ["alert", "cancelDownload"],
  "enabled": true
}
```

| field | meaning |
|---|---|
| `id` | Unique id (convention: `user.*`). |
| `name` | Human label shown in alerts. |
| `technique` | ATT&CK id this rule maps to (free-form; used for grouping/tuning). |
| `scope` | The signal source it listens on (see below). |
| `condition` | A leaf `{field, op, value}` or a compound `all` / `any` / `not`. |
| `responses` | Response ids to run on a hit. |
| `enabled` | Whether the engine loads it. |

## Scopes and payload fields

A `field` is a dot-path over the signal: top-level `name`, `scope`, `tabId`, `windowId`, plus `payload.*`.

| scope | payload fields |
|---|---|
| `download` | `payload.filename`, `payload.finalUrl`, `payload.mime`, `payload.referrer` |
| `management` | `payload.installType`, `payload.permissions` (array), `payload.hostPermissions` (array), `payload.name` |
| `webNavigation` | `payload.url`, `payload.transitionType` |
| `cookie` | `payload.cookie.name`, `payload.cookie.secure`, `payload.cookie.httpOnly`, `payload.cookie.sameSite`, `payload.cookie.session` |

> Only these four scopes have live signal sources in the community edition. `webRequest` / `content` are
> reserved for the commercial edition; `tab` / `window` are in the schema but not wired.

## Operators

`eq` · `ne` · `exists` (no value) · `in` / `nin` (array value) · `contains` · `containsAny` (array value) ·
`gt` · `lt` · `gte` · `lte` (numeric).

## Conditions

- **Leaf:** `{ "field": "payload.filename", "op": "contains", "value": ".hta" }`
- **All (AND):** `{ "all": [ …conditions ] }`
- **Any (OR):** `{ "any": [ …conditions ] }`
- **Not:** `{ "not": { …condition } }`

```json
{
  "all": [
    { "field": "payload.filename", "op": "contains", "value": ".docm" },
    { "field": "payload.referrer", "op": "contains", "value": "mail.google.com" }
  ]
}
```

## Responses

`alert` · `cancelDownload` · `closeTab` · `disableExtension` · `removeCookie` — use the ones that fit the scope
(`cancelDownload` for downloads, `disableExtension` for management, `removeCookie` for cookies, `closeTab` for
navigation).

## Limits

≤ 32 KB per rule, ≤ 200 condition nodes. The validator rejects anything larger, malformed, or referencing an
unknown response id.

## Testing a rule

- In VS Code: **Validate**, then **Tune rule against the corpus** (detection + false-positive report).
- CLI: `npm run scenarios` in the [`rules/`](https://github.com/0x13d/attack/tree/main/rules) package.
- Live: import it on the EDR extension's **Options** page → **Add a rule**.
