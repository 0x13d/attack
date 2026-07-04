/**
 * Re-export the authored-rule compiler from `0x13d-attack-rules-community/compile` (ADR-002/ADR-004). The
 * bridge from the declarative schema to a runtime `Rule` now lives in the rules package (it produces a
 * rules-package `Rule` and resolves responses from that package's registry), so the VS Code builder and the
 * scenario harness can compile authored rules too. The engine keeps importing from `./schema/compile`, a thin
 * shim like `./validate`/`./types`.
 */
export { compileAuthoredRule } from '0x13d-attack-rules-community/compile';
