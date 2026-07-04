"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateAuthoredRule = validateAuthoredRule;
/**
 * Authored-rule validator for the VSCode extension. A thin wrapper over the **canonical** validator in
 * `@attack/rule-schema` (ADR-004) — no duplicated logic, no hand-maintained scope/op/limit lists. The valid
 * response ids come from the generated `responseIds.generated.ts` (derived from the engine's live response
 * registry), so the editor and the engine can't drift (this fixes the v0.8.0 `RESPONSE_IDS` drift).
 */
const rule_schema_1 = require("@attack/rule-schema");
const responseIds_generated_1 = require("./responseIds.generated");
const RESPONSE_ID_SET = new Set(responseIds_generated_1.RESPONSE_IDS);
function validateAuthoredRule(input) {
    return (0, rule_schema_1.validateAuthoredRule)(input, RESPONSE_ID_SET);
}
//# sourceMappingURL=validate.js.map