/**
 * 0x13d-attack-rules-community — the 16 MITRE ATT&CK community detection rules for browser EDR.
 *
 * - `buildRules(policy)` — the full community rule set for an effective policy.
 * - `makeT…Rule(policy)` — each rule individually (mix and match, tune, extend).
 * - Detection logic is pure and unit-testable (`0x13d-attack-rules-community/detection/*`); responses run in
 *   an MV3 extension context (they call `chrome.*` APIs).
 */
export * from './types';
export * from './config';
export * from './alerts';
export * from './tamperState';
export * from './signals/cookie';

export { buildRules } from './rules';
export { makeT1176Rule } from './rules/t1176-browser-extensions';
export { makeT1176TamperRule } from './rules/t1176-tamper';
export { makeT1566Rule } from './rules/t1566-spearphishing-link';
export { makeT1566_001Rule } from './rules/t1566_001-spearphishing-attachment';
export { makeT1566_003Rule } from './rules/t1566_003-spearphishing-via-service';
export { makeT1539Rule } from './rules/t1539-session-cookie';
export { makeT1185Rule } from './rules/t1185-reverse-tabnabbing';
export { makeT1528Rule } from './rules/t1528-oauth-consent';
export { makeT1105Rule } from './rules/t1105-ingress-tool-transfer';
export { makeT1204_001Rule } from './rules/t1204_001-malicious-link';
export { makeT1204_002Rule } from './rules/t1204_002-malicious-file';
export { makeT1189Rule } from './rules/t1189-drive-by';
export { makeT1656Rule } from './rules/t1656-impersonation';
export { makeT1550_004Rule } from './rules/t1550_004-web-session-cookie';
export { makeT1606_002Rule } from './rules/t1606_002-saml-tokens';
export { makeT1217Rule } from './rules/t1217-browser-info-discovery';

export { makeAlertResponse } from './responses/alert';
export { closeTabResponse } from './responses/closeTab';
export { cancelDownloadResponse } from './responses/cancelDownload';
export { disableExtensionResponse } from './responses/disableExtension';
export { removeCookieResponse } from './responses/removeCookie';
export { buildResponseRegistry, RESPONSE_IDS } from './responses/registry';

// Scenario harness — the reusable tuning loop (drive rules with a labeled corpus; report detection + FP rates).
export { runScenarios, SIGNAL_NAME } from './scenarios/run';
export type { ScenarioCase, ScenarioReport, CaseResult, TechniqueStat } from './scenarios/run';
export { CORPUS } from './scenarios/corpus';
