"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.runScenarioReport = runScenarioReport;
const vscode = __importStar(require("vscode"));
const _0x13d_attack_rules_community_1 = require("0x13d-attack-rules-community");
/**
 * Run the community scenario corpus against the community rule set and render the detection / false-positive
 * report in a webview. This is the tuning feedback loop surfaced in the authoring tool: an author can watch,
 * per technique, which malicious cases fire and which benign cases stay silent. The runner + corpus come from
 * the published `0x13d-attack-rules-community` package, so this shows exactly what the CLI harness shows.
 */
function runScenarioReport() {
    let report;
    try {
        report = (0, _0x13d_attack_rules_community_1.runScenarios)((0, _0x13d_attack_rules_community_1.buildRules)(), _0x13d_attack_rules_community_1.CORPUS);
    }
    catch (err) {
        void vscode.window.showErrorMessage(`Scenario harness failed: ${err.message}`);
        return;
    }
    const panel = vscode.window.createWebviewPanel('attackScenarios', '0x13d::att&ck — Scenario report', vscode.ViewColumn.Beside, { enableScripts: false });
    panel.webview.html = renderHtml(report);
}
function esc(s) {
    return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}
function renderHtml(r) {
    const rows = r.byTechnique
        .map((s) => {
        const fp = s.falsePositives > 0;
        const miss = s.missed > 0;
        return `<tr>
        <td class="tech">${esc(s.technique)}</td>
        <td class="${miss ? 'bad' : 'ok'}">${s.detected}/${s.malicious}</td>
        <td class="${fp ? 'bad' : 'ok'}">${s.falsePositives}/${s.benign}</td>
      </tr>`;
    })
        .join('');
    const bad = r.results.filter((x) => x.outcome === 'missed' || x.outcome === 'false-positive');
    const badList = bad.length
        ? `<h2>Needs tuning (${bad.length})</h2><ul>${bad
            .map((x) => x.outcome === 'missed'
            ? `<li class="bad">MISS · <b>${esc(x.technique)}</b> · ${esc(x.label)} — expected a detection, none fired</li>`
            : `<li class="bad">FALSE POSITIVE · <b>${esc(x.technique)}</b> · ${esc(x.label)} — fired: ${esc(x.fired.join(', ') || '(none)')}</li>`)
            .join('')}</ul>`
        : `<p class="clean">✓ Clean — every malicious case fired and every benign case stayed silent across ${r.cases} cases.</p>`;
    return `<!doctype html><html><head><meta charset="utf-8"><style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 1rem 1.25rem; }
    h1 { font-size: 1.15rem; } h2 { font-size: 1rem; margin-top: 1.5rem; }
    .summary { opacity: .85; margin: .25rem 0 1rem; }
    table { border-collapse: collapse; width: 100%; max-width: 32rem; }
    th, td { text-align: left; padding: .3rem .6rem; border-bottom: 1px solid var(--vscode-panel-border); }
    th { opacity: .7; font-weight: 600; }
    .tech { font-variant-numeric: tabular-nums; }
    .ok { color: var(--vscode-testing-iconPassed, #3fb950); }
    .bad { color: var(--vscode-testing-iconFailed, #f85149); }
    .clean { color: var(--vscode-testing-iconPassed, #3fb950); font-weight: 600; }
    ul { line-height: 1.6; } li { list-style: none; }
    code { background: var(--vscode-textCodeBlock-background); padding: 0 .3rem; border-radius: 3px; }
  </style></head><body>
    <h1>Scenario harness — detection &amp; false-positive report</h1>
    <p class="summary">${r.cases} cases · <b class="${r.missed ? 'bad' : 'ok'}">${r.detected}/${r.detected + r.missed}</b> detections ·
      <b class="${r.falsePositives ? 'bad' : 'ok'}">${r.falsePositives}</b> false positives across ${r.results.filter((x) => !x.malicious).length} benign cases.
      Re-run after editing a rule or the policy: <code>npm run scenarios</code>.</p>
    <table>
      <thead><tr><th>Technique</th><th>Detected (TP/malicious)</th><th>False pos (FP/benign)</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    ${badList}
  </body></html>`;
}
//# sourceMappingURL=scenarios.js.map