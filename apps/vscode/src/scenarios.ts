import * as vscode from 'vscode';
import { buildRules, buildResponseRegistry, runScenarios, CORPUS, RESPONSE_IDS, type ScenarioReport } from '0x13d-attack-rules-community';
import { compileAuthoredRule } from '0x13d-attack-rules-community/compile';
import { validateAuthoredRule, type AuthoredRule } from '@attack/rule-schema';

/**
 * Run the community scenario corpus against the community rule set and render the detection / false-positive
 * report in a webview. This is the tuning feedback loop surfaced in the authoring tool: an author can watch,
 * per technique, which malicious cases fire and which benign cases stay silent. The runner + corpus come from
 * the published `0x13d-attack-rules-community` package, so this shows exactly what the CLI harness shows.
 */
export function runScenarioReport(): void {
  let report: ScenarioReport;
  try {
    report = runScenarios(buildRules(), CORPUS);
  } catch (err) {
    void vscode.window.showErrorMessage(`Scenario harness failed: ${(err as Error).message}`);
    return;
  }

  const panel = vscode.window.createWebviewPanel(
    'attackScenarios',
    '0x13d::att&ck — Scenario report',
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );
  panel.webview.html = renderHtml(report);
}

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));
}

function renderHtml(r: ScenarioReport): string {
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
        .map((x) =>
          x.outcome === 'missed'
            ? `<li class="bad">MISS · <b>${esc(x.technique)}</b> · ${esc(x.label)} — expected a detection, none fired</li>`
            : `<li class="bad">FALSE POSITIVE · <b>${esc(x.technique)}</b> · ${esc(x.label)} — fired: ${esc(x.fired.join(', ') || '(none)')}</li>`,
        )
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

// ── tune the authored rule in the active editor against the corpus ────────────────────────────────

interface CaseOutcome { label: string; technique: string; fired: boolean; }
interface TuneResult {
  ruleId: string;
  technique: string;
  scope: string;
  detected: CaseOutcome[]; // malicious cases of the rule's technique that fired
  missed: CaseOutcome[]; // malicious cases of the rule's technique that did NOT fire
  falsePositives: CaseOutcome[]; // benign cases (of the rule's scope) that fired
  benignChecked: number;
}

/**
 * Compile the authored rule in the active editor and run it against the corpus cases for its scope: how many
 * known-malicious cases of its technique it catches, and whether it trips any benign case. This is the live
 * tuning loop — narrow the condition to kill a false positive, broaden it to catch a missed case, re-run.
 */
export function tuneActiveRule(): void {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showWarningMessage('Open a *.attackrule.json rule file first.');
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(editor.document.getText());
  } catch (err) {
    void vscode.window.showErrorMessage(`Not valid JSON: ${(err as Error).message}`);
    return;
  }
  const validation = validateAuthoredRule(parsed, RESPONSE_IDS);
  if (!validation.ok) {
    void vscode.window.showErrorMessage(`Rule rejected — fix before tuning:\n• ${validation.errors.join('\n• ')}`);
    return;
  }

  const authored = parsed as AuthoredRule;
  let result: TuneResult;
  try {
    // Responses never fire during tuning (the harness only tests the signature), but pass the real registry
    // so response-id resolution matches the extension exactly.
    const rule = compileAuthoredRule(authored, buildResponseRegistry());
    const subset = CORPUS.filter((c) => rule.scope.includes(c.scope));
    const report = runScenarios([rule], subset);
    const detected: CaseOutcome[] = [];
    const missed: CaseOutcome[] = [];
    const falsePositives: CaseOutcome[] = [];
    for (const r of report.results) {
      const fired = r.fired.length > 0;
      if (r.malicious && r.technique === rule.technique) (fired ? detected : missed).push({ label: r.label, technique: r.technique, fired });
      else if (!r.malicious && fired) falsePositives.push({ label: r.label, technique: r.technique, fired });
    }
    result = {
      ruleId: rule.id,
      technique: rule.technique,
      scope: String(rule.scope[0]),
      detected,
      missed,
      falsePositives,
      benignChecked: report.results.filter((r) => !r.malicious).length,
    };
  } catch (err) {
    void vscode.window.showErrorMessage(`Could not tune rule: ${(err as Error).message}`);
    return;
  }

  const panel = vscode.window.createWebviewPanel(
    'attackTune',
    `Tune: ${result.ruleId}`,
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );
  panel.webview.html = renderTuneHtml(result);
}

function renderTuneHtml(t: TuneResult): string {
  const targetTotal = t.detected.length + t.missed.length;
  const li = (o: CaseOutcome, cls: string, tag: string) => `<li class="${cls}">${tag} · ${esc(o.label)}</li>`;
  const detectionBlock = targetTotal === 0
    ? `<p class="muted">No malicious reference cases for <code>${esc(t.technique)}</code> in the corpus — add some to <code>rules/src/scenarios/corpus.ts</code> to measure detection. False-positive tripwires for the <code>${esc(t.scope)}</code> scope are still checked below.</p>`
    : `<p>Catches <b class="${t.missed.length ? 'warn' : 'ok'}">${t.detected.length}/${targetTotal}</b> known-malicious <code>${esc(t.technique)}</code> cases.</p>
       <ul>${t.detected.map((o) => li(o, 'ok', '✓ caught')).join('')}${t.missed.map((o) => li(o, 'warn', '✗ missed')).join('')}</ul>`;

  const fpBlock = t.falsePositives.length
    ? `<h2 class="bad">False positives (${t.falsePositives.length})</h2>
       <p class="muted">Your rule fired on these benign <code>${esc(t.scope)}</code> cases — tighten the condition.</p>
       <ul>${t.falsePositives.map((o) => li(o, 'bad', `⚠ ${esc(o.technique)}`)).join('')}</ul>`
    : `<p class="ok">✓ No false positives across ${t.benignChecked} benign ${esc(t.scope)} case(s).</p>`;

  const verdict = t.falsePositives.length === 0 && t.missed.length === 0 && targetTotal > 0
    ? `<p class="clean">✓ Clean — catches every reference case for its technique, trips no benign case.</p>` : '';

  return `<!doctype html><html><head><meta charset="utf-8"><style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 1rem 1.25rem; }
    h1 { font-size: 1.1rem; } h2 { font-size: 1rem; margin-top: 1.4rem; }
    .muted { opacity: .8; } code { background: var(--vscode-textCodeBlock-background); padding: 0 .3rem; border-radius: 3px; }
    ul { line-height: 1.6; padding-left: 0; } li { list-style: none; }
    .ok { color: var(--vscode-testing-iconPassed, #3fb950); }
    .warn { color: var(--vscode-testing-iconQueued, #d29922); }
    .bad { color: var(--vscode-testing-iconFailed, #f85149); }
    .clean { color: var(--vscode-testing-iconPassed, #3fb950); font-weight: 600; }
  </style></head><body>
    <h1>Tuning <code>${esc(t.ruleId)}</code> · ${esc(t.technique)} · scope <code>${esc(t.scope)}</code></h1>
    ${verdict}
    <h2>Detection</h2>
    ${detectionBlock}
    ${fpBlock}
    <p class="muted" style="margin-top:1.5rem">Edit the rule and re-run this command to see the effect. The same corpus and runner back <code>npm run scenarios</code>.</p>
  </body></html>`;
}
