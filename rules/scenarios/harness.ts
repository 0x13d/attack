/**
 * CLI for the scenario harness. Drives the real community rule set (`buildRules()`) with the shipped corpus
 * and reports per-technique detection and false-positive rates — no browser, no human in the loop.
 *
 *   npx tsx scenarios/harness.ts            # summary table
 *   npx tsx scenarios/harness.ts --verbose  # + every misclassified case
 *   npx tsx scenarios/harness.ts --json     # machine-readable ScenarioReport (for tooling / CI)
 *
 * The runner, corpus, and types are exported from the package itself
 * (`0x13d-attack-rules-community` → runScenarios / CORPUS), so the same loop backs the VS Code rule builder.
 */
import { buildRules, DEFAULT_POLICY, runScenarios, CORPUS } from '../src';

const report = runScenarios(buildRules(DEFAULT_POLICY), CORPUS);

if (process.argv.includes('--json')) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.clean ? 0 : 1);
}

console.log('\n  technique     detect(TP/mal)   false-pos(FP/benign)');
console.log('  ────────────────────────────────────────────────────');
for (const s of report.byTechnique) {
  console.log(`  ${s.technique.padEnd(12)} ${String(s.detected + '/' + s.malicious).padStart(10)}        ${String(s.falsePositives + '/' + s.benign).padStart(10)}`);
}
console.log('  ────────────────────────────────────────────────────');
console.log(`  TOTAL: ${report.cases} cases — detection ${report.detected}/${report.detected + report.missed}, false positives ${report.falsePositives}/${report.results.filter((r) => !r.malicious).length}`);

if (process.argv.includes('--verbose')) {
  const bad = report.results.filter((r) => r.outcome === 'missed' || r.outcome === 'false-positive');
  if (bad.length) {
    console.log('');
    for (const r of bad) {
      if (r.outcome === 'missed') console.log(`  • MISS (false negative) [${r.technique}] ${r.label}`);
      else console.log(`  • FALSE POSITIVE [${r.technique}] ${r.label} → fired: ${r.fired.join(',') || '(none?)'}`);
    }
  }
}

console.log(report.clean
  ? '\n  ✓ clean: every malicious case fired, every benign case stayed silent.\n'
  : `\n  ✗ ${report.falsePositives} false positive(s), ${report.missed} false negative(s) — tune policy/heuristics and re-run.\n`);
process.exit(report.clean ? 0 : 1);
