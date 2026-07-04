import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { buildTargets } from '../../tools/gen-rule-schema';

// ADR-004 drift guard: the generated VSCode artifacts (JSON Schema + responseIds.generated.ts) must match what
// the generator produces from the canonical package + the live engine registry. A stale committed file fails
// `npm test` here (not just the separate `check:schema`), so the editor can't silently drift from the engine.
test('generated VSCode schema + response ids are in sync with the engine', () => {
  for (const { path, content } of buildTargets()) {
    assert.ok(existsSync(path), `missing generated file: ${path} — run \`npm run gen:schema\``);
    assert.equal(readFileSync(path, 'utf8'), content, `${path} is stale — run \`npm run gen:schema\``);
  }
});
