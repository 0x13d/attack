// Bundle the extension into a single self-contained out/extension.js so the packaged .vsix carries no
// node_modules — the workspace deps (@attack/rule-schema, 0x13d-attack-rules-community) are inlined. `vscode`
// is provided by the host and stays external. Run: `node esbuild.mjs` (add --watch for a rebuild loop).
import { build, context } from 'esbuild';
import { rmSync } from 'node:fs';

// Clear stale output (e.g. from an older tsc build) so the bundle — and the packaged .vsix — is only what
// esbuild emits: a single self-contained out/extension.js.
rmSync('out', { recursive: true, force: true });

const options = {
  entryPoints: ['src/extension.ts'],
  bundle: true,
  outfile: 'out/extension.js',
  platform: 'node',
  format: 'cjs',
  target: 'node18', // VS Code 1.85 runs on Node 18
  external: ['vscode'], // supplied by the extension host, never bundle it
  sourcemap: true,
  logLevel: 'info',
};

if (process.argv.includes('--watch')) {
  const ctx = await context(options);
  await ctx.watch();
  console.log('esbuild: watching for changes…');
} else {
  await build(options);
  console.log('esbuild: bundled out/extension.js (self-contained — deps inlined, vscode external).');
}
