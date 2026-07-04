// tsc emits ESM with extensionless relative imports, which plain Node can't resolve. Rewrite each relative
// specifier in dist/esm to its explicit file ('./x.js') or directory index ('./x/index.js').
import { readdirSync, readFileSync, writeFileSync, statSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';

const ROOT = resolve('dist/esm');

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (p.endsWith('.js')) yield p;
  }
}

for (const file of walk(ROOT)) {
  const src = readFileSync(file, 'utf8');
  const out = src.replace(/(from\s+['"])(\.\.?\/[^'"]+)(['"])/g, (m, pre, spec, post) => {
    const base = resolve(dirname(file), spec);
    if (existsSync(base + '.js')) return `${pre}${spec}.js${post}`;
    if (existsSync(join(base, 'index.js'))) return `${pre}${spec}/index.js${post}`;
    return m;
  });
  if (out !== src) writeFileSync(file, out);
}
console.log('[fix-esm-ext] dist/esm relative imports made Node-resolvable');
