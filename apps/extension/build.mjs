// Build the MV3 extension — bundle the service worker + popup, generate the manifest + PNG icons.
// The community edition's trust claim is enforced mechanically below: a build with host permissions or any
// network egress is a build FAILURE. `node build.mjs` → dist/ — load unpacked in Chrome/Edge.
import { build } from 'esbuild';
import { mkdir, copyFile, writeFile, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import zlib from 'node:zlib';

const OUTDIR = 'dist';

// --- minimal PNG encoder (solid RGB image) — defined first so it's initialized before use ---------------
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function solidPng(size, [r, g, b]) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // color type: RGB
  const row = Buffer.alloc(1 + size * 3); // filter byte (0) + pixels
  for (let x = 0; x < size; x++) {
    row[1 + x * 3] = r;
    row[2 + x * 3] = g;
    row[3 + x * 3] = b;
  }
  const raw = Buffer.concat(Array.from({ length: size }, () => row));
  const idat = zlib.deflateSync(raw);
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}

// --- build --------------------------------------------------------------------------------------------
await mkdir(OUTDIR, { recursive: true });

await build({
  entryPoints: [
    { in: 'src/background.ts', out: 'background' },
    { in: 'popup.ts', out: 'popup' },
    { in: 'options.ts', out: 'options' },
  ],
  bundle: true,
  format: 'esm',
  target: 'chrome110',
  outdir: OUTDIR,
  legalComments: 'none',
  logLevel: 'info',
  // Identifiers + whitespace stay intact so the bundle remains auditable.
  minifySyntax: true,
});

// The manifest ships as-authored: host-permission-free (the auditable trust claim, checked below).
const manifest = JSON.parse(await readFile('manifest.json', 'utf8'));
await writeFile(`${OUTDIR}/manifest.json`, JSON.stringify(manifest, null, 2));

await copyFile('popup.html', `${OUTDIR}/popup.html`);
await copyFile('options.html', `${OUTDIR}/options.html`);
await copyFile('managed_schema.json', `${OUTDIR}/managed_schema.json`);

// Real, valid PNG icons (a solid Ink-indigo square) so notifications + the toolbar render. Generated in-build
// to keep binary assets out of git; replace with a designed mark in a later polish card.
const INK_INDIGO = [63, 76, 107]; // #3F4C6B (indigo accent)
for (const size of [16, 48, 128]) {
  await writeFile(`${OUTDIR}/icon${size}.png`, solidPng(size, INK_INDIGO));
}

// --- trust self-check ----------------------------------------------------------------------------------
// The trust claim is mechanical, not aspirational: a build that gained host permissions or any network
// egress is a build *failure*, here, loudly.
{
  const errs = [];
  if (manifest.host_permissions?.length) errs.push(`host_permissions present: ${JSON.stringify(manifest.host_permissions)}`);
  if (manifest.optional_host_permissions?.length) errs.push('optional_host_permissions present');
  if (manifest.optional_permissions?.length) errs.push('optional_permissions present');
  if (manifest.content_scripts?.length) errs.push('content_scripts present');
  // Grep *every* bundle (worker + popup + options), not just the worker.
  for (const js of ['background.js', 'popup.js', 'options.js']) {
    const code = await readFile(`${OUTDIR}/${js}`, 'utf8');
    if (code.includes('fetch(')) errs.push(`${js} contains a fetch() — this build must have no network egress`);
    if (code.includes('chrome.webRequest')) errs.push(`${js} references chrome.webRequest — not part of this build`);
    if (code.includes('chrome.declarativeNetRequest')) errs.push(`${js} references chrome.declarativeNetRequest — not part of this build`);
    if (code.includes('chrome.scripting')) errs.push(`${js} references chrome.scripting — not part of this build`);
  }
  // No content script may ship.
  if (existsSync(`${OUTDIR}/content.js`)) errs.push('content.js present — no content script ships in this build');
  if (errs.length) throw new Error(`Trust self-check FAILED:\n  - ${errs.join('\n  - ')}`);
  console.log('attack: trust self-check passed — zero host permissions, no egress, no network APIs.');
}

console.log(`attack: built ${OUTDIR}/ (background.js + popup + manifest + icons) — Load unpacked in Chrome/Edge.`);
