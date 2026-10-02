import { readFile, stat } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { gunzipSync } from 'node:zlib';

// Prevent unfinished bootstraps from being published accidentally. Explicit
// local checks can override this guard; shard URLs are verified in both modes.
const root = resolve('public/data');
let summary;
try {
  summary = JSON.parse(await readFile(resolve(root, 'summary.json'), 'utf8'));
} catch {
  throw new Error('Missing dashboard cache. Run Python sync/export first (see README).');
}
if (summary.schemaVersion !== 1 || !Array.isArray(summary.years)) {
  throw new Error('Unsupported dashboard cache schema.');
}
if (!summary.coverage?.bootstrapComplete && process.env.ALLOW_INCOMPLETE_BUILD !== '1') {
  throw new Error('Initial import is unfinished. Complete sync before publishing. For local verification only, set ALLOW_INCOMPLETE_BUILD=1.');
}
let bytes = (await stat(resolve(root, 'summary.json'))).size;
const compressedSummary = await readFile(resolve(root, 'summary.json.gz'));
const decodedSummary = JSON.parse(gunzipSync(compressedSummary, { maxOutputLength: 16_000_000 }));
if (JSON.stringify(decodedSummary) !== JSON.stringify(summary)) throw new Error('Compressed summary does not match the exported snapshot. Run export again.');
bytes += compressedSummary.length;
for (const year of summary.years) {
  for (const month of year.months ?? []) {
    for (const path of month.paths ?? []) {
      if (!/^records\/[\w.-]+\.json(?:\.gz)?$/.test(path)) throw new Error('Invalid shard path');
      const target = resolve(root, path);
      if (!target.startsWith(root + sep)) throw new Error('Invalid shard location');
      bytes += (await stat(target)).size;
    }
  }
}
bytes += (await stat(resolve(root, 'kev.json'))).size;
const reportPaths = summary.reportPaths;
if (!reportPaths || Object.keys(reportPaths.products ?? {}).length !== summary.products.length || !summary.products.every(product => Object.hasOwn(reportPaths.products ?? {}, product.id)) || !['All', 'OS', 'Application', 'Hardware', 'Unknown'].every(id => reportPaths.categories?.[id])) throw new Error('Executive report cache is incomplete. Run export again.');
for (const [group, subjects] of Object.entries(reportPaths)) {
  if (!['products', 'categories'].includes(group)) throw new Error('Invalid report group');
  for (const [id, relative] of Object.entries(subjects)) {
    if (group === 'products' ? !/^[a-f0-9]{24}$/.test(id) : !['All', 'OS', 'Application', 'Hardware', 'Unknown'].includes(id)) throw new Error('Invalid report subject');
    if (relative !== `intel/${group}-${id}.json.gz`) throw new Error('Invalid report path');
    const compressed = await readFile(resolve(root, relative));
    const pack = JSON.parse(gunzipSync(compressed, { maxOutputLength: 8_000_000 }));
    if (pack.schemaVersion !== 1 || pack.subject?.id !== id || pack.subject?.kind !== (group === 'products' ? 'product' : 'category') || pack.generatedAt !== summary.generatedAt || pack.coverage?.end !== summary.coverage?.end || !Array.isArray(pack.years)) throw new Error('Report cache does not match the dashboard snapshot');
    bytes += compressed.length;
  }
}
console.log(`Dashboard cache verified: ${Number(summary.totalCves).toLocaleString()} CVEs, ${(bytes / 1_000_000).toFixed(1)} MB of data.`);
