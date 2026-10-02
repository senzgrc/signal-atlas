import test from 'node:test';
import assert from 'node:assert/strict';
import { buildIntelReport, controlForWeakness, safeReference, sumBins, withinPeriod } from '../src/report-content.js';

const bins = (...values) => [...values, ...Array(10).fill(0)].slice(0, 10);
const stats = (total = 0, fields = {}) => ({ total, critical: 0, kev: 0,
  severity: { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: total },
  insights: { causeKnown: bins(), impactKnown: bins(), reachKnown: bins(), remoteUnauthenticated: bins(), causes: {}, impacts: {} }, ...fields });
const pack = (years, fields = {}) => ({ schemaVersion: 1, subject: { kind: 'product', id: 'a'.repeat(24), name: 'Widget', vendor: 'Acme' }, years,
  coverage: { end: '2026-09-30T12:00:00Z' }, relatedKev: [], supplementalKev: [], examples: [], ...fields });
const report = (data, fields = {}) => buildIntelReport({ pack: data, year: 2026, comparison: 2025, ...fields });

test('zero CVEs keep rates undefined and do not claim known causes or impacts', () => {
  const result = report(pack([{ year: 2025, ...stats() }, { year: 2026, ...stats() }]));
  assert.equal(result.total, 0); assert.equal(result.changePercent, null); assert.deepEqual(result.weaknesses, []);
  assert.equal(result.impactKnown, 0); assert.equal(result.missingImpact, 0); assert.equal(result.lang, 'fr');
});

test('unknown assessments stay in the denominator and KEV bins are not double-counted', () => {
  const result = report(pack([{ year: 2025, ...stats(2) }, { year: 2026, ...stats(10, {
    insights: { causeKnown: [1, 2, 0, 0, 0, 1, 1, 0, 0, 0], impactKnown: bins(2, 3), reachKnown: bins(4),
      remoteUnauthenticated: bins(2), causes: { 'CWE-79': bins(2), 'NVD-CWE-noinfo': bins(8) }, impacts: { confidentiality: bins(3) } },
  }) }]));
  assert.equal(result.causeKnown, 3); assert.equal(result.missingCause, 7); assert.equal(result.impactKnown, 5);
  assert.equal(result.remote, 2); assert.equal(result.missingReach, 6); assert.equal(result.weaknesses.length, 1);
  assert.equal(sumBins([1, 2, 0, 0, 0, 3, 4, 0, 0, 0]), 3);
});

test('complete assessment with no non-zero impacts remains assessed', () => {
  const result = report(pack([{ year: 2026, ...stats(4, { insights: { impactKnown: bins(4), impacts: {} } }) }]));
  assert.equal(result.impactKnown, 4); assert.equal(result.missingImpact, 0);
  assert.deepEqual(result.impacts.map((item) => item.count), [0, 0, 0]);
});

test('same-period partial-year comparison uses through facts in every year', () => {
  const result = report(pack([{ year: 2025, ...stats(100), through: stats(20) }, { year: 2026, ...stats(30), through: stats(30) }],
    { comparisonWindow: { partialYear: 2026, endMonthDay: '09-30', endTime: '12:00:00Z' } }));
  assert.equal(result.matched, true); assert.equal(result.total, 30); assert.equal(result.previousTotal, 20);
  assert.equal(result.changePercent, 50); assert.deepEqual(result.historical.map((item) => item.total), [20, 30]);
});

test('two complete historical years compare full totals even when cache has a partial year', () => {
  const result = report(pack([{ year: 2024, ...stats(10), through: stats(5) }, { year: 2025, ...stats(20), through: stats(7) },
    { year: 2026, ...stats(30), through: stats(30) }], { comparisonWindow: { partialYear: 2026, endMonthDay: '09-30', endTime: '12:00:00Z' } }), { year: 2025, comparison: 2024 });
  assert.equal(result.matched, false); assert.equal(result.total, 20); assert.equal(result.previousTotal, 10);
});

test('missing alignment prevents a fabricated comparison', () => {
  const result = report(pack([{ year: 2025, ...stats(100) }, { year: 2026, ...stats(30) }],
    { comparisonWindow: { partialYear: 2026, endMonthDay: '09-30', endTime: '12:00:00Z' } }));
  assert.equal(result.comparable, false); assert.equal(result.changePercent, null); assert.equal(result.historical[0].available, false);
  assert.throws(() => report(pack([{ year: 2025, ...stats(100) }, { year: 2026, ...stats(30) }],
    { comparisonWindow: { partialYear: 2026, endMonthDay: '09-30', endTime: '12:00:00Z' } }), { year: 2025, comparison: 2026 }), /Aligned/);
});

test('KEV scope is uncapped, deduplicated, and supplemental records stay separate', () => {
  const records = Array.from({ length: 120 }, (_, index) => ({ id: `CVE-2026-${String(index + 1).padStart(4, '0')}`, published: '2026-05-01T00:00:00Z', kevDetails: { dateAdded: '2026-06-01' } }));
  const result = report(pack([{ year: 2026, ...stats(120, { kev: 120 }) }], {
    relatedKev: [...records, records[0]], supplementalKev: [records[0], { id: 'CVE-2014-0001' }], examples: records,
  }));
  assert.equal(result.relatedKev.length, 120); assert.equal(result.selectedKev.length, 120);
  assert.equal(result.supplementalKev.length, 1); assert.equal(result.examples.length, 10); assert.equal(result.kev, 120);
});

test('matched KEV dates honor cutoff time and leap-day clamping', () => {
  const window = { partialYear: 2024, endMonthDay: '02-29', endTime: '12:00:00Z' };
  assert.equal(withinPeriod({ published: '2023-02-28T12:00:00Z' }, 2023, window, true), true);
  assert.equal(withinPeriod({ published: '2023-02-28T12:00:01Z' }, 2023, window, true), false);
  assert.equal(withinPeriod({ published: '2023-03-01T00:00:00Z' }, 2023, window, true), false);
});

test('only safe HTTPS references become PDF link annotations', () => {
  assert.equal(safeReference('https://vendor.example/security'), 'https://vendor.example/security');
  for (const url of ['javascript:alert(1)', 'http://example.com', 'https://user:pass@example.com', 'https://example.com\\@evil.com', 'https://example.com/\nfoo']) assert.equal(safeReference(url), null);
});

test('recommendations stay deterministic, bilingual and bounded to reported weakness types', () => {
  assert.match(controlForWeakness('CWE-89', 'fr'), /paramétrées/);
  assert.match(controlForWeakness('CWE-89', 'en'), /parameterized/);
  assert.match(controlForWeakness('CWE-122', 'fr'), /mémoire/);
  assert.match(controlForWeakness('CWE-121', 'en'), /memory/);
  assert.match(controlForWeakness('CWE-999999', 'en'), /applicability/);
  assert.throws(() => report({}), /Unsupported/);
  assert.throws(() => report(pack([{ year: 2024, ...stats() }])), /outside/);
});
