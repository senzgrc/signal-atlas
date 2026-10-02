/* Pure report facts. No browser, model calls, or organization-specific assumptions. */

export const REPORT_SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
const number = (value) => Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : 0;
export const sumBins = (value, kev = false) => Array.isArray(value)
  ? value.slice(kev ? 5 : 0, kev ? 10 : 5).reduce((sum, item) => sum + number(item), 0) : 0;
export const percentage = (numerator, denominator) => denominator > 0 ? numerator * 100 / denominator : null;
export const safeReference = (value) => {
  if (typeof value !== 'string' || value.length > 8192 || /[\s\u0000-\u001f\u007f-\u009f\\]/.test(value)) return null;
  try { const url = new URL(value); return url.protocol === 'https:' && url.hostname && !url.username && !url.password ? url.href : null; } catch { return null; }
};
const recordId = (record) => typeof (record?.id ?? record?.cveID) === 'string' ? record.id ?? record.cveID : '';
const validRecord = (record) => record && /^CVE-\d{4}-\d{4,}$/.test(recordId(record));
const deduplicate = (records) => [...new Map((Array.isArray(records) ? records : [])
  .filter(validRecord).map((record) => [recordId(record), record])).values()];
const emptyStats = () => ({ total: 0, critical: 0, kev: 0, severity: {}, insights: {} });

function reportPeriod(entry, matched, partialYear) {
  if (!entry) return null;
  if (!matched) return entry;
  return entry.through ?? (Number(entry.year) === partialYear ? entry : null);
}

export function withinPeriod(record, year, window, matched) {
  const published = new Date(record?.published);
  if (!Number.isFinite(published.getTime()) || published.getUTCFullYear() !== Number(year)) return false;
  if (!matched) return true;
  if (!window || !/^\d{2}-\d{2}$/.test(window.endMonthDay ?? '')) return false;
  const [month, requestedDay] = window.endMonthDay.split('-').map(Number);
  const day = Math.min(requestedDay, new Date(Date.UTC(Number(year), month, 0)).getUTCDate());
  const cutoff = new Date(`${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}T${window.endTime ?? '23:59:59.999Z'}`);
  return Number.isFinite(cutoff.getTime()) && published <= cutoff;
}

export function buildIntelReport({ summary = {}, pack, year, comparison, lang = 'fr' }) {
  if (pack?.schemaVersion !== 1 || !['product', 'category'].includes(pack.subject?.kind) || !Array.isArray(pack.years)) {
    throw new Error('Unsupported intelligence report data');
  }
  const selectedYear = Number(year), comparisonYear = Number(comparison);
  const selectedEntry = pack.years.find((item) => Number(item.year) === selectedYear);
  const previousEntry = pack.years.find((item) => Number(item.year) === comparisonYear);
  if (!Number.isInteger(selectedYear) || !selectedEntry) throw new Error('Report year is outside cached coverage');
  const window = pack.comparisonWindow ?? summary.comparisonWindow;
  const partialYear = Number(window?.partialYear);
  const matched = Number.isInteger(partialYear) && [selectedYear, comparisonYear].includes(partialYear);
  const selectedPeriod = reportPeriod(selectedEntry, matched, partialYear);
  if (matched && !selectedPeriod) throw new Error('Aligned report period is unavailable in the cache');
  const previousPeriod = reportPeriod(previousEntry, matched, partialYear);
  const comparable = Boolean(selectedPeriod && previousPeriod && selectedYear !== comparisonYear);
  const stats = selectedPeriod ?? selectedEntry ?? emptyStats();
  const total = number(stats.total), previousTotal = comparable ? number(previousPeriod.total) : null;
  const insights = stats.insights ?? {};
  const causeKnown = sumBins(insights.causeKnown), impactKnown = sumBins(insights.impactKnown);
  const reachKnown = sumBins(insights.reachKnown), remote = sumBins(insights.remoteUnauthenticated);
  const weaknesses = Object.entries(insights.causes ?? {}).filter(([id]) => /^CWE-[1-9]\d{0,5}$/.test(id))
    .map(([id, bins]) => ({ id, name: String(summary.weaknessLabels?.names?.[id] ?? id), count: sumBins(bins) }))
    .filter((item) => item.count > 0).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
  const impacts = ['confidentiality', 'integrity', 'availability'].map((id) => ({ id, count: sumBins(insights.impacts?.[id]) }));
  const relatedKev = deduplicate(pack.relatedKev).sort((a, b) => String(b.kevDetails?.dateAdded ?? '')
    .localeCompare(String(a.kevDetails?.dateAdded ?? '')) || recordId(a).localeCompare(recordId(b)));
  const relatedIds = new Set(relatedKev.map(recordId));
  const supplementalKev = deduplicate(pack.supplementalKev).filter((record) => !relatedIds.has(recordId(record)));
  const selectedKev = relatedKev.filter((record) => withinPeriod(record, selectedYear, window, matched));
  const examples = deduplicate(pack.examples).slice(0, 10);
  const historical = [...pack.years].sort((a, b) => Number(a.year) - Number(b.year)).map((entry) => {
    const period = reportPeriod(entry, matched, partialYear);
    return { year: Number(entry.year), available: Boolean(period), total: period ? number(period.total) : null,
      critical: period ? number(period.critical) : null, kev: period ? number(period.kev) : null,
      partial: Number(entry.year) === partialYear, stats: period };
  });
  const fullTotals = pack.years.reduce((sum, entry) => sum + number(entry.total), 0);
  return { lang: lang === 'en' ? 'en' : 'fr', subject: pack.subject, year: selectedYear, comparison: comparisonYear,
    generatedAt: pack.generatedAt ?? summary.generatedAt, coverage: pack.coverage ?? summary.coverage ?? {},
    weaknessSource: summary.weaknessLabels ?? {}, matched, window, comparable,
    periodAvailable: Boolean(selectedPeriod), stats, total, critical: number(stats.critical), kev: number(stats.kev),
    previousTotal, difference: comparable ? total - previousTotal : null,
    changePercent: comparable && previousTotal > 0 ? (total - previousTotal) * 100 / previousTotal : null,
    severity: REPORT_SEVERITIES.map((id) => ({ id, count: number(stats.severity?.[id]) })),
    causeKnown, missingCause: Math.max(0, total - causeKnown), impactKnown, missingImpact: Math.max(0, total - impactKnown),
    reachKnown, missingReach: Math.max(0, total - reachKnown), remote, weaknesses, impacts,
    classification: stats.classification ?? selectedEntry.classification ?? pack.classification ?? null,
    historical, fullTotals, relatedKev, supplementalKev, selectedKev, examples,
    topProducts: pack.topProducts ?? null, pack,
  };
}

const controls = [
  { ids: ['CWE-79', 'CWE-89', 'CWE-78', 'CWE-77', 'CWE-94', 'CWE-95', 'CWE-611'],
    fr: 'Valider les entrées, employer des requêtes paramétrées et encoder les sorties selon leur contexte; tester les points d’entrée concernés.',
    en: 'Validate inputs, use parameterized queries and encode output for its context; test the affected entry points.' },
  { ids: ['CWE-119', 'CWE-120', 'CWE-121', 'CWE-122', 'CWE-125', 'CWE-787', 'CWE-416', 'CWE-415', 'CWE-190'],
    fr: 'Vérifier les correctifs de sûreté mémoire, les options de durcissement et les tests de fuzzing; planifier des composants sûrs pour les chemins sensibles.',
    en: 'Verify memory-safety patches, hardening options and fuzz testing; plan memory-safe components for sensitive paths.' },
  { ids: ['CWE-284', 'CWE-285', 'CWE-287', 'CWE-306', 'CWE-862', 'CWE-863', 'CWE-269', 'CWE-639'],
    fr: 'Tester l’authentification et l’autorisation côté serveur, appliquer le refus par défaut et réduire les privilèges des comptes et services.',
    en: 'Test server-side authentication and authorization, deny access by default and reduce account and service privileges.' },
  { ids: ['CWE-502'], fr: 'Éviter la désérialisation de données non fiables; vérifier les formats sûrs et les types explicitement autorisés.',
    en: 'Avoid deserializing untrusted data; verify safe formats and explicitly allowed types.' },
  { ids: ['CWE-22', 'CWE-23', 'CWE-36', 'CWE-73'],
    fr: 'Restreindre les chemins aux répertoires autorisés, normaliser les chemins et tester les traversées et les liens symboliques.',
    en: 'Restrict paths to allowed directories, canonicalize paths and test traversal and symbolic-link handling.' },
  { ids: ['CWE-200', 'CWE-201', 'CWE-209', 'CWE-522', 'CWE-798', 'CWE-321', 'CWE-327'],
    fr: 'Réduire l’exposition des secrets et des journaux, vérifier la gestion des clés et préparer une rotation si l’applicabilité est confirmée.',
    en: 'Reduce secret and log exposure, verify key management and prepare rotation when applicability is confirmed.' },
  { ids: ['CWE-400', 'CWE-770', 'CWE-835'],
    fr: 'Tester les limites de ressources, les délais et les quotas; vérifier la reprise après saturation ou interruption.',
    en: 'Test resource limits, timeouts and quotas; verify recovery after saturation or interruption.' },
];
export function controlForWeakness(id, lang = 'fr') {
  return controls.find((control) => control.ids.includes(id))?.[lang === 'en' ? 'en' : 'fr'] ??
    (lang === 'en' ? 'Review the vendor fix and the affected design; select and test the corresponding control after applicability is established.' :
      'Examiner le correctif du fournisseur et la conception touchée; choisir et tester le contrôle pertinent après confirmation de l’applicabilité.');
}

export const cveIdentifier = recordId;
