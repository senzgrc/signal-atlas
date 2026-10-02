import { buildIntelReport, controlForWeakness, cveIdentifier, percentage, safeReference } from './report-content.js';

const COLORS = { navy: [21, 40, 66], blue: [33, 91, 154], ink: [39, 54, 72], muted: [97, 112, 131],
  pale: [242, 246, 250], line: [218, 226, 235], white: [255, 255, 255] };
const CISA = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
const SOURCE_LINKS = [
  ['NVD - CVE API', 'https://nvd.nist.gov/developers/vulnerabilities'],
  ['CISA - Known Exploited Vulnerabilities', CISA],
  ['MITRE - CWE', 'https://cwe.mitre.org/'],
  ['FIRST - CVSS', 'https://www.first.org/cvss/'],
];
const sanitize = (value) => String(value ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '')
  .replace(/[\u2010-\u2015\u2212]/g, '-').replace(/[\u00a0\u202f]/g, ' ').replace(/[\u{1f000}-\u{1ffff}]/gu, '').trim();
const truncate = (value, length) => { const clean = sanitize(value); return clean.length > length ? clean.slice(0, length - 3) + '...' : clean; };
const copy = {
  fr: {
    report: 'Renseignement stratégique sur les vulnérabilités', executive: 'Rapport exécutif',
    subtitle: 'Transformer les divulgations publiques en décisions documentées.',
    selected: 'Période étudiée', allSeverity: 'Toutes les gravités', comparison: 'Comparaison',
    product: 'Produit', category: 'Catégorie', publisher: 'Éditeur', snapshot: 'Données du cache',
    total: 'CVE uniques', critical: 'CVE critiques', exploited: 'CVE connues exploitées', coverage: 'Impacts évalués',
    unknown: 'Non évalué', unavailable: 'Non disponible', none: 'Aucun', summary: 'Synthèse pour la décision',
    scopeTitle: 'Périmètre et qualité des preuves', trendTitle: 'Divulgations et gravité', weaknessTitle: 'Faiblesses rapportées et contrôles',
    impactTitle: 'Conséquences potentielles', exposureTitle: 'Exposition et exploitation connue',
    roadmapTitle: 'Priorités sur 30, 60 et 90 jours', technologyTitle: 'Périmètre technologique et preuves',
    methodTitle: 'Méthode, sources et limites', appendixTitle: 'Annexe - avis KEV du périmètre',
    year: 'Année', count: 'CVE', share: 'Part des CVE', severity: 'Gravité', cause: 'Faiblesse rapportée',
    confidentiality: 'Confidentialité', integrity: 'Intégrité', availability: 'Disponibilité',
    s_Critical: 'Critique', s_High: 'Élevée', s_Medium: 'Moyenne', s_Low: 'Faible', s_Unknown: 'Inconnue',
    c_All: 'Toutes les catégories', c_OS: 'Systèmes d’exploitation', c_Application: 'Applications', c_Hardware: 'Matériel', c_Unknown: 'Non classée',
    nvd: 'Fiche NVD', cisa: 'Catalogue CISA', action: 'Mesure requise par CISA', added: 'Ajout KEV', due: 'Échéance fédérale',
    ransomware: 'Usage en rançongiciel rapporté par CISA', notes: 'Notes CISA', references: 'Références publiées',
    noAction: 'Mesure non renseignée dans le cache; consulter CISA et le fournisseur.',
    appendixScope: 'Tous les avis correspondant au périmètre, pour toutes les années couvertes. Cette annexe n’est pas limitée à l’année étudiée.',
    noKev: 'Aucun avis KEV correspondant n’est présent dans ces données. L’absence de KEV ne démontre ni l’absence d’exploitation ni la sécurité du produit.',
    supplemental: 'Complément historique / CISA seulement', supplementalNote: 'Les avis suivants sont hors des comptes NVD du rapport. Leur rattachement est indiqué et doit être confirmé avec l’inventaire et les avis du fournisseur.',
    federal: 'Les échéances CISA affichées s’appliquent aux obligations fédérales américaines concernées; elles ne constituent pas un délai universel pour votre organisation.',
    page: 'Page', continued: 'suite', portfolio: 'Signal Atlas | Données publiques, décisions documentées',
    noDescription: 'Description absente du cache.', loading: 'Préparation du rapport',
  },
  en: {
    report: 'Strategic vulnerability intelligence', executive: 'Executive report',
    subtitle: 'Turn public disclosures into documented decisions.',
    selected: 'Reporting period', allSeverity: 'All severities', comparison: 'Comparison',
    product: 'Product', category: 'Category', publisher: 'Publisher', snapshot: 'Cached data',
    total: 'Unique CVEs', critical: 'Critical CVEs', exploited: 'Known-exploited CVEs', coverage: 'Impact assessed',
    unknown: 'Unassessed', unavailable: 'Unavailable', none: 'None', summary: 'Decision brief',
    scopeTitle: 'Scope and evidence quality', trendTitle: 'Disclosures and severity', weaknessTitle: 'Reported weaknesses and controls',
    impactTitle: 'Potential consequences', exposureTitle: 'Exposure and known exploitation',
    roadmapTitle: '30, 60 and 90-day priorities', technologyTitle: 'Technology scope and evidence',
    methodTitle: 'Method, sources and limitations', appendixTitle: 'Appendix - scoped KEV advisories',
    year: 'Year', count: 'CVEs', share: 'Share of CVEs', severity: 'Severity', cause: 'Reported weakness',
    confidentiality: 'Confidentiality', integrity: 'Integrity', availability: 'Availability',
    s_Critical: 'Critical', s_High: 'High', s_Medium: 'Medium', s_Low: 'Low', s_Unknown: 'Unknown',
    c_All: 'All categories', c_OS: 'Operating systems', c_Application: 'Applications', c_Hardware: 'Hardware', c_Unknown: 'Unclassified',
    nvd: 'NVD record', cisa: 'CISA catalog', action: 'CISA required action', added: 'KEV added', due: 'Federal due date',
    ransomware: 'Ransomware use reported by CISA', notes: 'CISA notes', references: 'Published references',
    noAction: 'No action is present in the cache; consult CISA and the vendor.',
    appendixScope: 'Every matching advisory across all covered years. This appendix is not restricted to the reporting year.',
    noKev: 'No matching KEV advisory is present in this data. Absence from KEV establishes neither absence of exploitation nor product safety.',
    supplemental: 'Historical / CISA-only supplement', supplementalNote: 'The following advisories are outside the report’s NVD counts. Their scope attribution is identified and must be verified against inventory and vendor advisories.',
    federal: 'Displayed CISA due dates apply to the relevant US federal obligations; they are not a universal deadline for your organization.',
    page: 'Page', continued: 'continued', portfolio: 'Signal Atlas | Public data, documented decisions',
    noDescription: 'No description is present in the cache.', loading: 'Preparing the report',
  },
};

let fontPromise;
async function loadFonts() {
  if (!fontPromise) fontPromise = Promise.all(['Regular', 'Bold'].map(async (style) => {
    const response = await fetch(`/fonts/NotoSans-${style}.ttf`, { signal: AbortSignal.timeout(20_000), credentials: 'same-origin' });
    if (!response.ok || Number(response.headers.get('content-length')) > 3_000_000) throw new Error('Report font is unavailable');
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (!bytes.length || bytes.length > 3_000_000) throw new Error('Report font is invalid');
    let binary = '';
    for (let index = 0; index < bytes.length; index += 16384) binary += String.fromCharCode(...bytes.subarray(index, index + 16384));
    return btoa(binary);
  })).catch((error) => { fontPromise = undefined; throw error; });
  return fontPromise;
}

class Layout {
  constructor(doc, model) {
    this.doc = doc; this.model = model; this.t = copy[model.lang]; this.fr = model.lang === 'fr';
    this.margin = 18; this.width = 174; this.bottom = 270; this.y = 38; this.pageTitles = [];
    this.sectionTitle = ''; this.sectionIndex = '';
    this.integer = new Intl.NumberFormat(this.fr ? 'fr-CA' : 'en-CA', { maximumFractionDigits: 0 });
    this.decimal = new Intl.NumberFormat(this.fr ? 'fr-CA' : 'en-CA', { maximumFractionDigits: 1 });
  }
  n(value) { return sanitize(this.integer.format(value ?? 0)); }
  pct(count, total) { const result = percentage(count, total); return result === null ? this.t.unavailable : sanitize(this.decimal.format(result)) + (this.fr ? ' %' : '%'); }
  font(size = 10, bold = false, color = COLORS.ink) { this.doc.setFont('NotoSans', bold ? 'bold' : 'normal'); this.doc.setFontSize(size); this.doc.setTextColor(...color); }
  wrap(value, width = this.width, size = 10, bold = false) { this.font(size, bold); return this.doc.splitTextToSize(sanitize(value), width); }
  date(value) {
    const parsed = new Date(value);
    return value && Number.isFinite(parsed.getTime()) ? sanitize(new Intl.DateTimeFormat(this.fr ? 'fr-CA' : 'en-CA', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' }).format(parsed)) : this.t.unavailable;
  }
  newPage(title = this.sectionTitle) {
    if (this.pageTitles.length) this.doc.addPage();
    this.sectionTitle = title; this.pageTitles.push(title); this.y = 38;
    this.doc.setFillColor(...COLORS.navy); this.doc.rect(0, 0, 210, 3, 'F');
    this.font(10, true, COLORS.navy); this.doc.text('SIGNAL ATLAS', 18, 17);
    const headerName = this.model.subject.kind === 'category' ? this.t[`c_${this.model.subject.id}`] ?? this.model.subject.name : this.model.subject.name;
    this.font(8, false, COLORS.muted); this.doc.text(truncate(headerName, 75), 192, 17, { align: 'right' });
    this.doc.setDrawColor(...COLORS.line); this.doc.line(18, 23, 192, 23);
  }
  ensure(height) {
    if (this.y + height > this.bottom) {
      this.newPage(); this.heading(`${this.sectionIndex} ${this.sectionTitle} (${this.t.continued})`, 16);
      if (this.context) this.heading(`${this.context} (${this.t.continued})`, 10);
    }
  }
  section(index, title, intro) {
    this.sectionIndex = String(index).padStart(2, '0'); this.newPage(title);
    this.font(8, true, COLORS.blue); this.doc.text(this.sectionIndex, 18, this.y); this.y += 9;
    this.heading(title, 22);
    if (intro) this.paragraph(intro, { color: COLORS.muted, size: 10.5 });
    this.y += 3;
  }
  heading(value, size = 13) {
    const lines = this.wrap(value, this.width, size, true), height = lines.length * size * 0.42 + 4;
    this.ensure(height); this.font(size, true, COLORS.navy); this.doc.text(lines, this.margin, this.y, { lineHeightFactor: 1.18 }); this.y += height;
  }
  paragraph(value, { size = 10, color = COLORS.ink, gap = 4, bold = false, keepNext = 0 } = {}) {
    const lines = this.wrap(value, this.width, size, bold), lineHeight = size * 0.45;
    for (const [index, line] of lines.entries()) {
      const remaining = lines.length - index;
      this.ensure(remaining <= 3 ? remaining * lineHeight + gap + keepNext : lineHeight + 1);
      this.font(size, bold, color); this.doc.text(line, this.margin, this.y); this.y += lineHeight;
    }
    this.y += gap;
  }
  paragraphHeight(value, size = 10, gap = 4, bold = false) { return this.wrap(value, this.width, size, bold).length * size * 0.45 + gap; }
  bullet(value) {
    const lines = this.wrap(value, this.width - 7, 10);
    this.ensure(Math.min(lines.length, 4) * 4.5 + 5);
    this.font(10, true, COLORS.blue); this.doc.text('-', 18, this.y);
    for (const line of lines) { this.ensure(5); this.font(10); this.doc.text(line, 25, this.y); this.y += 4.5; }
    this.y += 4;
  }
  callout(title, value) {
    const titleLines = this.wrap(title, this.width - 12, 10, true), bodyLines = this.wrap(value, this.width - 12, 9.5);
    const height = titleLines.length * 4.7 + bodyLines.length * 4.4 + 13;
    if (height > 190) { this.heading(title); this.paragraph(value); return; }
    this.ensure(height + 5); this.doc.setFillColor(...COLORS.pale); this.doc.roundedRect(18, this.y - 3, this.width, height, 2, 2, 'F');
    this.doc.setFillColor(...COLORS.blue); this.doc.rect(18, this.y - 3, 1, height, 'F');
    this.font(10, true, COLORS.navy); this.doc.text(titleLines, 24, this.y + 3, { lineHeightFactor: 1.25 });
    this.font(9.5); this.doc.text(bodyLines, 24, this.y + 3 + titleLines.length * 4.7 + 3, { lineHeightFactor: 1.3 });
    this.y += height + 5;
  }
  table(headers, rows, widths, { size = 9, repeat = true, padding = 6 } = {}) {
    const startX = 18, lineHeight = size * 0.45;
    const drawHeader = () => {
      this.ensure(12); this.doc.setFillColor(...COLORS.navy); this.doc.rect(startX, this.y - 3, this.width, 11, 'F');
      let x = startX;
      headers.forEach((header, index) => { this.font(8, true, COLORS.white); this.doc.text(truncate(header, 42), x + 3, this.y + 3); x += widths[index]; });
      this.y += 13;
    };
    drawHeader();
    rows.forEach((row, rowIndex) => {
      const cells = row.map((value, index) => this.wrap(value, widths[index] - 6, size));
      const height = Math.max(...cells.map((cell) => cell.length), 1) * lineHeight + padding;
      if (this.y + height > this.bottom) { this.newPage(); this.heading(`${this.sectionIndex} ${this.sectionTitle} (${this.t.continued})`, 16); if (repeat) drawHeader(); }
      if (rowIndex % 2 === 0) { this.doc.setFillColor(...COLORS.pale); this.doc.rect(startX, this.y - 3, this.width, height, 'F'); }
      let x = startX;
      cells.forEach((cell, index) => { this.font(size, index === 0); this.doc.text(cell, x + 3, this.y + 1, { lineHeightFactor: 1.27 }); x += widths[index]; });
      this.y += height;
    }); this.y += 5;
  }
  bars(items, total, maxLabelWidth = 53, spacing = 15) {
    for (const item of items) {
      this.ensure(spacing + 2); const y = this.y;
      this.font(9, true); this.doc.text(truncate(item.label, 32), 18, y);
      this.doc.setFillColor(...COLORS.pale); this.doc.roundedRect(18 + maxLabelWidth, y - 3, 81, 5, 1, 1, 'F');
      if (total > 0 && item.count > 0) { this.doc.setFillColor(...COLORS.blue); this.doc.roundedRect(18 + maxLabelWidth, y - 3, 81 * Math.min(1, item.count / total), 5, 1, 1, 'F'); }
      this.font(9); this.doc.text(`${this.n(item.count)} | ${this.pct(item.count, total)}`, 192, y, { align: 'right' }); this.y += spacing;
    }
  }
  linked(label, url) {
    const safe = safeReference(url); if (!safe) return;
    const lines = this.wrap(label, this.width, 8.5);
    for (const line of lines) { this.ensure(5); this.font(8.5, false, COLORS.blue); this.doc.textWithLink(line, 18, this.y, { url: safe }); this.y += 4.5; }
    this.y += 2;
  }
  footer() {
    const total = this.doc.getNumberOfPages();
    for (let page = 1; page <= total; page += 1) {
      this.doc.setPage(page); this.doc.setDrawColor(...COLORS.line); this.doc.line(18, 279, 192, 279);
      this.font(7.5, false, COLORS.muted); this.doc.text(this.t.portfolio, 18, 285);
      this.doc.text(`${this.t.page} ${page} / ${total}`, 192, 285, { align: 'right' });
      this.font(6.8, false, COLORS.muted); this.doc.text(`${this.t.snapshot}: ${this.date(this.model.generatedAt)} | ${this.model.year} | ${this.t.allSeverity}`, 18, 290);
    }
  }
}

function periodText(p, precise = false) {
  const m = p.model;
  if (m.matched) {
    const anchor = new Date(`${m.window.partialYear}-${m.window.endMonthDay}T00:00:00Z`);
    const cutoffDate = Number.isFinite(anchor.getTime()) ? sanitize(new Intl.DateTimeFormat(p.fr ? 'fr-CA' : 'en-CA', { month: 'long', day: 'numeric', timeZone: 'UTC' }).format(anchor)) : m.window.endMonthDay;
    const cutoffTime = String(m.window.endTime ?? '').replace(/Z$/, '').split('.')[0];
    const time = precise ? (p.fr ? `, à ${cutoffTime} UTC` : `, at ${cutoffTime} UTC`) : '';
    return p.fr ? `Du 1er janvier au ${cutoffDate}${time}, pour chaque année.` : `January 1 through ${cutoffDate}${time}, in every year.`;
  }
  return p.fr ? `Années de publication complètes; la couverture du cache se termine le ${p.date(m.coverage.end)}.` :
    `Full publication years; cached coverage ends ${p.date(m.coverage.end)}.`;
}

function comparisonText(p) {
  const m = p.model;
  if (!m.comparable) return p.fr ? 'La variation n’est pas calculable: période de comparaison absente, identique ou non alignable.' :
    'Change cannot be calculated: the comparison period is absent, identical or cannot be aligned.';
  if (m.previousTotal === 0) return p.fr ? `${p.n(m.total)} CVE contre aucune en ${m.comparison}; aucun pourcentage de variation n’est défini sur une base nulle.` :
    `${p.n(m.total)} CVEs versus none in ${m.comparison}; percentage change is undefined from a zero baseline.`;
  const change = sanitize(p.decimal.format(m.changePercent));
  return p.fr ? `${p.n(m.total)} CVE contre ${p.n(m.previousTotal)} en ${m.comparison}: ${m.difference >= 0 ? '+' : ''}${p.n(m.difference)} (${m.changePercent >= 0 ? '+' : ''}${change} %).` :
    `${p.n(m.total)} CVEs versus ${p.n(m.previousTotal)} in ${m.comparison}: ${m.difference >= 0 ? '+' : ''}${p.n(m.difference)} (${m.changePercent >= 0 ? '+' : ''}${change}%).`;
}

function cover(p) {
  const m = p.model, t = p.t; p.newPage(t.executive);
  p.font(9, true, COLORS.blue); p.doc.text(t.executive.toUpperCase(), 18, 42); p.y = 59;
  p.heading(t.report, 28); p.y += 4;
  p.heading(m.subject.kind === 'category' ? t[`c_${m.subject.id}`] ?? m.subject.name : m.subject.name, 22);
  p.paragraph(t.subtitle, { size: 12, color: COLORS.muted });
  p.paragraph(`${t.selected}: ${m.year} | ${t.comparison}: ${m.comparison} | ${t.allSeverity}`, { size: 10, bold: true });
  if (m.subject.vendor) p.paragraph(`${t.publisher}: ${m.subject.vendor}`, { size: 10, color: COLORS.muted });
  p.paragraph(periodText(p), { size: 9, color: COLORS.muted }); p.y += 3;
  const cards = [[t.total, p.n(m.total)], [t.critical, p.n(m.critical)], [t.exploited, p.n(m.kev)], [t.coverage, p.pct(m.impactKnown, m.total)]];
  p.ensure(32); const cardWidth = (p.width - 9) / 4;
  cards.forEach(([label, value], index) => {
    const x = 18 + index * (cardWidth + 3); p.doc.setFillColor(...COLORS.pale); p.doc.roundedRect(x, p.y, cardWidth, 28, 2, 2, 'F');
    p.font(8, true, COLORS.muted); p.doc.text(p.wrap(label, cardWidth - 8, 8, true), x + 4, p.y + 7);
    p.font(18, true, COLORS.navy);
    const valueSize = Math.min(18, 18 * (cardWidth - 8) / Math.max(1, p.doc.getTextWidth(value)));
    p.font(valueSize, true, COLORS.navy); p.doc.text(value, x + 4, p.y + 23);
  }); p.y += 40; p.heading(t.summary, 15);
  p.bullet(comparisonText(p));
  p.bullet(p.fr ? `${p.n(m.kev)} CVE de la période sont inscrites à KEV. Vérifier les versions déployées avant de décider d’une correction; KEV confirme une exploitation connue, pas un incident dans votre organisation.` :
    `${p.n(m.kev)} period CVEs are in KEV. Check deployed versions before deciding remediation; KEV confirms known exploitation, not an incident in your organization.`);
  if (m.weaknesses.length) p.bullet(p.fr ? `${m.weaknesses[0].id} est la principale faiblesse rapportée (${p.n(m.weaknesses[0].count)} CVE, ${p.pct(m.weaknesses[0].count, m.total)} du périmètre). Utiliser ce signal pour cibler les contrôles, sans l’assimiler à une cause d’incident observé.` :
    `${m.weaknesses[0].id} leads reported weaknesses (${p.n(m.weaknesses[0].count)} CVEs, ${p.pct(m.weaknesses[0].count, m.total)} of scope). Use this signal to target controls, without treating it as an observed incident cause.`);
  else p.bullet(p.fr ? 'Aucune faiblesse classifiée n’est disponible pour cette période. Le rapport ne déduit pas de cause depuis le score ou la description.' :
    'No classified weakness is available for this period. This report does not infer a cause from a score or description.');
  p.paragraph(p.fr ? `Qualité des preuves: ${p.n(m.missingImpact)} CVE sans évaluation complète des impacts et ${p.n(m.missingCause)} sans faiblesse rapportée. Aucune mesure de perte réelle ou de probabilité d’attaque n’est calculée.` :
    `Evidence quality: ${p.n(m.missingImpact)} CVEs lack complete impact assessment and ${p.n(m.missingCause)} lack a reported weakness. No actual-loss or attack-probability measure is calculated.`, { size: 9, color: COLORS.muted });
}

function scope(p) {
  const m = p.model; p.section(1, p.t.scopeTitle, p.fr ? 'Les dénominateurs et les limites font partie de la conclusion.' : 'Denominators and limitations are part of the conclusion.');
  p.heading(p.fr ? 'Ce que couvre le rapport' : 'What this report covers');
  p.paragraph(p.fr ? `${p.n(m.total)} CVE uniques pour ${m.year}, rattachées au ${m.subject.kind === 'product' ? 'produit sélectionné' : 'périmètre de catégorie sélectionné'}. Toutes les gravités sont incluses, indépendamment des filtres du tableau de bord. Les dates de publication NVD déterminent les années, qui peuvent différer de l’année de l’identifiant CVE. Les CVE rejetées sont exclues.` :
    `${p.n(m.total)} unique CVEs for ${m.year}, attributed to the selected ${m.subject.kind === 'product' ? 'product' : 'category scope'}. All severities are included regardless of dashboard filters. NVD publication dates determine years, which may differ from CVE identifier years. Rejected CVEs are excluded.`);
  p.paragraph(periodText(p, true));
  const rows = [
    [p.fr ? 'Score de gravité disponible' : 'Severity score available', p.n(Math.max(0, m.total - m.severity.find((s) => s.id === 'Unknown').count)), p.pct(Math.max(0, m.total - m.severity.find((s) => s.id === 'Unknown').count), m.total)],
    [p.fr ? 'Faiblesse CWE rapportée' : 'Reported CWE weakness', p.n(m.causeKnown), p.pct(m.causeKnown, m.total)],
    [p.fr ? 'Impacts CVSS complets' : 'Complete CVSS impacts', p.n(m.impactKnown), p.pct(m.impactKnown, m.total)],
    [p.fr ? 'Portée et privilèges évalués' : 'Reach and privileges assessed', p.n(m.reachKnown), p.pct(m.reachKnown, m.total)],
  ]; p.table([p.fr ? 'Preuve disponible' : 'Available evidence', p.t.count, p.t.share], rows, [105, 27, 42]);
  p.callout(p.fr ? 'Interpréter les données manquantes' : 'Interpret missing evidence', p.fr ? 'Un score absent, une faiblesse non classifiée ou un vecteur incomplet reste inconnu. Ces absences ne signifient pas une faible gravité. Les parts utilisent toutes les CVE du périmètre; les mesures conditionnelles utilisent uniquement les CVE évaluées et indiquent ce dénominateur.' :
    'A missing score, unclassified weakness or incomplete vector remains unknown. These gaps do not imply low severity. Scope shares use all CVEs; conditional measures use only assessed CVEs and identify that denominator.');
  if (m.classification) {
    p.heading(p.fr ? 'Confiance dans le rattachement' : 'Attribution confidence');
    p.paragraph(p.fr ? `Pour cette année/période: ${p.n(m.classification.authoritative)} CVE classées selon des CPE publiées, ${p.n(m.classification.inferred)} selon une inférence étayée, ${p.n(m.classification.unresolved)} entièrement non classées. Un rattachement inféré peut évoluer après l’enrichissement NVD. Un produit ou une CVE peut toucher plusieurs catégories.` :
      `For this year/period: ${p.n(m.classification.authoritative)} CVEs classified using published CPEs, ${p.n(m.classification.inferred)} using supported inference, ${p.n(m.classification.unresolved)} entirely unresolved. Inferred attribution may change after NVD enrichment. A product or CVE can affect multiple categories.`);
  }
  p.heading(p.fr ? 'Fraîcheur et provenance' : 'Freshness and provenance');
  p.paragraph(`${p.t.snapshot}: ${p.date(m.generatedAt)}. NVD: ${p.date(m.coverage.nvdLastSync)}. CISA KEV: ${p.date(m.coverage.kevLastSync)}.`, { size: 9 });
  p.paragraph(p.fr ? 'Il s’agit d’un instantané: les corrections, évaluations et inscriptions KEV peuvent changer après la date du cache. Les avis des fournisseurs et votre inventaire font autorité pour l’applicabilité opérationnelle.' :
    'This is a snapshot: fixes, assessments and KEV membership may change after the cache date. Vendor advisories and your inventory determine operational applicability.', { color: COLORS.muted });
}

function trends(p) {
  const m = p.model; p.section(2, p.t.trendTitle, periodText(p));
  p.table([p.t.year, p.t.total, p.t.critical, 'KEV'], m.historical.map((item) => [String(item.year) + (item.partial && !m.matched ? '*' : ''), item.available ? p.n(item.total) : p.t.unavailable, item.available ? p.n(item.critical) : p.t.unavailable, item.available ? p.n(item.kev) : p.t.unavailable]), [32, 54, 49, 39], { size: 8.5, padding: 4 });
  p.callout(p.fr ? 'Variation observée' : 'Observed change', comparisonText(p));
  p.heading(`${p.t.severity} | ${m.year}`);
  p.bars(m.severity.map((item) => ({ label: p.t[`s_${item.id}`], count: item.count })), m.total, 53, 10);
  p.paragraph(p.fr ? 'Les scores de base CVSS décrivent une gravité technique. Le volume de divulgations reflète aussi la couverture, la maturité de divulgation, le nombre de produits et l’enrichissement. Ni le volume ni le nombre de CVE critiques n’est un score de sécurité du fournisseur.' :
    'CVSS base scores describe technical severity. Disclosure volume also reflects coverage, disclosure maturity, product breadth and enrichment. Neither volume nor critical-CVE count is a vendor security score.', { size: 9, color: COLORS.muted });
  if (!m.matched && m.window) p.paragraph(p.fr ? `* ${m.window.partialYear} reste partielle. Les totaux complets et partiels ne doivent pas être comparés directement.` :
    `* ${m.window.partialYear} remains partial. Complete and partial totals should not be compared directly.`, { size: 9, color: COLORS.muted });
}

function weaknesses(p) {
  const m = p.model; p.section(3, p.t.weaknessTitle, p.fr ? 'Des causes rapportées aux contrôles à vérifier.' : 'From reported causes to controls worth validating.');
  p.paragraph(p.fr ? `Une faiblesse est disponible pour ${p.n(m.causeKnown)} CVE sur ${p.n(m.total)} (${p.pct(m.causeKnown, m.total)}). ${p.n(m.missingCause)} restent sans classification. Une CVE peut recevoir plusieurs CWE; les lignes se chevauchent.` :
    `A weakness is available for ${p.n(m.causeKnown)} of ${p.n(m.total)} CVEs (${p.pct(m.causeKnown, m.total)}). ${p.n(m.missingCause)} remain unclassified. A CVE can have several CWEs; rows overlap.`);
  const top = m.weaknesses.slice(0, 10);
  if (top.length) p.table([p.t.cause, p.t.count, p.t.share], top.map((item) => [`${item.id} - ${item.name}`, p.n(item.count), p.pct(item.count, m.total)]), [115, 23, 36], { size: 8, padding: 4 });
  else p.callout(p.fr ? 'Aucun motif classifié disponible' : 'No classified pattern available', p.fr ? 'Le rapport ne substitue pas des suppositions aux CWE absentes. Demander des évaluations au fournisseur et compléter le suivi de l’enrichissement.' :
    'This report does not replace absent CWEs with guesses. Request vendor assessments and monitor enrichment.');
  if (top.length) {
    p.heading(p.fr ? 'Contrôles candidats' : 'Candidate controls');
    for (const item of top.slice(0, 3)) p.bullet(`${item.id}: ${controlForWeakness(item.id, m.lang)}`);
  }
  p.paragraph(p.fr ? 'Ces associations de contrôle sont des pistes conditionnelles de prévention et de validation. Elles ne prouvent pas la cause d’un incident et ne remplacent pas les instructions du fournisseur. Les intitulés CWE sont les noms MITRE publiés, conservés dans leur langue source.' :
    'These control mappings are conditional prevention and validation options. They do not establish an incident cause or replace vendor instructions. CWE titles are published MITRE names retained in their source language.', { size: 9, color: COLORS.muted });
}

function impacts(p) {
  const m = p.model; p.section(4, p.t.impactTitle, p.fr ? 'Conséquences techniques possibles; aucune perte réelle n’est déduite.' : 'Possible technical consequences; no actual loss is inferred.');
  p.paragraph(p.fr ? `Les impacts CVSS sont évalués pour ${p.n(m.impactKnown)} CVE sur ${p.n(m.total)} (${p.pct(m.impactKnown, m.total)}). Les ${p.n(m.missingImpact)} autres restent inconnues. Les comptes ci-dessous incluent tout impact non nul et peuvent se chevaucher.` :
    `CVSS impacts are assessed for ${p.n(m.impactKnown)} of ${p.n(m.total)} CVEs (${p.pct(m.impactKnown, m.total)}). The other ${p.n(m.missingImpact)} remain unknown. Counts below include any non-zero impact and can overlap.`);
  p.bars(m.impacts.map((item) => ({ label: p.t[item.id], count: item.count })), m.total);
  const business = {
    confidentiality: [p.fr ? 'Données et secrets' : 'Data and secrets', p.fr ? 'Si une version touchée traite des données sensibles, une exposition de données ou de secrets peut être possible. Cartographier les données, réduire les accès et préparer les procédures de rotation selon l’avis applicable.' : 'If an affected version handles sensitive data, data or secret exposure may be possible. Map data, reduce access and prepare rotation procedures according to the applicable advisory.'],
    integrity: [p.fr ? 'Transactions et confiance' : 'Transactions and trust', p.fr ? 'Si une version touchée participe à une chaîne de traitement, une modification non autorisée peut affecter les résultats ou les configurations. Vérifier les autorisations, l’intégrité des artefacts et la capacité d’audit.' : 'If an affected version is part of a processing chain, unauthorized modification may affect outputs or configuration. Verify authorization, artifact integrity and auditability.'],
    availability: [p.fr ? 'Continuité des services' : 'Service continuity', p.fr ? 'Si le composant est essentiel au service, une interruption ou une saturation peut affecter les opérations. Tester la reprise, l’isolation, les limites de ressources et les possibilités de contournement validées par le fournisseur.' : 'If the component is essential to a service, interruption or saturation may affect operations. Test recovery, isolation, resource limits and vendor-approved workarounds.'],
  };
  for (const item of m.impacts) {
    const [title, body] = business[item.id];
    p.heading(`${title} | ${p.n(item.count)} CVE`);
    if (!item.count) p.paragraph(m.impactKnown ? (p.fr ? 'Aucun impact non nul de ce type n’est rapporté dans les CVE évaluées. Les autres évaluations manquent.' :
      'No non-zero impact of this type is reported among assessed CVEs. Other assessments are missing.') :
      (p.fr ? 'Aucune évaluation de ce type n’est disponible; une conclusion sur cet impact n’est pas possible.' : 'No assessment of this type is available; no impact conclusion is possible.'), { size: 9, color: COLORS.muted });
    else p.paragraph(body, { size: 9.5 });
  }
  p.callout(p.fr ? 'Ce qu’il faut pour estimer l’impact organisationnel' : 'What organizational impact estimation needs', p.fr ? 'Inventaire des versions et dépendances, exposition réelle, données traitées, criticité métier, protections existantes et résultats de validation. Ces éléments ne figurent pas dans les sources publiques du rapport.' :
    'Version and dependency inventory, actual exposure, handled data, business criticality, existing protections and validation results. These inputs are not present in this report’s public sources.');
}

function exposure(p) {
  const m = p.model; p.section(5, p.t.exposureTitle, p.fr ? 'Distinguer une possibilité technique d’une exploitation publiquement attestée.' : 'Distinguish technical possibility from publicly established exploitation.');
  p.heading(p.fr ? 'Portée réseau sans privilèges' : 'Network reach with no privileges');
  p.paragraph(p.fr ? `${p.n(m.remote)} CVE présentent un vecteur réseau sans privilèges requis: ${p.pct(m.remote, m.total)} de toutes les CVE, ou ${p.pct(m.remote, m.reachKnown)} des ${p.n(m.reachKnown)} évaluées pour la portée et l’authentification. ${p.n(m.missingReach)} restent non évaluées. Une interaction utilisateur, d’autres conditions ou une configuration particulière peuvent être nécessaires.` :
    `${p.n(m.remote)} CVEs have a network vector with no privileges required: ${p.pct(m.remote, m.total)} of all CVEs, or ${p.pct(m.remote, m.reachKnown)} of the ${p.n(m.reachKnown)} assessed for reach and authentication. ${p.n(m.missingReach)} remain unassessed. User interaction, other conditions or a particular configuration may still be required.`);
  p.heading(p.fr ? 'Exploitation connue selon CISA' : 'Known exploitation according to CISA');
  p.paragraph(p.fr ? `${p.n(m.kev)} CVE publiées dans la période étudiée figurent à KEV (${p.pct(m.kev, m.total)} du périmètre). Le paquet contient ${p.n(m.relatedKev.length)} avis liés au périmètre dans toutes les années NVD couvertes et ${p.n(m.supplementalKev.length)} avis historiques ou CISA seulement, présentés séparément en annexe.` :
    `${p.n(m.kev)} CVEs published in the reporting period are in KEV (${p.pct(m.kev, m.total)} of scope). The pack contains ${p.n(m.relatedKev.length)} scoped advisories across all covered NVD years and ${p.n(m.supplementalKev.length)} historical or CISA-only advisories, listed separately in the appendix.`);
  p.callout(p.fr ? 'Priorité basée sur l’applicabilité' : 'Applicability-based priority', m.kev > 0 ? (p.fr ? 'Pour les versions effectivement touchées, traiter les avis KEV avant les comparaisons de volume. Vérifier l’exposition, l’exploitabilité locale et les mesures du fournisseur, puis documenter les correctifs ou compensations validés.' :
    'For actually affected versions, address KEV advisories before volume comparisons. Verify exposure, local exploitability and vendor measures, then document validated fixes or compensating controls.') : p.t.noKev);
  p.heading(p.fr ? 'Décisions à documenter' : 'Decisions to document');
  p.bullet(p.fr ? 'Responsable de service: confirmer les actifs et versions touchés, y compris les dépendances embarquées.' : 'Service owner: confirm affected assets and versions, including embedded dependencies.');
  p.bullet(p.fr ? 'Équipe sécurité: vérifier les voies d’accès et les journaux pertinents, selon les indicateurs fournis par les avis.' : 'Security team: verify access paths and relevant logs, using indicators supplied by advisories.');
  p.bullet(p.fr ? 'Responsable du changement: tester la correction et sa compatibilité, avec preuve de déploiement et plan de retour arrière.' : 'Change owner: test remediation and compatibility, with deployment evidence and a rollback plan.');
  p.paragraph(p.t.federal, { size: 9, color: COLORS.muted });
  p.paragraph(p.fr ? 'Aucun acteur, campagne, délai d’exploitation, score EPSS ou incident local n’est attribué sans source correspondante. La mention de rançongiciel en annexe reproduit uniquement le champ CISA.' :
    'No actor, campaign, exploitation timeline, EPSS score or local incident is attributed without a corresponding source. Appendix ransomware statements reproduce only the CISA field.', { size: 9, color: COLORS.muted });
}

function roadmap(p) {
  const m = p.model; p.section(6, p.t.roadmapTitle, p.fr ? 'Horizons de planification proposés, à adapter aux obligations et à la criticité réelles.' : 'Suggested planning horizons, to adapt to actual obligations and criticality.');
  p.paragraph(p.fr ? 'Ces horizons ne sont pas des délais de correction et ne justifient pas de reporter une action urgente ou une obligation applicable.' :
    'These horizons are not remediation deadlines and do not justify postponing an urgent action or applicable obligation.', { size: 9, color: COLORS.muted });
  const phases = p.fr ? [
    ['0-30 jours | Établir l’applicabilité', 'Propriétaires des services + gestion des vulnérabilités',
      `Rapprocher l’inventaire des versions des ${p.n(m.relatedKev.length)} avis KEV couverts. Identifier les actifs exposés et les services critiques. Appliquer les correctifs ou mesures validés pour les avis pertinents; consigner les exceptions et leurs approbateurs.`,
      'Validation: registre des actifs concernés avec propriétaire, version, état du correctif et preuve de contrôle; aucune exception sans justification documentée.'],
    ['31-60 jours | Renforcer les contrôles', 'Ingénierie + équipes sécurité',
      'Vérifier les contrôles liés aux faiblesses dominantes, réduire les accès inutiles et vérifier les dépendances. Tester les correctifs, la segmentation et la capacité de reprise dans les services concernés.',
      'Validation: résultats de tests et preuves de déploiement; liste des lacunes restantes, avec responsable et décision de traitement.'],
    ['61-90 jours | Mesurer et pérenniser', 'Direction technologique + gouvernance',
      'Intégrer les avis et l’évolution des évaluations au suivi régulier. Relier les versions au cycle de support et au plan de modernisation. Réexaminer les exceptions avec la criticité métier et les protections constatées.',
      'Validation: indicateurs définis avec dénominateur stable (actifs évalués, avis applicables traités, exceptions en cours); tests de reprise et décisions de financement documentés.'],
  ] : [
    ['0-30 days | Establish applicability', 'Service owners + vulnerability management',
      `Match version inventory to the ${p.n(m.relatedKev.length)} covered KEV advisories. Identify exposed assets and critical services. Apply validated fixes or measures for applicable advisories; record exceptions and approvers.`,
      'Validation: affected-asset register with owner, version, remediation status and control evidence; no exception without documented justification.'],
    ['31-60 days | Strengthen controls', 'Engineering + security teams',
      'Verify controls linked to leading weaknesses, reduce unnecessary access and check dependencies. Test fixes, segmentation and recovery in affected services.',
      'Validation: test results and deployment evidence; remaining-gap register with an owner and treatment decision.'],
    ['61-90 days | Measure and sustain', 'Technology leadership + governance',
      'Bring advisories and assessment changes into recurring review. Link versions to support lifecycle and modernization plans. Revisit exceptions against business criticality and verified protections.',
      'Validation: measures with stable denominators (assessed assets, treated applicable advisories, open exceptions); documented recovery tests and funding decisions.'],
  ];
  phases.forEach(([title, owner, action, validation]) => {
    p.heading(title, 13); p.paragraph(owner, { size: 8.5, gap: 2, bold: true, color: COLORS.blue }); p.paragraph(action, { size: 9.5, gap: 2 }); p.paragraph(validation, { size: 8.5, gap: 2, color: COLORS.muted }); p.y += 2;
  });
  p.callout(p.fr ? 'Arbitrages de direction' : 'Leadership decisions', p.fr ? 'Attribuer les propriétaires, les fenêtres de changement et les ressources de validation. Financer la réduction des dépendances non supportées si l’inventaire la confirme. Accepter une exception uniquement avec un périmètre, des preuves et une date de réexamen définis par l’organisation.' :
    'Assign owners, change windows and validation resources. Fund reduction of unsupported dependencies when inventory confirms them. Accept an exception only with scope, evidence and an organization-defined review date.');
}

function categoryProducts(m) {
  const collection = m.matched ? m.pack.topProductsThrough : m.topProducts;
  if (!collection) return [];
  if (Array.isArray(collection)) {
    const entry = collection.find((item) => Number(item.year) === m.year);
    return m.matched ? entry?.through ?? entry?.products ?? [] : entry?.products ?? entry?.items ?? [];
  }
  const entry = collection[String(m.year)] ?? collection.years?.[String(m.year)];
  if (Array.isArray(entry)) return entry;
  return m.matched ? entry?.through ?? entry?.products ?? [] : entry?.products ?? entry?.items ?? [];
}

function technology(p) {
  const m = p.model; p.section(7, p.t.technologyTitle, p.fr ? 'Relier les données publiques à une enquête sur les versions et les services.' : 'Connect public evidence to a version and service investigation.');
  if (m.subject.kind === 'category') {
    const products = categoryProducts(m).slice(0, 10);
    p.heading(p.fr ? 'Produits les plus représentés dans la période' : 'Most represented products in the period');
    if (products.length) p.table([p.t.product, p.t.publisher, p.t.count], products.map((item) => [item.name ?? item.product ?? '', item.vendor ?? '', p.n(item.total ?? item.count ?? item.stats?.total)]), [90, 56, 28], { size: 8.5 });
    else p.paragraph(p.fr ? 'Aucun classement de produits n’est disponible pour ce périmètre et cette période.' : 'No product ranking is available for this scope and period.');
    p.paragraph(p.fr ? 'Classement calculé avant le plafonnement des classements de la page d’accueil. Les produits peuvent partager des CVE: les comptes ne s’additionnent pas en un total de catégorie et ne mesurent pas la taille installée ou la sécurité.' :
      'Ranking is calculated before home-page ranking caps. Products can share CVEs: counts do not add up to a category total and measure neither installed base nor security.', { size: 9, color: COLORS.muted });
  } else {
    p.heading(p.fr ? 'Questions de périmètre produit' : 'Product scope questions');
    p.bullet(p.fr ? 'Quelles versions et quels modules sont présents? Les composants embarqués et les dépendances transitives sont-ils inventoriés?' : 'Which versions and modules are present? Are embedded components and transitive dependencies inventoried?');
    p.bullet(p.fr ? 'Quels services utilisent le produit et quelles protections sont effectivement actives? Le chemin réseau décrit par le CVSS existe-t-il localement?' : 'Which services use the product and which protections are active? Does the CVSS network path exist locally?');
    p.bullet(p.fr ? 'Le correctif et les mesures provisoires couvrent-ils votre configuration? La version déployée est-elle encore supportée?' : 'Does the fix or workaround cover your configuration? Is the deployed version still supported?');
  }
  p.heading(p.fr ? 'Exemples de CVE pour approfondir' : 'Example CVEs for further investigation');
  p.paragraph(p.fr ? `${p.n(m.examples.length)} exemples non-KEV, au plus 10, sont fournis par le cache pour toutes les années couvertes. Ils illustrent les preuves; ils ne représentent ni l’ensemble des CVE ni une priorité fondée sur votre inventaire. Tous les avis KEV suivent en annexe.` :
    `${p.n(m.examples.length)} non-KEV examples, up to 10, are supplied by the cache across all covered years. They illustrate evidence; they represent neither all CVEs nor inventory-based priority. Every KEV advisory follows in the appendix.`, { size: 9 });
  p.paragraph(p.fr ? 'Les faits agrégés et tous les identifiants KEV du périmètre sont conservés. Les descriptions NVD sont plafonnées à 5 000 caractères, les produits à 20 et les références à 30 par CVE, avec les comptes originaux. Les exemples affichent un extrait de 430 caractères. Les mesures CISA ne sont pas tronquées. Les sources conservent leur langue originale.' :
    'Aggregate facts and every scoped KEV identifier are preserved. NVD descriptions are capped at 5,000 characters, products at 20 and references at 30 per CVE, with original counts retained. Examples show a 430-character extract. CISA actions are not truncated. Sources retain their original language.', { size: 8.5, color: COLORS.muted });
  if (!m.examples.length) p.paragraph(p.fr ? 'Aucun exemple supplémentaire disponible.' : 'No additional example is available.');
  for (const record of m.examples) {
    const title = `${cveIdentifier(record)} | ${p.t[`s_${record.severity}`] ?? p.t.unknown} | CVSS ${record.score ?? p.t.unknown}`;
    const metadata = `${p.t.year}: ${p.date(record.published)}. CWE: ${(record.weaknesses ?? []).join(', ') || p.t.unavailable}.`;
    const extract = truncate(record.description || p.t.noDescription, 430);
    const height = p.wrap(title, p.width, 10, true).length * 4.2 + 4 + p.paragraphHeight(metadata, 8.5) + p.paragraphHeight(extract, 9) + 9;
    p.ensure(height); p.heading(title, 10);
    p.paragraph(metadata, { size: 8.5, color: COLORS.muted });
    // Complete descriptions are available at the linked NVD record; example
    // extracts are explicitly bounded, unlike the uncapped KEV action appendix.
    p.paragraph(extract, { size: 9, keepNext: 8 });
    p.linked(p.t.nvd, `https://nvd.nist.gov/vuln/detail/${cveIdentifier(record)}`);
  }
}

function methodology(p) {
  const m = p.model; p.section(8, p.t.methodTitle, p.fr ? 'Une analyse déterministe des données du cache, sans modèle génératif ni service externe.' : 'A deterministic analysis of cached data, with no generative model or external service.');
  const paragraphs = p.fr ? [
    'Unités: une CVE unique dans le périmètre par période de publication. Les gravités suivent les scores de base disponibles, en privilégiant CVSS 4.0, puis 3.1, 3.0 et 2.0 selon la collecte. Un score inconnu reste distinct; il n’est jamais égal à zéro.',
    'Faiblesses: les CWE valides et publiées sont dédupliquées par CVE. Leur comptage décrit des classifications rapportées, pas des causes d’incident établies. Les intitulés sont issus de MITRE CWE.',
    'Impacts: CVSS v2/v3 utilise C, I et A; v4 utilise les impacts des systèmes vulnérables et subséquents. Toute valeur non nulle peut contribuer. Un vecteur incomplet ou malformé reste inconnu. Les catégories d’impact peuvent se chevaucher.',
    'Portée: le signal réseau sans privilèges exige AV:N et PR:N (v3/v4), ou AV:N et Au:N (v2). Il ne déduit ni facilité d’exploitation, ni absence d’interaction utilisateur, ni exposition réelle.',
    'KEV: la correspondance utilise les identifiants CVE du catalogue CISA en cache. L’année statistique reste l’année de publication NVD, et non la date d’ajout à KEV. Les compléments historiques ou CISA seulement restent séparés des comptes NVD.',
    'Catégories et attribution: les CPE vulnérables priment. Des produits CNA explicitement touchés, des correspondances exactes, des collections de paquets et des règles conservatrices peuvent étayer une inférence. Les catégories incertaines restent non classées. Une plateforme d’exécution ne suffit pas à définir le type du produit vulnérable.',
    'Comparaison: lorsqu’une des années sélectionnées est partielle, le même jour, mois et instant UTC sont appliqués à chaque année. Le 29 février est ramené au 28 février si nécessaire. Une base nulle produit une différence absolue, jamais un pourcentage infini.',
  ] : [
    'Units: one unique scoped CVE per publication period. Severity follows available base scores, preferring CVSS 4.0, then 3.1, 3.0 and 2.0 under the collection rules. Unknown scores stay separate and are never treated as zero.',
    'Weaknesses: valid published CWEs are deduplicated per CVE. Their counts describe reported classifications, not established incident causes. Names come from MITRE CWE.',
    'Impacts: CVSS v2/v3 uses C, I and A; v4 uses vulnerable- and subsequent-system impacts. Any non-zero value can contribute. Incomplete or malformed vectors remain unknown. Impact categories can overlap.',
    'Reach: the network/no-privileges signal requires AV:N and PR:N (v3/v4), or AV:N and Au:N (v2). It infers neither ease of exploitation, absence of user interaction, nor real exposure.',
    'KEV: matching uses CVE identifiers in the cached CISA catalog. Statistical years remain NVD publication years, not KEV addition years. Historical and CISA-only supplements remain outside NVD counts.',
    'Categories and attribution: vulnerable CPEs take priority. Explicitly affected CNA products, exact matches, package collections and conservative rules can support inference. Uncertain categories stay unresolved. An execution platform does not establish the vulnerable product type.',
    'Comparison: when either selected year is partial, the same day, month and UTC instant is applied to each year. February 29 is clamped to February 28 when needed. A zero baseline produces an absolute difference, never an infinite percentage.',
  ]; paragraphs.forEach((paragraph) => p.paragraph(paragraph, { size: 8.5, gap: 2 }));
  p.heading(p.fr ? 'Sources de référence' : 'Reference sources');
  SOURCE_LINKS.forEach(([label, url]) => p.linked(`${label} | ${url}`, url));
  if (m.weaknessSource.version) p.paragraph(`MITRE CWE: ${m.weaknessSource.version}. ${p.t.snapshot}: ${p.date(m.generatedAt)}.`, { size: 8.5, color: COLORS.muted });
  if (m.weaknessSource.copyright || m.weaknessSource.license) {
    const legalHeight = 9 + p.paragraphHeight(m.weaknessSource.copyright ?? '', 7.5, 2) + p.paragraphHeight(m.weaknessSource.license ?? '', 7.5, 2) + 7;
    p.ensure(legalHeight); p.heading(p.fr ? 'Notice de licence MITRE CWE (texte original)' : 'MITRE CWE license notice (original text)', 10);
    if (m.weaknessSource.copyright) p.paragraph(m.weaknessSource.copyright, { size: 7.5, gap: 2, color: COLORS.muted });
    if (m.weaknessSource.license) p.paragraph(m.weaknessSource.license, { size: 7.5, gap: 2, color: COLORS.muted });
    if (safeReference(m.weaknessSource.terms)) p.linked(p.fr ? 'Conditions d’utilisation de MITRE CWE' : 'MITRE CWE terms of use', m.weaknessSource.terms);
  }
  p.heading(p.fr ? 'Données nécessaires pour aller plus loin' : 'Inputs needed for further assessment');
  p.paragraph(p.fr ? 'Un inventaire et une SBOM permettent de confirmer l’applicabilité. Les tests de déploiement et la télémétrie établissent les protections et incidents locaux. Une source EPSS datée peut compléter la probabilité relative; une attribution d’acteur ou de campagne exige une source spécifique. Ces informations ne sont pas présentes ici.' :
    'Inventory and an SBOM establish applicability. Deployment tests and telemetry establish local protections and incidents. A dated EPSS source may add relative likelihood; actor or campaign attribution requires a specific source. These inputs are not present here.', { size: 8.5, gap: 3 });
}

function advisory(p, record, supplemental = false) {
  const id = cveIdentifier(record), detail = record.kevDetails ?? record;
  const product = detail.product || (record.products ?? []).map((item) => item.name).join(', ');
  const title = `${id} | ${p.t[`s_${record.severity}`] ?? p.t.unknown} | CVSS ${record.score ?? p.t.unknown}`;
  const productLine = `${detail.vendorProject ? detail.vendorProject + ' | ' : ''}${product || detail.vulnerabilityName || ''}`;
  const dateLine = `${p.t.added}: ${p.date(detail.dateAdded)} | ${p.t.due}: ${p.date(detail.dueDate)}`;
  const description = detail.shortDescription || record.description;
  const action = `${p.t.action}: ${detail.requiredAction || p.t.noAction}`;
  const references = [...new Set((Array.isArray(record.references) ? record.references : []).map(safeReference).filter(Boolean))];
  const referenceCount = Math.max(references.length, Number(record.sourceDetail?.referenceCount) || 0);
  const referenceLabels = references.slice(0, 3).map((url) => `${p.t.references}: ${truncate(new URL(url).hostname + new URL(url).pathname, 95)}`);
  const additional = referenceCount > 3 ? (p.fr ? `${p.n(referenceCount - 3)} autres références sont disponibles dans la fiche NVD.` : `${p.n(referenceCount - 3)} additional references are available in the NVD record.`) : '';
  const truncation = record.sourceDetail?.descriptionTruncated && !detail.shortDescription ? (p.fr ? 'Description NVD abrégée dans le paquet; consulter la fiche liée pour le texte complet.' : 'NVD description is shortened in the pack; consult the linked record for complete text.') : '';
  const ransomware = detail.knownRansomwareCampaignUse ? `${p.t.ransomware}: ${p.fr ? ({ Known: 'Oui, selon CISA', Unknown: 'Inconnu, selon CISA' }[detail.knownRansomwareCampaignUse] ?? detail.knownRansomwareCampaignUse) : detail.knownRansomwareCampaignUse}` : '';
  const notes = detail.notes ? `${p.t.notes}: ${detail.notes}` : '';
  const linksHeight = [p.t.nvd, ...referenceLabels].reduce((sum, label) => sum + p.wrap(label, p.width, 8.5).length * 4.5 + 2, 0) +
    (additional ? p.paragraphHeight(additional, 7.5, 2) : 0) + (truncation ? p.paragraphHeight(truncation, 7.5, 2) : 0) + 5;
  const tailHeight = p.paragraphHeight(action, 8.5, 2, true) + (ransomware ? p.paragraphHeight(ransomware, 8, 1) : 0) +
    (notes ? p.paragraphHeight(notes, 8, 1) : 0) + linksHeight;
  const completeHeight = p.wrap(title, p.width, 10.5, true).length * 4.41 + 4 + p.paragraphHeight(productLine, 8.5, 2, true) +
    p.paragraphHeight(dateLine, 8, 2) + (description ? p.paragraphHeight(description, 8.5, 1) : 0) + tailHeight +
    (supplemental ? 12 : 0) + (record.nvdCached === false ? 12 : 0) + 3;
  p.ensure(completeHeight <= 200 ? completeHeight : 40);
  p.context = id; p.heading(title, 10.5);
  p.paragraph(productLine, { size: 8.5, gap: 2, bold: true });
  p.paragraph(dateLine, { size: 8, gap: 2, color: COLORS.muted });
  if (supplemental) {
    const reportMatch = record.reportMatch ?? record.scopeMatch?.reason ?? record.scopeEvidence?.reason ?? record.scopeMatchReason ?? '';
    const labels = { 'Exact vendor/product or cached product identifier': 'Correspondance exacte éditeur/produit ou identifiant de produit en cache',
      'Supported category evidence; supplemental catalog advisory': 'Catégorie étayée par les preuves publiées; avis supplémentaire du catalogue',
      'Catalog advisory outside covered NVD publication records': 'Avis du catalogue hors des publications NVD couvertes' };
    p.paragraph(`${p.t.supplemental}. ${p.fr ? labels[reportMatch] ?? reportMatch : reportMatch}`, { size: 8, color: COLORS.blue });
  }
  if (record.nvdCached === false) p.paragraph(p.fr ? 'Évaluation NVD absente du cache; seuls les faits de l’avis CISA sont disponibles.' : 'NVD assessment is absent from the cache; only CISA advisory facts are available.', { size: 8, color: COLORS.muted });
  if (description) p.paragraph(description, { size: 8.5, gap: 1, keepNext: Math.min(tailHeight, 90) });
  if (tailHeight < 190) p.ensure(tailHeight);
  p.paragraph(action, { size: 8.5, gap: 2, bold: true, keepNext: Math.min(linksHeight + (notes ? p.paragraphHeight(notes, 8, 1) : 0) + (ransomware ? p.paragraphHeight(ransomware, 8, 1) : 0), 90) });
  if (ransomware) p.paragraph(ransomware, { size: 8, gap: 1 });
  if (notes) p.paragraph(notes, { size: 8, gap: 1, keepNext: Math.min(linksHeight, 90) });
  p.linked(`${p.t.nvd} | ${id}`, `https://nvd.nist.gov/vuln/detail/${id}`);
  references.slice(0, 3).forEach((url, index) => p.linked(referenceLabels[index], url));
  if (additional) p.paragraph(additional, { size: 7.5, color: COLORS.muted, gap: 2 });
  if (truncation) p.paragraph(truncation, { size: 7.5, color: COLORS.muted, gap: 2 });
  p.doc.setDrawColor(...COLORS.line); p.doc.line(18, p.y, 192, p.y); p.y += 5;
  p.context = null;
}

async function appendix(p, onStatus) {
  const m = p.model; p.section(9, p.t.appendixTitle, p.t.appendixScope);
  p.paragraph(`${p.n(m.relatedKev.length)} ${p.fr ? 'avis NVD/KEV couverts' : 'covered NVD/KEV advisories'} | ${p.n(m.supplementalKev.length)} ${p.fr ? 'compléments historiques ou CISA seulement' : 'historical or CISA-only supplements'}.`, { bold: true });
  p.paragraph(p.t.federal, { size: 9, color: COLORS.muted }); p.linked(p.t.cisa, CISA);
  if (!m.relatedKev.length) p.paragraph(p.t.noKev);
  for (let index = 0; index < m.relatedKev.length; index += 1) {
    advisory(p, m.relatedKev[index]);
    if (index % 40 === 0) { onStatus?.({ stage: 'advisories', completed: index + 1, total: m.relatedKev.length + m.supplementalKev.length }); await new Promise((resolve) => setTimeout(resolve, 0)); }
  }
  if (m.supplementalKev.length) {
    p.newPage(p.t.supplemental); p.heading(p.t.supplemental, 20); p.paragraph(p.t.supplementalNote, { size: 9 });
    for (let index = 0; index < m.supplementalKev.length; index += 1) {
      advisory(p, m.supplementalKev[index], true);
      if (index % 40 === 0) { onStatus?.({ stage: 'advisories', completed: m.relatedKev.length + index + 1, total: m.relatedKev.length + m.supplementalKev.length }); await new Promise((resolve) => setTimeout(resolve, 0)); }
    }
  }
}

export async function createIntelPdf({ summary, pack, year, comparison, lang = 'fr', onStatus } = {}) {
  const model = buildIntelReport({ summary, pack, year, comparison, lang });
  onStatus?.({ stage: 'preparing', completed: 0 });
  const [{ jsPDF }, fonts] = await Promise.all([import('jspdf'), loadFonts()]);
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4', compress: true, putOnlyUsedFonts: true, precision: 2 });
  fonts.forEach((font, index) => { const filename = `NotoSans-${index ? 'Bold' : 'Regular'}.ttf`; doc.addFileToVFS(filename, font); doc.addFont(filename, 'NotoSans', index ? 'bold' : 'normal'); });
  doc.setProperties({ title: `Signal Atlas | ${sanitize(model.subject.name)} | ${model.year}`, subject: copy[model.lang].report, author: 'Signal Atlas', creator: 'Signal Atlas - cached public vulnerability intelligence', keywords: 'CVE, CISA KEV, NVD, CWE, CVSS' });
  doc.setLanguage(model.lang === 'fr' ? 'fr-CA' : 'en-CA');
  const p = new Layout(doc, model);
  cover(p); scope(p); trends(p); weaknesses(p); impacts(p); exposure(p); roadmap(p); technology(p); methodology(p);
  await appendix(p, onStatus); p.footer();
  const filenamePart = sanitize(model.subject.name).normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').slice(0, 70) || 'scope';
  const blob = doc.output('blob');
  const result = { blob, filename: `Signal-Atlas-${filenamePart}-${model.year}-${model.lang}.pdf`, pages: doc.getNumberOfPages() };
  onStatus?.({ stage: 'complete', pages: result.pages, completed: model.relatedKev.length + model.supplementalKev.length });
  return result;
}
