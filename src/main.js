import './style.css';

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
const CATEGORIES = ['OS', 'Application', 'Hardware', 'Unknown'];
const PAGE_SIZE = 25;
const translations = {
  en: {
    classificationPartial: 'Another {count} classified CVEs still have a product with an unresolved category.',
    heroEyebrow: 'Open vulnerability intelligence', heroHeadline: 'Make sense of the vulnerability landscape.', heroSubtitle: 'Explore CVEs, affected products, and known exploitation in one clear view.', navOverview: 'Overview', navExplore: 'Explore CVEs', navKev: 'KEV catalog', overview: 'Vulnerability landscape', overviewSub: 'Compare publication years. Follow the signals that matter.', heroSources: 'Two trusted sources. One clear perspective.', heroOpen: 'Open data', footerTag: 'A clearer perspective on vulnerability intelligence.', footerSources: 'Sources', footerData: 'Data transparency', categoryMethodology: 'How categories are assigned',
    category: 'Product category', allCategories: 'All categories', classificationSummary: 'Across the full cache: {authoritative} CVEs classified from published CPE data; {inferred} classified through supported inference; {unresolved} remain unclassified because the evidence is insufficient.', classificationFallback: 'Categories use published CPE data where available, then supported product and description evidence. Records remain unclassified when the evidence is insufficient.', classificationRejected: 'Of those unclassified records, {count} are rejected CVEs.', categoryDetail: 'Category evidence', categoryAuthoritative: 'Published CPE classification', categoryInferred: 'Inferred classification', categoryInferredNote: 'Inferred categories follow the cited evidence and may change as published CPE data becomes available.', categoryUnresolved: 'The available product and advisory information is insufficient to assign a category reliably.', source_cpe: 'CPE data', source_affected: 'CNA affected products', source_cnaCpe: 'Published CNA CPE', source_kev: 'CISA KEV advisory', source_description: 'CVE description',
    skip: 'Skip to content', title: 'Vulnerability landscape', tag: 'A clearer view of CVEs, products and known exploitation.', year: 'Year', versus: 'vs', dark: 'Dark mode', loading: 'Loading the cached snapshot…', retry: 'Try again', severity: 'Severity',
    trend: 'Trend by year', trendSub: 'Unique CVE records by publication year, in the current snapshot.', severityTitle: 'By severity', categories: 'By product category', categorySub: 'CPE data and supported inference. A CVE can affect multiple categories.', rankings: 'Rankings', rankSub: 'Choose a metric. Select a product to see its benchmark.', topProducts: 'Top 10 products', topPublishers: 'Top 10 publishers',
    benchmark: 'Product benchmark', benchmarkSub: 'An observed comparison among the products included in this snapshot’s rankings.', product: 'Product', average: 'CVEs per ranked product', averageSub: 'Selected metric · only products with records in that year.', productTrend: 'Product vs category average',
    inspect: 'Inspect the evidence', explorer: 'CVE explorer', explorerSub: 'Load one publication month from the cache. Search records and inspect advisory links.', month: 'Publication month', loadMonth: 'Load month', search: 'Search', exploitation: 'Exploitation', recordStatus: 'NVD status', kevTitle: 'The full CISA KEV catalog', kevSub: 'Includes legacy CVEs published before 2020. KEV membership identifies known exploitation, not a severity rating.', loadCatalog: 'Load catalog', searchCatalog: 'Search catalog',
    scope: 'Counts describe this cached snapshot. Publication years may differ from CVE identifier years, and partial years are not directly comparable to complete years. Categories use CPE data first, followed by supported inference from affected products, KEV advisories or descriptions. Assignments may overlap; evidence is shown in each CVE record.', portfolio: 'An open-data portfolio project', close: 'Close',
    all: 'All CVEs', critical: 'Critical only', kev: 'Known exploited (KEV)', allProducts: 'All products', c_OS: 'Operating systems', c_Application: 'Applications', c_Hardware: 'Hardware', c_Unknown: 'Unclassified', s_Critical: 'Critical', s_High: 'High', s_Medium: 'Medium', s_Low: 'Low', s_Unknown: 'Unknown',
    unique: 'Unique CVEs published', criticalKpi: 'Critical CVEs', kevKpi: 'CVEs in CISA KEV', catalogKpi: 'Full KEV catalog', catalogFoot: 'All publication years · no severity filter', compared: 'vs {year}: {count}', selected: 'Selected severities · {year}', noData: 'No records for this selection.', noProducts: 'No ranked products in this snapshot.', productLimit: 'From the top {count} ranked products. Counts can overlap between products.', publisherLimit: 'From the top {count} ranked publishers in this snapshot.', categoryAverage: 'Category average', globalAverage: 'All ranked products average',
    benchmarkSentence: '{product} has {count} CVEs in {year} for this metric. Category rank: {rank} of {total} active ranked products. Category average: {average}.', benchmarkEmpty: 'Select a product with cached records to compare it.', uninitialized: 'The initial cache has not been built. Run the Python bootstrap to populate this dashboard.', partial: 'Initial collection is incomplete. These counts show only records cached so far.', ready: 'Cached snapshot · generated {date}', fetchError: 'The cached snapshot could not be loaded. Check that /data/summary.json is published.', coverage: 'Publication coverage: {start} to {end}. NVD sync: {nvd}. KEV sync: {kev}.', notSynced: 'not yet synced', partialYear: 'Current coverage includes a partial year. Compare publication periods with care.',
    selectMonth: 'Select a month and choose “Load month” to fetch its cached records.', noMonths: 'No publication months have been cached yet.', loadingMonth: 'Loading {month}…', loadedMonth: '{count} cached records loaded for {month}.', errorMonth: 'This month could not be loaded. Retry after verifying the cache files.', matches: '{count} matches', allSeverity: 'All severities', allExploitation: 'All records', kevOnly: 'KEV only', notKev: 'Not in KEV', allStatus: 'All statuses', previous: 'Previous', next: 'Next', page: 'Page {page} of {total}', published: 'Published', modified: 'Last modified', status: 'NVD status', score: 'CVSS score', vector: 'CVSS vector', products: 'Affected products', weaknesses: 'Weaknesses', references: 'Advisory and reference links', referenceNote: 'Links come from NVD. They may include advisories, mitigations or patches; verify applicability with the vendor.', noReferences: 'No HTTPS references are available in this record.', noDescription: 'No description is available.', unknown: 'Unknown', pending: 'Not yet scored', nvdRecord: 'View the NVD record', kevDetails: 'Known exploitation · CISA KEV', dateAdded: 'Added to KEV', dueDate: 'Federal remediation due date', ransomware: 'Known ransomware campaign use', requiredAction: 'Required action', notes: 'CISA notes', kevInitial: 'Load the catalog to browse all cached KEV advisories, including legacy CVEs.', loadingCatalog: 'Loading the CISA catalog…', catalogLoaded: '{count} advisories · catalog {version} · released {date}', catalogError: 'The KEV catalog could not be loaded. Check /data/kev.json and try again.', noCatalog: 'The cached KEV catalog is empty. Run the collector to populate it.', searchPlaceholder: 'CVE ID, product or description', catalogPlaceholder: 'CVE ID, vendor or product', languageLabel: 'Passer en français', vendor: 'Publisher', noProductsDetail: 'No affected products are identified in this cached record.', noWeaknesses: 'No weakness classification is available.', legacy: 'Legacy CVE', collectionMismatch: 'This cache month is incomplete or inconsistent. Rebuild the export before relying on these records.',
  },
  fr: {
    classificationPartial: 'Dans {count} autres CVE classées, la catégorie d’un produit reste non résolue.',
    heroEyebrow: 'Veille ouverte sur les vulnérabilités', heroHeadline: 'Comprendre le paysage des vulnérabilités.', heroSubtitle: 'Explorez les CVE, les produits touchés et leur exploitation connue dans une vue claire.', navOverview: 'Vue d’ensemble', navExplore: 'Explorer les CVE', navKev: 'Catalogue KEV', overview: 'Paysage des vulnérabilités', overviewSub: 'Comparez les années de publication. Suivez les signaux pertinents.', heroSources: 'Deux sources fiables. Une perspective claire.', heroOpen: 'Données ouvertes', footerTag: 'Une perspective claire sur les vulnérabilités.', footerSources: 'Sources', footerData: 'Transparence des données', categoryMethodology: 'Comment les catégories sont attribuées',
    category: 'Catégorie de produit', allCategories: 'Toutes les catégories', classificationSummary: 'Dans l’ensemble du cache : {authoritative} CVE classées à partir de données CPE publiées; {inferred} classées par inférence étayée; {unresolved} restent non classées faute de preuves suffisantes.', classificationFallback: 'Les catégories proviennent des données CPE publiées disponibles, puis des informations étayées sur les produits et les descriptions. Les CVE restent non classées lorsque les preuves sont insuffisantes.', classificationRejected: 'Parmi ces CVE non classées, {count} ont été rejetées.', categoryDetail: 'Preuves de classification', categoryAuthoritative: 'Classification CPE publiée', categoryInferred: 'Classification inférée', categoryInferredNote: 'Les catégories inférées reposent sur les preuves citées et peuvent évoluer lorsque des données CPE publiées deviennent disponibles.', categoryUnresolved: 'Les informations disponibles sur les produits et les avis ne permettent pas d’attribuer une catégorie fiable.', source_cpe: 'Données CPE', source_affected: 'Produits touchés selon la CNA', source_cnaCpe: 'CPE publiées par la CNA', source_kev: 'Avis CISA KEV', source_description: 'Description de la CVE',
    skip: 'Aller au contenu', title: 'Paysage des vulnérabilités', tag: 'Une vue claire des CVE, des produits et de leur exploitation connue.', year: 'Année', versus: 'vs', dark: 'Mode sombre', loading: 'Chargement des données en cache…', retry: 'Réessayer', severity: 'Gravité',
    trend: 'Tendance par année', trendSub: 'CVE uniques par année de publication dans les données actuelles.', severityTitle: 'Par gravité', categories: 'Par catégorie de produit', categorySub: 'Données CPE et inférences étayées. Une CVE peut toucher plusieurs catégories.', rankings: 'Classements', rankSub: 'Choisissez une mesure. Sélectionnez un produit pour le comparer.', topProducts: 'Top 10 des produits', topPublishers: 'Top 10 des éditeurs',
    benchmark: 'Comparaison de produit', benchmarkSub: 'Comparaison observée parmi les produits inclus dans les classements de ces données.', product: 'Produit', average: 'CVE par produit classé', averageSub: 'Mesure sélectionnée · produits ayant des données durant cette année.', productTrend: 'Produit vs moyenne de sa catégorie',
    inspect: 'Examiner les données', explorer: 'Explorateur de CVE', explorerSub: 'Chargez un mois de publication en cache. Cherchez les CVE et consultez leurs avis.', month: 'Mois de publication', loadMonth: 'Charger le mois', search: 'Rechercher', exploitation: 'Exploitation', recordStatus: 'Statut NVD', kevTitle: 'Le catalogue CISA KEV complet', kevSub: 'Comprend les CVE publiées avant 2020. KEV indique une exploitation connue, et non un niveau de gravité.', loadCatalog: 'Charger le catalogue', searchCatalog: 'Chercher dans le catalogue',
    scope: 'Les comptes décrivent les données en cache. L’année de publication peut différer de celle de l’identifiant CVE, et une année partielle ne se compare pas directement à une année complète. Les catégories proviennent d’abord des données CPE, puis d’inférences étayées sur les produits touchés, les avis KEV ou les descriptions. Les catégories peuvent se chevaucher; chaque CVE présente ses preuves.', portfolio: 'Un projet de portfolio fondé sur des données ouvertes', close: 'Fermer',
    all: 'Toutes les CVE', critical: 'Critiques seulement', kev: 'Exploitation connue (KEV)', allProducts: 'Tous les produits', c_OS: 'Systèmes d’exploitation', c_Application: 'Applications', c_Hardware: 'Matériel', c_Unknown: 'Non classé', s_Critical: 'Critique', s_High: 'Élevée', s_Medium: 'Modérée', s_Low: 'Faible', s_Unknown: 'Inconnue',
    unique: 'CVE uniques publiées', criticalKpi: 'CVE critiques', kevKpi: 'CVE dans CISA KEV', catalogKpi: 'Catalogue KEV complet', catalogFoot: 'Toutes les années · sans filtre de gravité', compared: 'vs {year} : {count}', selected: 'Gravités sélectionnées · {year}', noData: 'Aucune donnée pour cette sélection.', noProducts: 'Aucun produit classé dans ces données.', productLimit: 'Parmi les {count} produits classés. Les comptes peuvent se chevaucher.', publisherLimit: 'Parmi les {count} éditeurs classés dans ces données.', categoryAverage: 'Moyenne de la catégorie', globalAverage: 'Moyenne des produits classés',
    benchmarkSentence: '{product} compte {count} CVE en {year} pour cette mesure. Rang dans la catégorie : {rank} sur {total} produits classés actifs. Moyenne de la catégorie : {average}.', benchmarkEmpty: 'Sélectionnez un produit ayant des données pour le comparer.', uninitialized: 'Le cache initial n’a pas été créé. Exécutez la collecte Python initiale pour alimenter ce tableau de bord.', partial: 'La collecte initiale est incomplète. Les comptes reflètent uniquement les données déjà en cache.', ready: 'Données en cache · générées le {date}', fetchError: 'Impossible de charger les données. Vérifiez la publication de /data/summary.json.', coverage: 'Publications couvertes : du {start} au {end}. Sync NVD : {nvd}. Sync KEV : {kev}.', notSynced: 'pas encore synchronisé', partialYear: 'La couverture comprend une année partielle. Comparez les périodes avec prudence.',
    selectMonth: 'Sélectionnez un mois, puis « Charger le mois » pour consulter ses données en cache.', noMonths: 'Aucun mois de publication n’a encore été mis en cache.', loadingMonth: 'Chargement de {month}…', loadedMonth: '{count} données en cache chargées pour {month}.', errorMonth: 'Impossible de charger ce mois. Vérifiez le cache et réessayez.', matches: '{count} résultats', allSeverity: 'Toutes les gravités', allExploitation: 'Toutes les CVE', kevOnly: 'KEV seulement', notKev: 'Absentes de KEV', allStatus: 'Tous les statuts', previous: 'Précédent', next: 'Suivant', page: 'Page {page} sur {total}', published: 'Publication', modified: 'Dernière modification', status: 'Statut NVD', score: 'Score CVSS', vector: 'Vecteur CVSS', products: 'Produits touchés', weaknesses: 'Faiblesses', references: 'Liens vers les avis et références', referenceNote: 'Les liens proviennent du NVD et peuvent inclure des avis, mesures ou correctifs. Vérifiez leur applicabilité auprès du fournisseur.', noReferences: 'Aucune référence HTTPS disponible pour cette CVE.', noDescription: 'Aucune description disponible.', unknown: 'Inconnu', pending: 'Pas encore évaluée', nvdRecord: 'Consulter la CVE dans le NVD', kevDetails: 'Exploitation connue · CISA KEV', dateAdded: 'Ajout à KEV', dueDate: 'Échéance de correction fédérale', ransomware: 'Usage dans des campagnes de rançongiciels', requiredAction: 'Mesure requise', notes: 'Notes CISA', kevInitial: 'Chargez le catalogue pour parcourir tous les avis KEV en cache, dont les anciennes CVE.', loadingCatalog: 'Chargement du catalogue CISA…', catalogLoaded: '{count} avis · catalogue {version} · publié le {date}', catalogError: 'Impossible de charger KEV. Vérifiez /data/kev.json et réessayez.', noCatalog: 'Le catalogue KEV en cache est vide. Exécutez la collecte pour le remplir.', searchPlaceholder: 'Identifiant CVE, produit ou description', catalogPlaceholder: 'Identifiant CVE, fournisseur ou produit', languageLabel: 'Switch to English', vendor: 'Éditeur', noProductsDetail: 'Aucun produit touché n’est identifié dans cette donnée en cache.', noWeaknesses: 'Aucune classification de faiblesse disponible.', legacy: 'Ancienne CVE', collectionMismatch: 'Ce mois de cache est incomplet ou incohérent. Reconstruisez l’export avant de vous fier à ces données.',
  },
};

Object.assign(translations.en, {
  trendFullPartial: 'Full-year totals; {year} remains partial through {end}. Selected severities.',
  fetchError: 'The cached snapshot could not be loaded. Check that /data/summary.json.gz is published.',
  benchmark: 'Product & publisher benchmark', benchmarkSub: 'Compare disclosure counts among the ranked entities. Volume reflects coverage and disclosure practices as well as vulnerabilities; it is not a security score.', rankSub: 'Select a metric, then a product or publisher to investigate its benchmark.',
  scope: 'Rejected CVEs are excluded. Counts use publication dates. Matched periods are used when comparing a partial year. Product, publisher, category and weakness counts can overlap. Weaknesses describe reported causes; CVSS describes potential impact, not observed incidents. Inferred categories are identified in record details.',
  publisher: 'Publisher', productMode: 'Products', publisherMode: 'Publishers', periodMatched: 'Matched period: Jan 1–{end}, for both {year} and {comparison}. Trend charts use this same period in every year.', periodFull: 'Full publication years · selected severity filters apply to overview and comparisons.', periodPartial: 'Coverage ends {end}.',
  trendMatched: 'Same publication period in every year; selected severities.', trendFull: 'Publication years; selected severities. The latest year may be partial.', trendNew: 'New', trendFlat: 'No change', trendUp: 'Increase', trendDown: 'Decrease', trendVs: '{direction} vs {year}: {change}', trendNoBaseline: 'No CVEs in the comparison period; a percentage change is unavailable.',
  causesTitle: 'Top reported weaknesses', causesSub: '{year} · {metric} · reported CWE classifications', impactsTitle: 'Potential impact', impactsSub: '{year} · {metric} · CVSS impact assessment', causeCoverage: 'A reported weakness is available for {known} of {total} CVEs ({percent}%). Shares use all CVEs in this selection; multiple weaknesses can overlap.', impactCoverage: 'CVSS impact data is available for {known} of {total} CVEs ({percent}%). Counts include any non-zero impact; they do not identify actual incidents. Impacts can overlap.', insightUnavailable: 'No assessment is available for this selection.',
  confidentiality: 'Confidentiality exposure', integrity: 'Integrity compromise', availability: 'Availability disruption', causeEmpty: 'No reported weakness in this selection.', shareOfSelection: '{percent}% of selected CVEs',
  signalKev: 'Known exploitation', signalKevNote: 'Share of selected CVEs in CISA KEV', signalRemote: 'Network · no privileges', signalRemoteNote: 'CVSS assessment; user interaction may still be required', signalCause: 'Leading reported weakness', signalCauseNote: '{count} CVEs · {share}% of this selection', signalCoverage: 'Assessment coverage', signalCoverageNote: '{cause}% with a weakness · {impact}% with CVSS impact data',
  publisherAverage: 'CVEs per ranked publisher', publisherAverageLabel: 'Ranked publisher average', publisherTrend: 'Publisher vs ranked average', publisherBenchmarkSentence: '{product} has {count} CVEs in {year} for this metric. Publisher rank: {rank} of {total} active ranked publishers. Ranked average: {average}.', publisherBenchmarkEmpty: 'Select a publisher with cached records to compare it.', peerNote: 'Selected metric · ranked entities with records in the shown period.', publisherAttribution: 'Publisher: {publisher} · {count} unique publisher CVEs in this period. Publisher and product counts have different scopes.',
  tacticalEyebrow: 'From signal to action', priorityTitle: 'Recent known-exploited advisories', prioritySub: 'Check affected versions, then follow the vendor’s mitigation or patch guidance.', priorityNote: 'Showing {shown} of {available} recent candidates from the full cached KEV catalog, newest CISA date added first. Includes legacy CVEs; advisory records without cached NVD analysis are marked unscored. Use the full catalog for complete coverage. Applicability depends on your inventory; federal due dates are not universal deadlines.', priorityDetails: 'Inspect advisory & references', priorityEmpty: 'No recent KEV advisories are available in this snapshot.', showMore: 'Show more', showLess: 'Show fewer', rejectedExcluded: '{count} rejected CVE records excluded from the dashboard.',
  assessedImpact: 'Potential impact assessment', networkAssessment: 'Network attack vector with no privileges required. User interaction may still be required.',
  signalImpact: 'Leading potential impact', signalImpactNote: '{count} CVEs · {share}% of this selection · {coverage}% assessed', signalRemoteCoverage: '{known} of {total} CVEs assessed for reach; user interaction may still be required.', noImpactReported: 'No non-zero impact reported', additionalFilters: 'More evidence filters', reportedWeakness: 'Reported weakness', allWeaknesses: 'All weaknesses', allImpacts: 'All impacts', impactAssessmentNote: 'CVSS describes potential consequences. It does not confirm an incident.', cweSource: 'Weakness names: MITRE CWE {version}', nvdNotCached: 'NVD assessment not cached', navInsights: 'Insights',
});
Object.assign(translations.fr, {
  trendFullPartial: 'Totaux annuels; {year} reste partielle jusqu’au {end}. Gravités sélectionnées.',
  fetchError: 'Impossible de charger les données. Vérifiez la publication de /data/summary.json.gz.',
  benchmark: 'Comparaison de produits et d’éditeurs', benchmarkSub: 'Comparez les comptes de divulgation parmi les entités classées. Le volume reflète aussi la couverture et les pratiques de divulgation; ce n’est pas un score de sécurité.', rankSub: 'Choisissez une mesure, puis un produit ou un éditeur pour examiner sa comparaison.',
  scope: 'Les CVE rejetées sont exclues. Les comptes utilisent les dates de publication. Les comparaisons comprenant une année partielle utilisent des périodes équivalentes. Les produits, éditeurs, catégories et faiblesses peuvent se chevaucher. Les faiblesses décrivent les causes rapportées; CVSS décrit les impacts potentiels, pas des incidents observés. Les catégories inférées sont indiquées dans les détails.',
  publisher: 'Éditeur', productMode: 'Produits', publisherMode: 'Éditeurs', periodMatched: 'Période équivalente : du 1er janv. au {end}, pour {year} et {comparison}. Les tendances utilisent la même période pour chaque année.', periodFull: 'Années de publication complètes · les filtres de gravité s’appliquent à la vue d’ensemble et aux comparaisons.', periodPartial: 'Couverture jusqu’au {end}.',
  trendMatched: 'Même période de publication chaque année; gravités sélectionnées.', trendFull: 'Années de publication; gravités sélectionnées. La dernière année peut être partielle.', trendNew: 'Nouveau', trendFlat: 'Stable', trendUp: 'Hausse', trendDown: 'Baisse', trendVs: '{direction} par rapport à {year} : {change}', trendNoBaseline: 'Aucune CVE dans la période de comparaison; la variation en pourcentage n’est pas disponible.',
  causesTitle: 'Principales faiblesses rapportées', causesSub: '{year} · {metric} · classifications CWE rapportées', impactsTitle: 'Impact potentiel', impactsSub: '{year} · {metric} · évaluation de l’impact CVSS', causeCoverage: 'Une faiblesse est rapportée pour {known} CVE sur {total} ({percent} %). Les parts utilisent toutes les CVE sélectionnées; plusieurs faiblesses peuvent se chevaucher.', impactCoverage: 'Les impacts CVSS sont disponibles pour {known} CVE sur {total} ({percent} %). Les comptes comprennent tout impact non nul, et ne décrivent pas des incidents observés. Les impacts peuvent se chevaucher.', insightUnavailable: 'Aucune évaluation disponible pour cette sélection.',
  confidentiality: 'Exposition de la confidentialité', integrity: 'Compromission de l’intégrité', availability: 'Perturbation de la disponibilité', causeEmpty: 'Aucune faiblesse rapportée dans cette sélection.', shareOfSelection: '{percent} % des CVE sélectionnées',
  signalKev: 'Exploitation connue', signalKevNote: 'Part des CVE sélectionnées présentes dans CISA KEV', signalRemote: 'Réseau · sans privilèges', signalRemoteNote: 'Évaluation CVSS; une interaction peut être nécessaire', signalCause: 'Principale faiblesse rapportée', signalCauseNote: '{count} CVE · {share} % de cette sélection', signalCoverage: 'Couverture des évaluations', signalCoverageNote: '{cause} % avec une faiblesse · {impact} % avec un impact CVSS',
  publisherAverage: 'CVE par éditeur classé', publisherAverageLabel: 'Moyenne des éditeurs classés', publisherTrend: 'Éditeur vs moyenne du classement', publisherBenchmarkSentence: '{product} compte {count} CVE en {year} pour cette mesure. Rang parmi les éditeurs : {rank} sur {total} éditeurs classés actifs. Moyenne : {average}.', publisherBenchmarkEmpty: 'Sélectionnez un éditeur ayant des données pour le comparer.', peerNote: 'Mesure sélectionnée · entités classées avec des données pour la période affichée.', publisherAttribution: 'Éditeur : {publisher} · {count} CVE uniques de cet éditeur pour cette période. Les comptes de produits et d’éditeurs ont des portées différentes.',
  tacticalEyebrow: 'Du signal à l’action', priorityTitle: 'Avis récents sur l’exploitation connue', prioritySub: 'Vérifiez les versions touchées, puis consultez les mesures ou correctifs du fournisseur.', priorityNote: '{shown} avis affichés parmi {available} candidats récents du catalogue KEV en cache, par date d’ajout CISA décroissante. Les anciennes CVE sont incluses; les avis sans analyse NVD en cache sont marqués non évalués. Consultez le catalogue complet pour une couverture totale. L’applicabilité dépend de votre inventaire; les échéances fédérales ne sont pas universelles.', priorityDetails: 'Examiner l’avis et les références', priorityEmpty: 'Aucun avis KEV récent disponible dans ces données.', showMore: 'Afficher plus', showLess: 'Afficher moins', rejectedExcluded: '{count} CVE rejetées exclues du tableau de bord.',
  assessedImpact: 'Évaluation de l’impact potentiel', networkAssessment: 'Vecteur d’attaque réseau sans privilèges requis. Une interaction utilisateur peut être nécessaire.',
  signalImpact: 'Principal impact potentiel', signalImpactNote: '{count} CVE · {share} % de cette sélection · {coverage} % évaluées', signalRemoteCoverage: 'Portée évaluée pour {known} CVE sur {total}; une interaction peut être nécessaire.', noImpactReported: 'Aucun impact non nul rapporté', additionalFilters: 'Filtres de preuves supplémentaires', reportedWeakness: 'Faiblesse rapportée', allWeaknesses: 'Toutes les faiblesses', allImpacts: 'Tous les impacts', impactAssessmentNote: 'CVSS décrit les conséquences potentielles et ne confirme pas un incident.', cweSource: 'Noms des faiblesses : MITRE CWE {version}', nvdNotCached: 'Évaluation NVD absente du cache', navInsights: 'Analyses',
});

const $ = (id) => document.getElementById(id);
Object.assign(translations.en, {
  sharedSearchScope: 'Search the KEV catalog and the loaded CVE month. Load a month below to explore its CVEs.', sharedSearchPlaceholder: 'CVE ID, publisher, product or description', searchCves: 'CVE month · {count} matches', searchKev: 'KEV catalog · {count} matches', searchLoadCves: 'CVE explorer · load a month', searchLoadKev: 'KEV catalog · load catalog', searchResultsLabel: 'Search results',
  reportEyebrow: 'Brief the decision makers', reportTitle: 'Executive threat intelligence', reportSub: 'Turn a product or category into an evidence-based strategic briefing.', reportCategoryMode: 'Category', createReport: 'Create executive report', reportSubjectLabel: 'Report subject', reportScope: '{subject} · {year} vs {comparison} · all severities. Includes historical trends, reported weaknesses, potential impacts, KEV evidence and a 30/60/90-day action plan.', reportUnavailable: 'Report data is unavailable for this selection. Refresh the cached export.', reportLoading: 'Preparing the executive briefing…', reportReady: '{subject} · {year} · PDF ready · {pages} pages. Opened in a new tab.', reportPopupBlocked: '{subject} · {year} · PDF ready · {pages} pages. Use the link below to open or download it.', reportError: 'The report could not be generated. Check the cached snapshot and try again.', reportPreparingTab: 'Signal Atlas is preparing your executive briefing. This tab will display the PDF when it is ready.', downloadReport: 'Download PDF', reportBusy: 'Creating PDF…',
});
Object.assign(translations.fr, {
  searchCatalog: 'Chercher dans le catalogue', sharedSearchScope: 'Recherche dans le catalogue KEV et le mois de CVE chargé. Chargez un mois ci-dessous pour explorer ses CVE.', sharedSearchPlaceholder: 'Identifiant CVE, éditeur, produit ou description', searchCves: 'Mois de CVE · {count} résultats', searchKev: 'Catalogue KEV · {count} résultats', searchLoadCves: 'Explorateur CVE · charger un mois', searchLoadKev: 'Catalogue KEV · charger le catalogue', searchResultsLabel: 'Résultats de recherche',
  reportEyebrow: 'Éclairer les décisions', reportTitle: 'Renseignement stratégique pour les exécutifs', reportSub: 'Transformez les données d’un produit ou d’une catégorie en un rapport stratégique documenté.', reportCategoryMode: 'Catégorie', createReport: 'Créer le rapport exécutif', reportSubjectLabel: 'Sujet du rapport', reportScope: '{subject} · {year} vs {comparison} · toutes les gravités. Tendances historiques, faiblesses rapportées, impacts potentiels, preuves KEV et plan d’action à 30/60/90 jours.', reportUnavailable: 'Les données du rapport ne sont pas disponibles pour cette sélection. Actualisez l’export du cache.', reportLoading: 'Préparation du rapport stratégique…', reportReady: '{subject} · {year} · PDF prêt · {pages} pages. Ouvert dans un nouvel onglet.', reportPopupBlocked: '{subject} · {year} · PDF prêt · {pages} pages. Utilisez le lien ci-dessous pour l’ouvrir ou le télécharger.', reportError: 'Le rapport n’a pas pu être généré. Vérifiez le cache et réessayez.', reportPreparingTab: 'Signal Atlas prépare votre rapport stratégique. Cet onglet affichera le PDF dès qu’il sera prêt.', downloadReport: 'Télécharger le PDF', reportBusy: 'Création du PDF…',
});
const storage = (key, value) => { try { if (value !== undefined) localStorage.setItem(key, value); return localStorage.getItem(key); } catch { return null; } };
const savedLanguage = storage('vl-language');
const state = {
  lang: savedLanguage === 'fr' || (!savedLanguage && navigator.language.startsWith('fr')) ? 'fr' : 'en',
  summary: null, summaryError: false, year: 2026, comparison: 2025, metric: 'all', category: 'All', severities: new Set(SEVERITIES), product: '', productOptions: [], benchmarkMode: 'product', publisher: '', publisherOptions: [], priorityExpanded: false,
  monthRecords: null, loadedMonth: '', monthPage: 1, monthLoading: false, monthError: false, monthAbort: null,
  catalog: null, catalogPage: 1, catalogLoading: false, catalogError: false,
  reportKind: 'product', reportCategory: 'All', reportLoading: false,
  reportFeedback: null,
};
const t = (key, values = {}) => (translations[state.lang][key] ?? key).replace(/\{(\w+)\}/g, (_, name) => String(values[name] ?? ''));
const number = (value) => Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : 0;
const formatters = Object.fromEntries(['en', 'fr'].map((lang) => {
  const locale = `${lang}-CA`, dateOptions = { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' };
  return [lang, {
    integer: new Intl.NumberFormat(locale, { maximumFractionDigits: 0 }),
    decimal: new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }),
    date: new Intl.DateTimeFormat(locale, dateOptions),
    monthDay: new Intl.DateTimeFormat(locale, { month: 'short', day: 'numeric', timeZone: 'UTC' }),
    timestamp: new Intl.DateTimeFormat(locale, { ...dateOptions, hour: '2-digit', minute: '2-digit' }),
  }];
}));
const nf = (value, fractional = false) => formatters[state.lang][fractional ? 'decimal' : 'integer'].format(number(value));
const text = (value, fallback = '') => typeof value === 'string' ? value : fallback;
const pretty = (value) => text(value).replaceAll('_', ' ');
const date = (value, timestamp = false) => {
  const parsed = new Date(value);
  if (!value || !Number.isFinite(parsed.getTime())) return t('notSynced');
  return formatters[state.lang][timestamp ? 'timestamp' : 'date'].format(parsed) + (timestamp ? ' UTC' : '');
};
const searchIndex = new WeakMap(), categoryIndex = new WeakMap();
let monthFilterCache = null, catalogFilterCache = null;
function recordCategories(record) {
  if (categoryIndex.has(record)) return categoryIndex.get(record);
  const supplied = Array.isArray(record.categories) ? record.categories.filter((category) => CATEGORIES.includes(category)) : [];
  const candidates = supplied.length ? supplied : (Array.isArray(record.products) ? record.products.map((product) => product.category).filter((category) => CATEGORIES.includes(category)) : []);
  const categories = CATEGORIES.filter((category) => candidates.includes(category));
  if (!categories.length) categories.push('Unknown');
  categoryIndex.set(record, categories); return categories;
}
function indexRecords(records, catalog = false) {
  for (const record of records) {
    const fields = catalog ? [record.cveID, record.vendorProject, record.product, record.vulnerabilityName, record.shortDescription] : [record.id, record.description, ...(Array.isArray(record.vendors) ? record.vendors : []), ...(Array.isArray(record.products) ? record.products.flatMap((product) => [product.name, product.vendor]) : [])];
    searchIndex.set(record, fields.map((value) => String(value ?? '').toLocaleLowerCase()).join('\u0000'));
    if (!catalog) recordCategories(record);
  }
}
function node(tag, className, content) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (content !== undefined) element.textContent = String(content);
  return element;
}
function svgNode(tag, attributes = {}, content) {
  const element = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
  if (content !== undefined) element.textContent = String(content);
  return element;
}
function options(element, items, selected) {
  element.replaceChildren(...items.map(([value, label]) => { const option = node('option', '', label); option.value = value; return option; }));
  if (selected !== undefined) element.value = String(selected);
}
const empty = (element, key = 'noData') => element.replaceChildren(node('p', 'empty', t(key)));
function safeHTTPS(value) {
  if (typeof value !== 'string' || value.length > 2500 || !/^https:\/\//i.test(value) || /[\s\u0000-\u001f\u007f-\u009f\\]/.test(value)) return null;
  try { const url = new URL(value); return url.protocol === 'https:' && url.hostname && !url.username && !url.password ? url : null; } catch { return null; }
}
function link(url, label) {
  const anchor = node('a', '', label); anchor.href = url.href; anchor.target = '_blank'; anchor.rel = 'noopener noreferrer'; anchor.referrerPolicy = 'no-referrer'; return anchor;
}
async function fetchJSON(path, maxBytes = 8_000_000, signal) {
  const controller = new AbortController();
  const forwardAbort = () => controller.abort();
  if (signal?.aborted) controller.abort();
  signal?.addEventListener('abort', forwardAbort, { once: true });
  const timer = setTimeout(() => controller.abort(), 30_000);
  const readBounded = async (stream) => {
    const reader = stream?.getReader();
    if (!reader) throw new Error('Response stream is unavailable');
    const chunks = []; let size = 0;
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { await reader.cancel(); throw new Error('Cache file exceeds limit'); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return bytes;
  };
  try {
    const response = await fetch(path, { signal: controller.signal, credentials: 'omit', redirect: 'error', headers: { Accept: 'application/json' }, cache: 'no-cache' });
    if (!response.ok || (!path.endsWith('.gz') && !response.headers.get('content-type')?.includes('application/json'))) throw new Error('Invalid cache response');
    if (number(response.headers.get('content-length')) > maxBytes) throw new Error('Cache file exceeds limit');
    let bytes = await readBounded(response.body);
    if (path.endsWith('.gz') && bytes[0] === 0x1f && bytes[1] === 0x8b) {
      if (!('DecompressionStream' in globalThis)) throw new Error('This browser does not support gzip cache files');
      bytes = await readBounded(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip')));
    }
    return JSON.parse(new TextDecoder().decode(bytes));
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', forwardAbort); }
}
function metric(stats, metricName = state.metric) {
  if (!stats) return 0;
  if (metricName === 'crit') return state.severities.has('Critical') ? number(stats.critical) : 0;
  if (metricName === 'kev') return SEVERITIES.filter((severity) => state.severities.has(severity)).reduce((sum, severity) => sum + number(stats.kevSeverity?.[severity]), 0);
  return SEVERITIES.filter((severity) => state.severities.has(severity)).reduce((sum, severity) => sum + number(stats.severity?.[severity]), 0);
}
const matchedPeriod = () => Number.isInteger(state.summary?.comparisonWindow?.partialYear) && [state.year, state.comparison].includes(state.summary.comparisonWindow.partialYear);
const trendPeriodLabel = () => matchedPeriod() ? t('trendMatched') : state.summary?.comparisonWindow ? t('trendFullPartial', { year: state.summary.comparisonWindow.partialYear, end: date(state.summary.coverage?.end) }) : t('trendFull');
const yearStats = (year) => { const item = state.summary?.years.find((entry) => entry.year === Number(year)); return matchedPeriod() ? item?.through ?? item : item; };
const entityStats = (entity, year) => matchedPeriod() ? entity.throughYears?.[year] ?? entity.years?.[year] : entity.years?.[year];
const rankedProducts = () => state.summary?.products ?? [];
const rankedPublishers = () => state.summary?.publishers ?? [];
const percent = (value, total) => total > 0 ? value / total * 100 : 0;
const metricLabel = () => t({ all: 'all', crit: 'critical', kev: 'kev' }[state.metric]);
function binsMetric(bins, metricName = state.metric) {
  if (!Array.isArray(bins)) return 0;
  if (metricName === 'crit') return state.severities.has('Critical') ? number(bins[0]) : 0;
  const offset = metricName === 'kev' ? 5 : 0;
  return SEVERITIES.reduce((sum, severity, index) => sum + (state.severities.has(severity) ? number(bins[index + offset]) : 0), 0);
}
function weaknessName(id) { return text(state.summary?.weaknessLabels?.names?.[id], id); }
function weaknessLink(id, label = weaknessName(id)) {
  const url = /^CWE-[1-9]\d{0,5}$/.test(id) ? safeHTTPS(`https://cwe.mitre.org/data/definitions/${id.slice(4)}.html`) : null;
  return url ? link(url, label) : node('span', '', label);
}
function trendBadge(value, before) {
  const change = before > 0 ? (value - before) / before * 100 : value > 0 ? null : 0;
  const direction = change === null ? 'new' : change > 0 ? 'up' : change < 0 ? 'down' : 'flat';
  const badge = node('span', `trend-indicator ${direction}`, change === null ? t('trendNew') : `${direction === 'up' ? '↑ +' : direction === 'down' ? '↓ −' : '→ '}${nf(Math.abs(change), true)}%`);
  badge.setAttribute('aria-label', change === null ? t('trendNoBaseline') : t('trendVs', { direction: t(`trend${direction[0].toUpperCase()}${direction.slice(1)}`), year: state.comparison, change: `${nf(Math.abs(change), true)}%` }));
  badge.title = badge.getAttribute('aria-label'); return badge;
}
function legend(element, items) {
  element.replaceChildren(...items.map(([label, className]) => { const item = node('span', 'legend-item'); item.append(node('span', `legend-dot ${className}`), document.createTextNode(String(label))); return item; }));
}
function comparisonLegend(element) { legend(element, [[state.year, ''], [state.comparison, 'previous']]); }
function pairRows(element, rows, clickable = false, rank = false) {
  if (!rows.length) { empty(element); return; }
  const maximum = Math.max(1, ...rows.flatMap((row) => [row.a, row.b]));
  element.replaceChildren(...rows.map((item, index) => {
    const row = node(clickable ? 'button' : 'div', 'rank-row');
    if (clickable) { row.type = 'button'; row.addEventListener('click', () => selectEntity(item.kind ?? 'product', item.id)); row.setAttribute('aria-label', `${item.name}, ${nf(item.a)}; ${t('benchmark')}`); }
    row.append(node('span', 'rank-position', rank ? index + 1 : ''));
    const main = node('span'); main.append(node('span', 'rank-name', item.name));
    if (item.description) main.append(node('span', 'rank-description', item.description));
    const bars = svgNode('svg', { viewBox: '0 0 200 12', preserveAspectRatio: 'none', class: 'comparison-bars', 'aria-hidden': 'true' });
    bars.append(svgNode('rect', { x: 0, y: 0, width: number(item.a) / maximum * 200, height: 5, rx: 2, class: 'bar-current' }), svgNode('rect', { x: 0, y: 7, width: number(item.b) / maximum * 200, height: 5, rx: 2, class: 'bar-previous' }));
    main.append(bars);
    const value = node('span', 'rank-value', nf(item.a, item.fractional));
    value.append(node('span', 'rank-comparison', `${state.comparison}: ${nf(item.b, item.fractional)}`));
    if (rank || item.trend) value.append(trendBadge(item.a, item.b));
    row.append(main, value); return row;
  }));
}
function lineChart(element, series, heading) {
  const years = state.summary?.years.map((item) => item.year) ?? [];
  if (!years.length || !series.some((item) => item.values.some((value) => value > 0))) { empty(element); return; }
  const width = 460, height = 198, left = 42, right = 16, top = 12, bottom = 30;
  const max = Math.max(1, ...series.flatMap((item) => item.values));
  const x = (index) => left + index * (width - left - right) / Math.max(1, years.length - 1);
  const y = (value) => height - bottom - value / max * (height - top - bottom);
  const label = heading + '. ' + series.map((item) => `${item.label}: ${years.map((year, index) => `${year}: ${nf(item.values[index], true)}`).join(', ')}`).join('. ');
  const svg = svgNode('svg', { viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': label });
  for (const step of [0, .5, 1]) svg.append(svgNode('line', { x1: left, x2: width - right, y1: y(max * step), y2: y(max * step), class: 'chart-grid' }), svgNode('text', { x: left - 8, y: y(max * step) + 4, class: 'chart-label', 'text-anchor': 'end' }, nf(max * step)));
  years.forEach((year, index) => svg.append(svgNode('text', { x: x(index), y: height - 8, class: 'chart-label', 'text-anchor': 'middle' }, year)));
  for (const item of series) {
    svg.append(svgNode('polyline', { points: item.values.map((value, index) => `${x(index)},${y(value)}`).join(' '), class: `chart-line series-${item.className}` }));
    item.values.forEach((value, index) => svg.append(svgNode('circle', { cx: x(index), cy: y(value), r: years[index] === state.year ? 4 : 2.8, class: `dot-${item.className}` })));
  }
  const chartLegend = node('div', 'legend'); legend(chartLegend, series.map((item) => [item.label, item.className === 'total' ? '' : item.className === 'average' ? 'previous' : item.className]));
  element.replaceChildren(svg, chartLegend);
}
function segments(element, items, active, onClick) {
  element.replaceChildren(...items.map(([value, label]) => { const button = node('button', '', label); button.type = 'button'; button.dataset.value = value; button.setAttribute('aria-pressed', String(active(value))); button.addEventListener('click', () => { onClick(value); for (const sibling of element.children) sibling.setAttribute('aria-pressed', String(active(sibling.dataset.value))); }); return button; }));
}
function buildControls() {
  document.documentElement.lang = state.lang;
  document.title = `Signal Atlas · ${t('title')} · CVE & CISA KEV`;
  document.querySelectorAll('[data-i]').forEach((element) => { element.textContent = t(element.dataset.i); });
  $('language').textContent = state.lang === 'en' ? 'Français' : 'English'; $('language').lang = state.lang === 'en' ? 'fr' : 'en'; $('language').setAttribute('aria-label', t('languageLabel'));
  $('year').setAttribute('aria-label', t('year')); $('comparison').setAttribute('aria-label', t('versus'));
  const years = state.summary?.years.length ? state.summary.years.map((item) => item.year) : Array.from({ length: 7 }, (_, index) => 2020 + index);
  options($('year'), years.map((year) => [year, String(year)]), state.year);
  options($('comparison'), years.map((year) => [year, String(year)]), state.comparison);
  segments($('severity-filter'), SEVERITIES.map((severity) => [severity, t(`s_${severity}`)]), (severity) => state.severities.has(severity), (severity) => { if (state.severities.has(severity)) { if (state.severities.size === 1) return; state.severities.delete(severity); } else state.severities.add(severity); renderSummary(); });
  segments($('metric-filter'), [['all', t('all')], ['crit', t('critical')], ['kev', t('kev')]], (value) => value === state.metric, (value) => { state.metric = value; renderSummary(); });
  segments($('category-filter'), [['All', t('allProducts')], ...CATEGORIES.map((category) => [category, t(`c_${category}`)])], (value) => value === state.category, (value) => { state.category = value; state.reportKind = 'category'; state.reportCategory = value; $('report-category').value = value; updateReportKind(); renderSummary(); });
  const productValue = state.product;
  options($('product'), state.productOptions, productValue);
  $('product').disabled = !rankedProducts().length;
  options($('publisher'), state.publisherOptions, state.publisher);
  $('publisher').disabled = !rankedPublishers().length;
  segments($('benchmark-mode'), [['product', t('productMode')], ['publisher', t('publisherMode')]], (value) => value === state.benchmarkMode, (value) => { state.benchmarkMode = value; renderBenchmark(); });
  const selectedMonth = $('month').value;
  const months = (state.summary?.years ?? []).flatMap((year) => year.months).filter((month) => number(month.count) > 0).sort((a, b) => b.month.localeCompare(a.month));
  options($('month'), months.map((month) => [month.month, `${month.month} · ${nf(month.count)}`]), selectedMonth || months[0]?.month);
  $('load-month').disabled = !months.length || state.monthLoading;
  options($('record-severity'), [['All', t('allSeverity')], ...SEVERITIES.map((severity) => [severity, t(`s_${severity}`)])], $('record-severity').value || 'All');
  options($('record-category'), [['All', t('allCategories')], ...CATEGORIES.map((category) => [category, t(`c_${category}`)])], $('record-category').value || 'All');
  options($('record-kev'), [['All', t('allExploitation')], ['yes', t('kevOnly')], ['no', t('notKev')]], $('record-kev').value || 'All');
  updateStatusOptions();
  updateEvidenceOptions();
  $('search').placeholder = t('sharedSearchPlaceholder'); $('search-results').setAttribute('aria-label', t('searchResultsLabel'));
  $('load-kev').disabled = state.catalogLoading;
  options($('report-product'), state.productOptions, state.product);
  options($('report-category'), [['All', t('allCategories')], ...CATEGORIES.map((category) => [category, t(`c_${category}`)])], state.reportCategory);
  updateReportKind(); renderSearchState();
}
function renderCacheState() {
  const banner = document.querySelector('.cache-banner');
  if (!state.summary) $('classification-note').textContent = t('classificationFallback');
  $('retry').hidden = !state.summaryError;
  if (state.summaryError) { banner.dataset.state = 'error'; $('cache-status').textContent = t('fetchError'); $('coverage').textContent = ''; return; }
  if (!state.summary) { $('cache-status').textContent = t('loading'); return; }
  const coverage = state.summary.coverage ?? {};
  const years = state.summary.years.filter((year) => number(year.total) > 0).map((year) => year.year);
  $('hero-range').textContent = years.length ? `${years[0]}–${years.at(-1)}` : '2020–2026';
  const classification = state.summary.classification;
  $('classification-note').textContent = classification ? t('classificationSummary', { authoritative: nf(classification.authoritative), inferred: nf(classification.inferred), unresolved: nf(classification.unresolved) }) : t('classificationFallback');
  if (number(classification?.partiallyClassified)) $('classification-note').append(document.createTextNode(' ' + t('classificationPartial', { count: nf(classification.partiallyClassified) })));
  if (number(state.summary.excludedRejected)) $('classification-note').append(document.createTextNode(' ' + t('rejectedExcluded', { count: nf(state.summary.excludedRejected) })));
  const labels = state.summary.weaknessLabels;
  $('weakness-source').replaceChildren();
  if (labels?.version) {
    $('weakness-source').append(link(safeHTTPS('https://cwe.mitre.org/data/downloads.html'), t('cweSource', { version: text(labels.version) })));
    if (text(labels.copyright)) $('weakness-source').append(document.createTextNode(' · ' + text(labels.copyright)));
    const terms = safeHTTPS(labels.terms); if (terms) $('weakness-source').append(document.createTextNode(' · '), link(terms, state.lang === 'fr' ? 'Conditions d’utilisation' : 'Terms of use'));
    if (text(labels.license)) $('weakness-source').append(node('br'), document.createTextNode(text(labels.license)));
  }
  const incomplete = !coverage.bootstrapComplete;
  banner.dataset.state = incomplete ? 'warning' : 'ready';
  $('cache-status').textContent = incomplete ? t(number(state.summary.totalCves) ? 'partial' : 'uninitialized') : t('ready', { date: date(state.summary.generatedAt, true) });
  $('coverage').textContent = t('coverage', { start: date(coverage.start || '2020-01-01'), end: date(coverage.end), nvd: date(coverage.nvdLastSync, true), kev: date(coverage.kevLastSync, true) });
}
function renderSummary() {
  renderCacheState();
  renderReportScope();
  const matched = matchedPeriod(), window = state.summary?.comparisonWindow;
  const periodEnd = window?.endMonthDay && /^\d{2}-\d{2}$/.test(window.endMonthDay) ? formatters[state.lang].monthDay.format(new Date(`${state.year}-${window.endMonthDay}T00:00:00Z`)) : date(state.summary?.coverage?.end);
  $('comparison-period').textContent = matched ? t('periodMatched', { end: periodEnd, year: state.year, comparison: state.comparison }) : t('periodFull');
  const current = yearStats(state.year), previous = yearStats(state.comparison);
  const kpis = [[t('unique'), metric(current, 'all'), metric(previous, 'all')], [t('criticalKpi'), metric(current, 'crit'), metric(previous, 'crit')], [t('kevKpi'), metric(current, 'kev'), metric(previous, 'kev')], [t('catalogKpi'), number(state.summary?.catalogKev), null]];
  $('kpis').replaceChildren(...kpis.map(([label, value, before]) => { const card = node('article', 'card span3'); card.append(node('p', 'kpi-label', label), node('p', 'kpi-value', state.summary ? nf(value) : '—')); const foot = node('p', 'kpi-foot'); if (before === null) foot.textContent = t('catalogFoot'); else { foot.append(trendBadge(value, before), document.createTextNode(t('compared', { year: state.comparison, count: nf(before) })), node('br'), document.createTextNode(t('selected', { year: state.year }))); } card.append(foot); return card; }));
  document.querySelector('[data-i="trendSub"]').textContent = trendPeriodLabel();
  lineChart($('trend'), [{ label: t('all'), className: 'total', values: (state.summary?.years ?? []).map((year) => metric(yearStats(year.year), 'all')) }, { label: t('critical'), className: 'critical', values: (state.summary?.years ?? []).map((year) => metric(yearStats(year.year), 'crit')) }, { label: t('kev'), className: 'kev', values: (state.summary?.years ?? []).map((year) => metric(yearStats(year.year), 'kev')) }], t('trend'));
  $('severity-sub').textContent = `${state.year} vs ${state.comparison} · ${t('all')}`;
  pairRows($('severity-chart'), SEVERITIES.filter((severity) => state.severities.has(severity)).map((severity) => ({ name: t(`s_${severity}`), a: number(current?.severity?.[severity]), b: number(previous?.severity?.[severity]) })));
  pairRows($('category-chart'), CATEGORIES.map((category) => ({ name: t(`c_${category}`), a: metric(current?.categories?.[category]), b: metric(previous?.categories?.[category]) })).sort((a, b) => b.a - a.a));
  $('product-limit').textContent = t('productLimit', { count: nf(state.summary?.rankingsLimit?.products ?? 500) });
  $('publisher-limit').textContent = t('publisherLimit', { count: nf(state.summary?.rankingsLimit?.publishers ?? 250) });
  const products = rankedProducts().filter((product) => state.category === 'All' || product.category === state.category).map((product) => ({ id: product.id, name: pretty(product.name), description: `${pretty(product.vendor)} · ${t(`c_${product.category}`)}`, a: metric(entityStats(product, state.year)), b: metric(entityStats(product, state.comparison)) })).filter((product) => product.a > 0).sort((a, b) => b.a - a.a || a.name.localeCompare(b.name)).slice(0, 10);
  pairRows($('top-products'), products, true, true);
  const publishers = rankedPublishers().map((publisher) => ({ id: publisher.name, kind: 'publisher', name: pretty(publisher.name), a: metric(entityStats(publisher, state.year)), b: metric(entityStats(publisher, state.comparison)) })).filter((publisher) => publisher.a > 0).sort((a, b) => b.a - a.a || a.name.localeCompare(b.name)).slice(0, 10);
  pairRows($('top-publishers'), publishers, true, true); comparisonLegend($('ranking-legend'));
  renderStrategic(current);
  $('causes-sub').textContent = t('causesSub', { year: state.year, metric: metricLabel() });
  $('impacts-sub').textContent = t('impactsSub', { year: state.year, metric: metricLabel() });
  renderInsights(current, 'causes', 'impacts', 'causes-coverage', 'impacts-coverage');
  renderBenchmark();
}
function average(products, year) {
  const active = products.filter((product) => number(entityStats(product, year)?.total) > 0);
  return active.length ? active.reduce((sum, product) => sum + metric(entityStats(product, year)), 0) / active.length : 0;
}
function causes(stats) {
  return Object.entries(stats?.insights?.causes ?? {}).filter(([id]) => /^CWE-[1-9]\d{0,5}$/.test(id)).map(([id, bins]) => ({ id, name: weaknessName(id), count: binsMetric(bins) })).filter((item) => item.count > 0).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
}
function insightRows(element, items, total, emptyKey = 'insightUnavailable') {
  if (!items.length) { empty(element, emptyKey); return; }
  element.replaceChildren(...items.map((item) => {
    const row = node('div', 'insight-row'), name = node('span', 'insight-name');
    if (item.id) name.append(weaknessLink(item.id, `${item.id} · ${item.name}`)); else name.textContent = item.name;
    const values = node('span', 'insight-count', nf(item.count));
    values.append(node('span', 'insight-share', `${nf(percent(item.count, total), true)}%`));
    const track = svgNode('svg', { viewBox: '0 0 200 7', preserveAspectRatio: 'none', class: 'insight-track', 'aria-hidden': 'true' });
    track.append(svgNode('rect', { x: 0, y: 0, width: 200, height: 7, rx: 3, class: 'bar-previous' }), svgNode('rect', { x: 0, y: 0, width: Math.min(200, percent(item.count, total) * 2), height: 7, rx: 3, class: 'bar-current' }));
    row.append(name, values, track); return row;
  }));
}
function renderInsights(stats, causeId, impactId, causeCoverageId, impactCoverageId) {
  const total = metric(stats), causeKnown = binsMetric(stats?.insights?.causeKnown), impactKnown = binsMetric(stats?.insights?.impactKnown);
  insightRows($(causeId), causes(stats).slice(0, 5), total, 'causeEmpty');
  const impacts = impactKnown ? ['confidentiality', 'integrity', 'availability'].map((key) => ({ name: t(key), count: binsMetric(stats?.insights?.impacts?.[key]) })).sort((a, b) => b.count - a.count) : [];
  insightRows($(impactId), impacts, total);
  $(causeCoverageId).textContent = t('causeCoverage', { known: nf(causeKnown), total: nf(total), percent: nf(percent(causeKnown, total), true) });
  $(impactCoverageId).textContent = t('impactCoverage', { known: nf(impactKnown), total: nf(total), percent: nf(percent(impactKnown, total), true) });
}
function renderStrategic(stats) {
  const total = metric(stats), topCause = causes(stats)[0], known = binsMetric(stats?.insights?.causeKnown), impactKnown = binsMetric(stats?.insights?.impactKnown);
  const impacts = ['confidentiality', 'integrity', 'availability'].map((key) => ({ key, count: binsMetric(stats?.insights?.impacts?.[key]) })).sort((a, b) => b.count - a.count);
  const leadingImpact = impacts[0]?.count > 0 ? impacts[0] : null;
  const exploited = state.metric === 'crit' ? state.severities.has('Critical') ? number(stats?.kevSeverity?.Critical) : 0 : metric(stats, 'kev');
  const items = [
    [t('signalKev'), `${nf(percent(exploited, total), true)}%`, `${t('signalKevNote')} · ${metricLabel()}`],
    [t('signalRemote'), nf(binsMetric(stats?.insights?.remoteUnauthenticated)), t('signalRemoteCoverage', { known: nf(binsMetric(stats?.insights?.reachKnown)), total: nf(total) })],
    [t('signalCause'), topCause ? topCause.id : '—', topCause ? `${topCause.name} · ${t('signalCauseNote', { count: nf(topCause.count), share: nf(percent(topCause.count, total), true) })}` : t('causeEmpty')],
    [t('signalImpact'), leadingImpact ? t(leadingImpact.key) : '—', leadingImpact ? t('signalImpactNote', { count: nf(leadingImpact.count), share: nf(percent(leadingImpact.count, total), true), coverage: nf(percent(impactKnown, total), true) }) : t(impactKnown ? 'noImpactReported' : 'insightUnavailable')],
  ];
  $('strategic-insights').replaceChildren(...items.map(([label, value, note]) => { const card = node('article', 'signal-card'); card.append(node('p', 'signal-label', label), node('p', 'signal-value', state.summary ? value : '—'), node('p', 'signal-note', note)); return card; }));
}
function renderBenchmark() {
  const publisherMode = state.benchmarkMode === 'publisher';
  document.querySelector('.product-control').hidden = publisherMode;
  document.querySelector('.publisher-control').hidden = !publisherMode;
  for (const button of $('benchmark-mode').children) button.setAttribute('aria-pressed', String(button.dataset.value === state.benchmarkMode));
  const entity = publisherMode ? rankedPublishers().find((item) => item.name === state.publisher) : rankedProducts().find((item) => item.id === state.product);
  $('benchmark-average-title').textContent = t(publisherMode ? 'publisherAverage' : 'average');
  $('benchmark-trend-title').textContent = t(publisherMode ? 'publisherTrend' : 'productTrend');
  $('benchmark-average-sub').textContent = t('peerNote');
  $('benchmark-trend-sub').textContent = trendPeriodLabel();
  $('benchmark-publisher').replaceChildren();
  if (!entity) {
    $('benchmark-sentence').textContent = t(publisherMode ? 'publisherBenchmarkEmpty' : 'benchmarkEmpty'); empty($('benchmark-bars')); empty($('product-trend'));
    renderInsights(null, 'benchmark-causes', 'benchmark-impacts', 'benchmark-causes-coverage', 'benchmark-impacts-coverage'); return;
  }
  const peers = publisherMode ? rankedPublishers() : rankedProducts().filter((item) => item.category === entity.category);
  const allPeers = publisherMode ? rankedPublishers() : rankedProducts();
  const active = peers.filter((item) => number(entityStats(item, state.year)?.total) > 0);
  const stats = entityStats(entity, state.year), value = metric(stats);
  const rank = active.filter((item) => metric(entityStats(item, state.year)) > value).length + 1;
  $('benchmark-sentence').textContent = t(publisherMode ? 'publisherBenchmarkSentence' : 'benchmarkSentence', { product: pretty(entity.name), count: nf(value), year: state.year, rank: number(stats?.total) ? rank : '—', total: nf(active.length), average: nf(average(peers, state.year), true) });
  const peerLabel = t(publisherMode ? 'publisherAverageLabel' : 'categoryAverage');
  const rows = [{ name: pretty(entity.name), a: value, b: metric(entityStats(entity, state.comparison)), trend: true }, { name: peerLabel, a: average(peers, state.year), b: average(peers, state.comparison), fractional: true }];
  if (!publisherMode) rows.push({ name: t('globalAverage'), a: average(allPeers, state.year), b: average(allPeers, state.comparison), fractional: true });
  pairRows($('benchmark-bars'), rows);
  lineChart($('product-trend'), [{ label: pretty(entity.name), className: 'total', values: state.summary.years.map((year) => metric(entityStats(entity, year.year))) }, { label: peerLabel, className: 'average', values: state.summary.years.map((year) => average(peers, year.year)) }], t(publisherMode ? 'publisherTrend' : 'productTrend'));
  renderInsights(stats, 'benchmark-causes', 'benchmark-impacts', 'benchmark-causes-coverage', 'benchmark-impacts-coverage');
  if (!publisherMode) {
    const publisher = rankedPublishers().find((item) => item.name === entity.vendor);
    if (publisher) {
      const publisherButton = node('button', 'publisher-link', pretty(publisher.name)); publisherButton.type = 'button'; publisherButton.addEventListener('click', () => selectEntity('publisher', publisher.name));
      $('benchmark-publisher').append(node('span', '', t('publisherAttribution', { publisher: pretty(publisher.name), count: nf(metric(entityStats(publisher, state.year))) })), document.createTextNode(' '), publisherButton);
    } else $('benchmark-publisher').textContent = `${t('vendor')}: ${pretty(entity.vendor)}`;
  }
}
function selectEntity(kind, id) {
  state.benchmarkMode = kind;
  state[kind] = id; $(kind).value = id;
  if (kind === 'product') { state.reportKind = 'product'; $('report-product').value = id; updateReportKind(); }
  renderBenchmark();
  $('benchmark').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' }); $(kind).focus({ preventScroll: true });
}
function renderPriority() {
  const records = (state.summary?.priorityRecords ?? []).filter((record) => record && /^CVE-\d{4}-\d{4,}$/.test(record.id) && record.kev && text(record.status).toLowerCase() !== 'rejected').slice(0, 30);
  const visible = records.slice(0, state.priorityExpanded ? 30 : 5);
  $('priority-more').hidden = records.length <= 5; $('priority-more').textContent = t(state.priorityExpanded ? 'showLess' : 'showMore');
  $('priority-note').textContent = t('priorityNote', { shown: nf(visible.length), available: nf(records.length) });
  if (!visible.length) { empty($('priority-records'), 'priorityEmpty'); return; }
  $('priority-records').replaceChildren(...visible.map((record) => {
    const row = node('article', 'priority-row'), main = node('div', 'priority-main'), action = node('div', 'priority-action');
    const title = node('button', 'record-id', record.id); title.type = 'button'; title.addEventListener('click', () => showDetail(record));
    main.append(title, node('p', 'record-title', `${text(record.kevDetails?.vendorProject)} · ${text(record.kevDetails?.product)}`));
    const meta = node('div', 'priority-meta'); meta.append(node('span', 'pill kev', 'CISA KEV'));
    if (record.severity && record.score !== null && record.score !== undefined) meta.append(node('span', `pill ${SEVERITIES.includes(record.severity) ? record.severity : 'Unknown'}`, `${t(`s_${record.severity}`)} ${nf(record.score, true)}`));
    else meta.append(node('span', 'pill Unknown', t('pending')));
    meta.append(node('span', '', `${t('dateAdded')}: ${date(record.kevDetails?.dateAdded)}`)); main.append(meta);
    if (recordCategories(record).some((category) => category !== 'Unknown')) main.append(node('p', 'record-meta', recordCategories(record).map((category) => t(`c_${category}`)).join(', ')));
    action.append(node('span', 'control-label', t('requiredAction')), node('p', '', text(record.kevDetails?.requiredAction, t('unknown'))));
    const inspect = node('button', '', t('priorityDetails')); inspect.type = 'button'; inspect.addEventListener('click', () => showDetail(record)); action.append(inspect);
    row.append(main, action); return row;
  }));
}
function validateSummary(data) {
  if (data?.schemaVersion !== 1 || !Array.isArray(data.years) || !Array.isArray(data.products) || !Array.isArray(data.publishers) || data.products.length > 1000 || data.publishers.length > 1000) throw new Error('Invalid summary schema');
  const years = data.years.filter((year) => Number.isInteger(year.year) && year.year >= 1900 && year.year <= 9998);
  if (new Set(years.map((year) => year.year)).size !== years.length) throw new Error('Duplicate summary years');
  data.years = years.sort((a, b) => a.year - b.year).map((year) => ({ ...year, months: Array.isArray(year.months) ? year.months.filter((month) => /^\d{4}-(0[1-9]|1[0-2])$/.test(month.month) && Number(month.month.slice(0, 4)) === year.year) : [] }));
  data.products = data.products.filter((product) => typeof product.id === 'string' && typeof product.name === 'string' && CATEGORIES.includes(product.category));
  data.publishers = data.publishers.filter((publisher) => typeof publisher.name === 'string');
  if (data.priorityRecords !== undefined && (!Array.isArray(data.priorityRecords) || data.priorityRecords.length > 30)) throw new Error('Invalid priority records');
  const window = data.comparisonWindow;
  if (window && (!Number.isInteger(window.partialYear) || !/^\d{2}-\d{2}$/.test(window.endMonthDay) || !Number.isFinite(new Date(`${window.partialYear}-${window.endMonthDay}T00:00:00Z`).getTime()))) throw new Error('Invalid comparison window');
  return data;
}
async function loadSummary() {
  state.summaryError = false; renderCacheState();
  try {
    state.summary = validateSummary(await fetchJSON('/data/summary.json.gz', 16_000_000));
    state.productOptions = [...rankedProducts()].sort((a, b) => a.name.localeCompare(b.name)).map((product) => [product.id, `${pretty(product.name)} (${pretty(product.vendor)})`]);
    state.publisherOptions = [...rankedPublishers()].sort((a, b) => a.name.localeCompare(b.name)).map((publisher) => [publisher.name, pretty(publisher.name)]);
    const populatedYears = state.summary.years.filter((year) => year.total > 0);
    if (populatedYears.length) { state.year = populatedYears.at(-1).year; state.comparison = populatedYears.at(-2)?.year ?? state.summary.years.find((year) => year.year === state.year - 1)?.year ?? state.year; }
    state.product = rankedProducts()[0]?.id ?? '';
    state.publisher = rankedPublishers()[0]?.name ?? '';
  } catch { state.summaryError = true; }
  buildControls(); renderSummary(); renderRecords(); renderCatalog(); renderPriority();
}
function updateReportKind() {
  if (!$('report-kind').children.length || $('report-kind').dataset.lang !== state.lang) {
    segments($('report-kind'), [['product', t('product')], ['category', t('reportCategoryMode')]], (kind) => kind === state.reportKind, (kind) => { state.reportKind = kind; updateReportKind(); });
    $('report-kind').dataset.lang = state.lang;
  }
  for (const button of $('report-kind').children) button.setAttribute('aria-pressed', String(button.dataset.value === state.reportKind));
  $('report-kind').setAttribute('aria-label', t('reportSubjectLabel'));
  $('report-product-control').hidden = state.reportKind !== 'product';
  $('report-category-control').hidden = state.reportKind !== 'category';
  renderReportScope();
}
function reportSelection() {
  if (state.reportKind === 'category') return { kind: 'category', id: state.reportCategory, name: state.reportCategory === 'All' ? t('allCategories') : t(`c_${state.reportCategory}`) };
  const product = rankedProducts().find((item) => item.id === state.product);
  return { kind: 'product', id: state.product, name: product ? `${pretty(product.name)} (${pretty(product.vendor)})` : '' };
}
function reportPath(subject) {
  const path = state.summary?.reportPaths?.[subject.kind === 'product' ? 'products' : 'categories']?.[subject.id];
  const validId = subject.kind === 'product' ? /^[a-f0-9]{24}$/.test(subject.id) : ['All', ...CATEGORIES].includes(subject.id);
  const expected = `intel/${subject.kind === 'product' ? 'products' : 'categories'}-${subject.id}.json.gz`;
  return validId && path === expected ? `/data/${path}` : null;
}
function renderReportScope() {
  const subject = reportSelection(), available = Boolean(reportPath(subject));
  $('report-scope').textContent = available ? t('reportScope', { subject: subject.name, year: state.year, comparison: state.comparison }) : t('reportUnavailable');
  $('create-report').disabled = state.reportLoading || !available;
  $('create-report').textContent = t(state.reportLoading ? 'reportBusy' : 'createReport');
  $('create-report').setAttribute('aria-busy', String(state.reportLoading));
  renderReportFeedback();
}
function setReportFeedback(key, values = {}) { state.reportFeedback = { key, values }; renderReportFeedback(); }
function renderReportFeedback() {
  const feedback = state.reportFeedback; if (!feedback) return;
  const values = { ...feedback.values };
  if (values.subject) values.subject = values.subject.kind === 'category' ? (values.subject.id === 'All' ? t('allCategories') : t(`c_${values.subject.id}`)) : values.subject.name;
  if (values.pages !== undefined) values.pages = nf(values.pages);
  $('report-status').textContent = t(feedback.key, values);
  if (!state.reportLoading && values.subject && ! $('report-download').hidden) $('report-download').textContent = `${t('downloadReport')} · ${values.subject} · ${values.year}`;
}
let reportUrl = null;
async function createReport() {
  if (state.reportLoading) return;
  const subject = reportSelection(), path = reportPath(subject);
  if (!path) return;
  const summary = state.summary, year = state.year, comparison = state.comparison, lang = state.lang;
  // Open during the click gesture, then sever the opener before any async work.
  const popup = window.open('about:blank', '_blank');
  if (popup) {
    popup.opener = null;
    popup.document.title = 'Signal Atlas - PDF';
    const message = popup.document.createElement('p'); message.textContent = t('reportPreparingTab');
    popup.document.body.replaceChildren(message);
  }
  state.reportLoading = true; renderReportScope();
  setReportFeedback('reportLoading'); $('report-download').hidden = true;
  try {
    const [pack, module] = await Promise.all([fetchJSON(path, 8_000_000), import('./report-pdf.js')]);
    if (pack?.schemaVersion !== 1 || pack.subject?.kind !== subject.kind || pack.subject?.id !== subject.id || pack.generatedAt !== summary.generatedAt || pack.coverage?.end !== summary.coverage?.end || !Array.isArray(pack.years) || pack.years.length > 20 || !Array.isArray(pack.relatedKev) || !Array.isArray(pack.supplementalKev) || pack.relatedKev.length + pack.supplementalKev.length > 20_000) throw new Error('Invalid report fact pack');
    const { blob, filename, pages } = await module.createIntelPdf({ summary, pack, year, comparison, lang, onStatus: (progress) => {
      if (progress.stage === 'advisories') $('report-status').textContent = `${t('reportLoading')} ${nf(progress.completed)} / ${nf(progress.total)} ${state.lang === 'fr' ? 'avis KEV' : 'KEV advisories'}.`;
    } });
    if (!(blob instanceof Blob) || blob.type !== 'application/pdf' || blob.size > 64_000_000 || blob.size < 100) throw new Error('Invalid PDF output');
    const url = URL.createObjectURL(blob); reportUrl = url;
    const download = $('report-download'); download.href = url; download.download = filename; download.textContent = `${t('downloadReport')} · ${subject.name} · ${year}`; download.hidden = false;
    let opened = false;
    if (popup && !popup.closed) { try { popup.location.replace(url); opened = true; } catch { /* Download remains available. */ } }
    setReportFeedback(opened ? 'reportReady' : 'reportPopupBlocked', { subject, year, pages });
    // Leave enough time for viewing, saving and printing an already-open PDF.
    setTimeout(() => { URL.revokeObjectURL(url); if (reportUrl === url) { reportUrl = null; download.hidden = true; } }, 30 * 60 * 1000);
  } catch {
    if (popup && !popup.closed) { try { if (popup.location.href === 'about:blank') popup.close(); } catch { /* User may have navigated away. */ } }
    setReportFeedback('reportError');
  } finally { state.reportLoading = false; renderReportScope(); }
}
function recordCauses(record) {
  return (Array.isArray(record.insights?.causes) ? record.insights.causes : Array.isArray(record.weaknesses) ? record.weaknesses : []).filter((id) => typeof id === 'string' && /^CWE-[1-9]\d{0,5}$/.test(id));
}
function updateEvidenceOptions() {
  const cause = $('record-cause').value || 'All', impact = $('record-impact').value || 'All';
  const ids = [...new Set((state.monthRecords ?? []).flatMap(recordCauses))].sort((a, b) => weaknessName(a).localeCompare(weaknessName(b)));
  options($('record-cause'), [['All', t('allWeaknesses')], ...ids.map((id) => [id, `${id} · ${weaknessName(id)}`])], ids.includes(cause) ? cause : 'All');
  options($('record-impact'), [['All', t('allImpacts')], ...['confidentiality', 'integrity', 'availability'].map((key) => [key, t(key)])], impact);
}
function updateStatusOptions() {
  const value = $('record-status').value || 'All';
  const statuses = [...new Set((state.monthRecords ?? []).map((record) => text(record.status)).filter(Boolean))].sort();
  options($('record-status'), [['All', t('allStatus')], ...statuses.map((status) => [status, status])], statuses.includes(value) ? value : 'All');
}
function resetMonth() {
  state.monthAbort?.abort(); state.monthAbort = null; state.monthRecords = null; state.loadedMonth = ''; state.monthPage = 1; state.monthLoading = false; state.monthError = false;
  monthFilterCache = null;
  $('load-month').disabled = !$('month').value; updateStatusOptions(); updateEvidenceOptions(); renderRecords();
}
async function loadMonth() {
  const month = (state.summary?.years ?? []).flatMap((year) => year.months).find((item) => item.month === $('month').value);
  if (!month || state.monthLoading) return;
  resetMonth(); const controller = new AbortController(); state.monthAbort = controller; state.monthLoading = true; state.loadedMonth = month.month;
  $('load-month').disabled = true; renderRecords();
  try {
    if (!Array.isArray(month.paths) || month.paths.length > 100 || !month.paths.every((path) => new RegExp(`^records/${month.month}-[0-9]{4,8}\\.json(?:\\.gz)?$`).test(path))) throw new Error('Unsafe cache paths');
    const records = []; let next = 0;
    // A month is loaded on demand. Three workers bound network concurrency and
    // the previous month's data is released rather than retaining all years.
    await Promise.all(Array.from({ length: Math.min(3, month.paths.length) }, async () => {
      while (next < month.paths.length && !controller.signal.aborted) {
        const path = month.paths[next++]; const payload = await fetchJSON(`/data/${path}`, 16_000_000, controller.signal);
        if (!Array.isArray(payload) && (payload.schemaVersion !== 1 || payload.month !== month.month)) throw new Error('Invalid record page schema');
        const pageRecords = Array.isArray(payload) ? payload : payload.records;
        if (!Array.isArray(pageRecords) || pageRecords.length > 1000) throw new Error('Invalid record page');
        records.push(...pageRecords);
        if (records.length > 100_000) throw new Error('Record limit exceeded');
      }
    }));
    if (state.monthAbort !== controller) return;
    if (records.length !== number(month.count) || new Set(records.map((record) => record.id)).size !== records.length || records.some((record) => !/^CVE-\d{4}-\d{4,}$/.test(record.id) || !SEVERITIES.includes(record.severity) || text(record.status).trim().toLowerCase() === 'rejected')) throw new Error('Incomplete or invalid records');
    state.monthRecords = records.sort((a, b) => text(b.published).localeCompare(text(a.published)) || b.id.localeCompare(a.id)); indexRecords(state.monthRecords); monthFilterCache = null; state.monthError = false;
  } catch {
    if (state.monthAbort !== controller) return;
    controller.abort(); state.monthRecords = null; state.monthError = true;
  } finally {
    if (state.monthAbort === controller) { state.monthAbort = null; state.monthLoading = false; $('load-month').disabled = false; updateStatusOptions(); updateEvidenceOptions(); renderRecords(); }
  }
}
function filteredRecords() {
  const query = $('search').value.trim().toLocaleLowerCase(), severity = $('record-severity').value, kev = $('record-kev').value, status = $('record-status').value, category = $('record-category').value, cause = $('record-cause').value, impact = $('record-impact').value;
  const key = JSON.stringify([query, severity, kev, status, category, cause, impact]);
  if (monthFilterCache?.source === state.monthRecords && monthFilterCache.key === key) return monthFilterCache.records;
  const records = (state.monthRecords ?? []).filter((record) => (severity === 'All' || record.severity === severity) && (kev === 'All' || Boolean(record.kev) === (kev === 'yes')) && (status === 'All' || record.status === status) && (category === 'All' || recordCategories(record).includes(category)) && (cause === 'All' || recordCauses(record).includes(cause)) && (impact === 'All' || record.insights?.impacts?.includes(impact)) && (!query || searchIndex.get(record)?.includes(query)));
  monthFilterCache = { source: state.monthRecords, key, records }; return records;
}
function pagination(element, total, page, change) {
  const pages = Math.ceil(total / PAGE_SIZE);
  if (!pages) { element.replaceChildren(); return; }
  const previous = node('button', '', t('previous')); previous.type = 'button'; previous.disabled = page === 1; previous.addEventListener('click', () => change(page - 1));
  const next = node('button', '', t('next')); next.type = 'button'; next.disabled = page >= pages; next.addEventListener('click', () => change(page + 1));
  element.replaceChildren(previous, node('span', '', t('page', { page: nf(page), total: nf(pages) })), next);
}
function recordRow(record, catalog = false) {
  const row = node('article', 'record-row'), id = catalog ? record.cveID : record.id;
  const button = node('button', 'record-id', id); button.type = 'button'; button.addEventListener('click', () => showDetail(catalog ? { id, description: record.shortDescription, kev: true, kevDetails: record, references: [] } : record));
  const description = node('div'); description.append(node('p', 'record-title', catalog ? record.vulnerabilityName || record.shortDescription : record.description || t('noDescription')));
  const meta = catalog ? `${text(record.vendorProject)} · ${text(record.product)}` : `${t('status')}: ${text(record.status, t('unknown'))} · ${recordCategories(record).map((category) => t(`c_${category}`)).join(', ')}${record.vendors?.length ? ' · ' + record.vendors.slice(0, 2).map(pretty).join(', ') : ''}`;
  description.append(node('p', 'record-meta', meta));
  const tags = node('div', 'record-tags');
  if (!catalog) tags.append(node('span', `pill ${SEVERITIES.includes(record.severity) ? record.severity : 'Unknown'}`, `${t(`s_${record.severity}`)}${record.score !== null && record.score !== undefined ? ' ' + nf(record.score, true) : ''}`));
  if (catalog || record.kev) tags.append(node('span', 'pill kev', 'KEV'));
  if (catalog && Number(id?.split('-')[1]) < 2020) tags.append(node('span', 'pill', t('legacy')));
  const dates = node('p', 'record-date', `${catalog ? t('dateAdded') : t('published')}\n${date(catalog ? record.dateAdded : record.published)}`);
  row.append(button, description, tags, dates); return row;
}
function renderRecords() {
  renderSearchState();
  const message = $('record-message'); $('explorer-count').textContent = '';
  if (state.monthLoading) { message.textContent = t('loadingMonth', { month: state.loadedMonth }); $('records').replaceChildren(); $('record-pagination').replaceChildren(); return; }
  if (state.monthError) { message.textContent = t('errorMonth') + ' ' + t('collectionMismatch'); $('records').replaceChildren(); $('record-pagination').replaceChildren(); return; }
  if (!state.monthRecords) { message.textContent = t($('month').value ? 'selectMonth' : 'noMonths'); $('records').replaceChildren(); $('record-pagination').replaceChildren(); return; }
  const records = filteredRecords(); state.monthPage = Math.min(state.monthPage, Math.max(1, Math.ceil(records.length / PAGE_SIZE)));
  message.textContent = t('loadedMonth', { count: nf(state.monthRecords.length), month: state.loadedMonth }); $('explorer-count').textContent = t('matches', { count: nf(records.length) });
  if (!records.length) empty($('records')); else $('records').replaceChildren(...records.slice((state.monthPage - 1) * PAGE_SIZE, state.monthPage * PAGE_SIZE).map((record) => recordRow(record)));
  pagination($('record-pagination'), records.length, state.monthPage, (page) => { state.monthPage = page; renderRecords(); $('record-pagination').querySelector('button:not(:disabled)')?.focus(); });
}
async function loadCatalog() {
  if (state.catalogLoading) return; state.catalogLoading = true; state.catalogError = false; $('load-kev').disabled = true; renderCatalog();
  try {
    const catalog = await fetchJSON('/data/kev.json', 16_000_000);
    if (catalog?.schemaVersion !== 1 || !Array.isArray(catalog.vulnerabilities) || catalog.vulnerabilities.length > 20_000 || catalog.vulnerabilities.some((item) => !/^CVE-\d{4}-\d{4,}$/.test(item.cveID))) throw new Error('Invalid KEV schema');
    catalog.vulnerabilities.sort((a, b) => text(b.dateAdded).localeCompare(text(a.dateAdded)) || b.cveID.localeCompare(a.cveID)); indexRecords(catalog.vulnerabilities, true); catalogFilterCache = null; state.catalog = catalog; state.catalogPage = 1;
  } catch { state.catalogError = true; } finally { state.catalogLoading = false; $('load-kev').disabled = false; renderCatalog(); }
}
function renderCatalog() {
  renderSearchState();
  const message = $('kev-message');
  if (state.catalogLoading || state.catalogError || !state.catalog) { message.textContent = t(state.catalogLoading ? 'loadingCatalog' : state.catalogError ? 'catalogError' : 'kevInitial'); $('kev-records').replaceChildren(); $('kev-pagination').replaceChildren(); return; }
  message.textContent = state.catalog.vulnerabilities.length ? t('catalogLoaded', { count: nf(state.catalog.vulnerabilities.length), version: text(state.catalog.catalogVersion, '—'), date: date(state.catalog.dateReleased) }) : t('noCatalog');
  const records = filteredCatalog();
  state.catalogPage = Math.min(state.catalogPage, Math.max(1, Math.ceil(records.length / PAGE_SIZE)));
  if (!records.length) empty($('kev-records')); else $('kev-records').replaceChildren(...records.slice((state.catalogPage - 1) * PAGE_SIZE, state.catalogPage * PAGE_SIZE).map((record) => recordRow(record, true)));
  pagination($('kev-pagination'), records.length, state.catalogPage, (page) => { state.catalogPage = page; renderCatalog(); $('kev-pagination').querySelector('button:not(:disabled)')?.focus(); });
}
function filteredCatalog() {
  if (!state.catalog) return [];
  const query = $('search').value.trim().toLocaleLowerCase();
  if (catalogFilterCache?.source !== state.catalog.vulnerabilities || catalogFilterCache.query !== query) catalogFilterCache = { source: state.catalog.vulnerabilities, query, records: query ? state.catalog.vulnerabilities.filter((record) => searchIndex.get(record)?.includes(query)) : state.catalog.vulnerabilities };
  return catalogFilterCache.records;
}
function renderSearchState() {
  $('search-cve-results').textContent = state.monthLoading ? t('loadingMonth', { month: state.loadedMonth }) : state.monthError ? t('errorMonth') : state.monthRecords ? t('searchCves', { count: nf(filteredRecords().length) }) : t('searchLoadCves');
  $('search-kev-results').textContent = state.catalogLoading ? t('loadingCatalog') : state.catalogError ? t('catalogError') : state.catalog ? t('searchKev', { count: nf(filteredCatalog().length) }) : t('searchLoadKev');
}
function detailsGrid(items) {
  const grid = node('dl', 'detail-grid');
  for (const [label, value] of items) { const item = node('div'); item.append(node('dt', '', label), node('dd', '', value || t('unknown'))); grid.append(item); }
  return grid;
}
function showDetail(record) {
  $('detail-title').textContent = record.id; const body = $('detail-body'); body.replaceChildren();
  const tags = node('div');
  if (record.severity) tags.append(node('span', `pill ${SEVERITIES.includes(record.severity) ? record.severity : 'Unknown'}`, t(`s_${record.severity}`)));
  if (record.kev) tags.append(node('span', 'pill kev', 'CISA KEV'));
  body.append(tags, node('p', 'detail-description', text(record.description, t('noDescription'))));
  if (record.published) body.append(detailsGrid([[t('published'), date(record.published, true)], [t('modified'), date(record.modified, true)], [t('status'), record.status], [t('score'), record.score !== null && record.score !== undefined ? `${nf(record.score, true)} · CVSS ${text(record.cvssVersion)}` : t('pending')], [t('vector'), record.vector || t('pending')]]));
  const nvd = safeHTTPS(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(record.id)}`); if (nvd) body.append(link(nvd, t('nvdRecord')));
  if (record.kevDetails) {
    const kev = record.kevDetails;
    body.append(node('h3', 'detail-heading', t('kevDetails')), detailsGrid([[t('dateAdded'), date(kev.dateAdded)], [t('dueDate'), date(kev.dueDate)], [t('ransomware'), kev.knownRansomwareCampaignUse]]), node('p', 'detail-note', `${t('requiredAction')}: ${text(kev.requiredAction, t('unknown'))}`));
    if (kev.notes) body.append(node('p', 'detail-description', `${t('notes')}: ${text(kev.notes)}`));
    body.append(link(safeHTTPS('https://www.cisa.gov/known-exploited-vulnerabilities-catalog'), t('navKev')));
    if (record.nvdCached === false) body.append(node('p', 'detail-note', t('nvdNotCached')));
  }
  if (record.published || record.nvdCached === false) {
    body.append(node('h3', 'detail-heading', t('categoryDetail')));
    const evidence = Array.isArray(record.categoryEvidence) ? record.categoryEvidence.filter((item) => item && CATEGORIES.includes(item.category) && ['cpe', 'affected', 'kev', 'description'].includes(item.source)).slice(0, 20) : [];
    body.append(node('p', 'muted', recordCategories(record).map((category) => t(`c_${category}`)).join(', ')));
    if (evidence.length) {
      const list = node('ul', 'detail-list');
      for (const item of evidence) {
        const unresolved = item.category === 'Unknown';
        const authoritative = !unresolved && (item.authoritative === true || item.source === 'cpe');
        const source = item.source === 'affected' && authoritative ? 'cnaCpe' : item.source;
        list.append(node('li', '', `${t(`c_${item.category}`)}${unresolved ? '' : ' · ' + t(authoritative ? 'categoryAuthoritative' : 'categoryInferred')} · ${t(`source_${source}`)}${text(item.reason) ? ': ' + text(item.reason) : ''}`));
      }
      body.append(list);
      if (evidence.some((item) => item.category !== 'Unknown' && item.authoritative !== true && item.source !== 'cpe')) body.append(node('p', 'detail-note', t('categoryInferredNote')));
    } else body.append(node('p', 'detail-note', t(recordCategories(record).includes('Unknown') ? 'categoryUnresolved' : 'classificationFallback')));
    body.append(node('h3', 'detail-heading', t('products')));
    const products = Array.isArray(record.products) ? record.products : [];
    if (products.length) { const list = node('ul', 'detail-list'); products.slice(0, 100).forEach((product) => list.append(node('li', '', `${pretty(product.vendor)} · ${pretty(product.name)} · ${t(`c_${product.category}`)}`))); body.append(list); } else body.append(node('p', 'muted', t('noProductsDetail')));
    body.append(node('h3', 'detail-heading', t('weaknesses')));
    const weaknesses = recordCauses(record).slice(0, 30);
    if (weaknesses.length) { const list = node('ul', 'detail-list'); for (const id of weaknesses) { const item = node('li'); item.append(weaknessLink(id, `${id} · ${weaknessName(id)}`)); list.append(item); } body.append(list); }
    else body.append(node('p', 'muted', t('noWeaknesses')));
    body.append(node('h3', 'detail-heading', t('assessedImpact')), node('p', 'detail-note', t('impactAssessmentNote')));
    const impacts = Array.isArray(record.insights?.impacts) ? record.insights.impacts.filter((key) => ['confidentiality', 'integrity', 'availability'].includes(key)) : [];
    body.append(node('p', 'muted', record.insights?.impactKnown ? impacts.length ? impacts.map((key) => t(key)).join(' · ') : t('noImpactReported') : t('insightUnavailable')));
    if (record.insights?.remoteUnauthenticated === true) body.append(node('p', 'detail-note', t('networkAssessment')));
  }
  body.append(node('h3', 'detail-heading', t('references')), node('p', 'subtitle', t('referenceNote')));
  const references = [...new Set(Array.isArray(record.references) ? record.references : [])].map(safeHTTPS).filter(Boolean).slice(0, 50);
  if (references.length) { const list = node('ul', 'detail-list'); references.forEach((url) => { const item = node('li'); item.append(link(url, url.hostname + url.pathname)); list.append(item); }); body.append(list); } else body.append(node('p', 'muted', t('noReferences')));
  $('detail').showModal(); $('close-detail').focus();
}
function setTheme(dark) { document.documentElement.dataset.theme = dark ? 'dark' : 'light'; $('theme').setAttribute('aria-pressed', String(dark)); storage('vl-theme', dark ? 'dark' : 'light'); }
function debounce(callback) { let timeout; return () => { clearTimeout(timeout); timeout = setTimeout(callback, 180); }; }
$('theme').addEventListener('click', () => setTheme(document.documentElement.dataset.theme !== 'dark'));
$('language').addEventListener('click', () => { state.lang = state.lang === 'en' ? 'fr' : 'en'; storage('vl-language', state.lang); buildControls(); renderSummary(); renderRecords(); renderCatalog(); renderPriority(); });
$('year').addEventListener('change', () => { state.year = Number($('year').value); renderSummary(); });
$('comparison').addEventListener('change', () => { state.comparison = Number($('comparison').value); renderSummary(); });
$('product').addEventListener('change', () => { state.product = $('product').value; state.reportKind = 'product'; $('report-product').value = state.product; updateReportKind(); renderBenchmark(); });
$('report-product').addEventListener('change', () => { state.product = $('report-product').value; $('product').value = state.product; renderBenchmark(); renderReportScope(); });
$('report-category').addEventListener('change', () => { state.reportCategory = $('report-category').value; renderReportScope(); });
$('create-report').addEventListener('click', createReport);
$('publisher').addEventListener('change', () => { state.publisher = $('publisher').value; renderBenchmark(); });
$('priority-more').addEventListener('click', () => { state.priorityExpanded = !state.priorityExpanded; renderPriority(); $('priority-more').focus(); });
$('retry').addEventListener('click', loadSummary);
$('month').addEventListener('change', resetMonth);
$('load-month').addEventListener('click', loadMonth);
$('search').addEventListener('input', debounce(() => { state.monthPage = 1; state.catalogPage = 1; renderRecords(); renderCatalog(); if ($('search').value.trim() && !state.catalog && !state.catalogLoading && !state.catalogError) loadCatalog(); }));
for (const id of ['record-severity', 'record-category', 'record-kev', 'record-status', 'record-cause', 'record-impact']) $(id).addEventListener('change', () => { state.monthPage = 1; renderRecords(); if (id === 'record-category') { state.reportKind = 'category'; state.reportCategory = $('record-category').value; $('report-category').value = state.reportCategory; updateReportKind(); } });
$('load-kev').addEventListener('click', loadCatalog);
$('close-detail').addEventListener('click', () => $('detail').close());
$('detail').addEventListener('click', (event) => { if (event.target === $('detail')) { const box = $('detail').getBoundingClientRect(); if (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom) $('detail').close(); } });
setTheme((storage('vl-theme') ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')) === 'dark');
buildControls(); renderSummary(); renderRecords(); renderCatalog(); renderPriority();
loadSummary();
