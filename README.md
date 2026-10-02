# Signal Atlas

A portfolio dashboard based on NVD CVEs and CISA's Known Exploited Vulnerabilities catalog. Signal Atlas presents a compact introduction and simple dashboard, with data freshness and classification transparency in the footer. The visual layout follows the supplied `Vulnerability Landscape.html`; the original keyword/inventory restrictions and generated example data have been removed.

```text
NVD CVE API + CISA KEV catalog
             ↓ Python fetchers
      persistent SQLite cache
             ↓ export_dashboard.py
   summary + monthly JSON shards + full KEV catalog
             ↓ Vite build
      static dashboard on Vercel
```

## Run locally

Use Python 3.12+ and Node.js 22.12+ (or Node 24). Python uses the standard library; no pip packages or database service are required.

```sh
npm ci
python cvefetcher.py --start-year 2020 --end-year 2026
python fetch_cisakev.py
python export_dashboard.py
npm run dev
```

The first NVD import fetches **all CVEs by publication date** from January 1, 2020 through December 31, 2026, capped at the current UTC time. Future dates are never requested. The CVE identifier's year is not its publication year. Pending analysis and unscored records remain visible. Rejected CVEs are excluded from the published dashboard, rankings, monthly records and insights; their raw cache status is retained so refreshes can recognize withdrawals and later changes. The initial backfill may take a considerable time because NVD requests must respect rate limits. Stop and rerun the same command to resume.

An optional [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) speeds requests. Set `NVD_API_KEY` in your process environment or a GitHub Actions secret. `.env.example` documents names only; Python does not load `.env` automatically. Never put secrets in variables prefixed `VITE_`.

To see the layout before importing NVD, run `python export_dashboard.py --allow-incomplete`, then `npm run dev`. This displays an explicit incomplete/empty state and never invents CVEs. `--max-pages 1` on `cvefetcher.py` is available for a bounded live smoke check; production export and build refuse an incomplete backfill. For an explicit local build check of partial data, set `ALLOW_INCOMPLETE_BUILD=1` (the code-only CI check uses this).

## Refresh

```sh
npm run sync
npm run build
```

Subsequent NVD runs request **new or modified records** using last-modified date windows and a short overlap to cover boundary updates. Upserts are keyed by CVE ID and content hashes; unchanged payloads are not rewritten. The initial backfill is followed by a modified-record catch-up so edits during the import are captured. Success checkpoints are committed transactionally; a failed request does not skip data.

CISA publishes a complete JSON catalog rather than an advisory delta API. The fetcher uses conditional HTTP where supported and compares cached entries to detect additions, modifications, and removals. This also catches corrections to older advisories. All KEV entries are cached, including pre-2020 CVEs; the dashboard exposes the full catalog separately from the NVD publication-date scope.

The SQLite database is `cache/vulnerabilities.sqlite3`. Generated files live in `public/data/`; both are ignored by Git. Back up the SQLite file rather than treating deployed static JSON as the ingestion database. To expand the configured publication range after 2026, run with the desired `--end-year` and let the fetcher validate/reinitialize its range state.

On Windows, OneDrive or a running development server can hold the generated directory open. The exporter retries transient locks and clears read-only attributes only on verified export paths. If a lock persists, stop the development server and rerun export; the SQLite cache remains intact.

## Publish on Vercel

The application is a static Vite project. The importer runs locally or in GitHub Actions, outside Vercel request handlers. This avoids function timeouts, public refresh endpoints, and nonpersistent function filesystems. API keys stay outside the deployed bundle.

For a first local deployment after a complete import:

```sh
npm run build
npx vercel@62.0.0 link
npx vercel@62.0.0 git disconnect --yes
npx vercel@62.0.0 pull --yes --environment=production
npx vercel@62.0.0 build --prod
npx vercel@62.0.0 deploy --prebuilt --prod --archive=tgz
```

The included `vercel.json` selects Vite, an explicit Node dependency install, `dist`, and security headers. The Python fetchers run before deployment and are not installed by Vercel. **Do not rely on an ordinary Git import to fetch data:** generated data is intentionally not committed. Disconnect automatic Git deployments after linking; use the included refresh workflow, or sync locally before deploying. The project checks for an exported cache before building.

The overview (`summary.json.gz`) and monthly record shards use deterministic gzip and are decompressed in the browser with `DecompressionStream`. The plain summary remains available for tooling; the build verifies both forms match. Summary decompression is limited to 16 MB; use a current Chrome, Edge, Firefox, or Safari. The build reports the total data size. Compression keeps the historical snapshot practical within [Vercel's CLI upload limits](https://vercel.com/docs/limits).

For automated deployment:

1. Push this project to your GitHub repository and link it to a Vercel project.
2. Add GitHub Actions secrets `VERCEL_TOKEN`, `VERCEL_ORG_ID`, and `VERCEL_PROJECT_ID`. The IDs are in `.vercel/project.json` after linking. Add optional `NVD_API_KEY`.
3. Run **Refresh cached vulnerability data** from Actions on the default branch, enabling its **deploy** input. The first run bootstraps; later runs refresh.
4. The scheduled workflow refreshes and deploys daily at **09:17 UTC** (05:17 Toronto during daylight saving time, 04:17 in winter).

Workflow concurrency prevents overlapping imports. A rolling Actions cache preserves the SQLite database. The latest two consistent compressed artifact backups are retained, each with a 90-day expiry; a verified backup is restored if that cache is evicted. Older backups are pruned only after a replacement uploads successfully. One dashboard artifact is retained for one day. If cache and backups disappear, the next run safely performs a new bootstrap. For archival retention, download a backup and retain it in your own storage. Failed syncs never replace the published snapshot; a saved partial cache allows the next run to resume. Scheduled Actions may be delayed by GitHub and must remain enabled for ongoing updates.

Vercel's supported CI flow is [`build` followed by `deploy --prebuilt`](https://vercel.com/kb/guide/how-can-i-use-github-actions-with-vercel). This project has no paid runtime database dependency; hosting and CI usage still follow the limits of your accounts.

## Data interpretation

- Headline totals count each CVE once. A CVE can affect multiple publishers, products, or categories, so their counts may overlap.
- Categories are OS, Application (including libraries and browsers), Hardware, and Unclassified. Vulnerable NVD CPE matches take priority. When those are absent, explicitly affected CNA products supply published CPE types or supported inference from exact vendor/product CPE consensus, package registries and specific product names. Bounded description and CISA KEV evidence provide a final fallback. Execution platforms alone never determine the category.
- Each CVE retains `categories`, `categoryEvidence`, `categoryMethod`, and `categoryAuthority`. Published CPE types and inferred assignments are distinguished in the details dialog; the footer shows whole-cache classification counts. Ambiguous types and insufficient evidence remain Unclassified. A partly classified CVE can appear in both a known category and Unclassified. Rejected records are excluded from the published snapshot.
- Product and publisher attribution comes from vulnerable CPE matches or explicitly affected CNA products, deduplicated per CVE. Description/KEV inference can identify a category without inventing product or publisher attribution. The exact-name taxonomy is rebuilt from the cached CPE data on every export, so classifications can improve as upstream records change.
- CVSS selection prefers v4, then v3.1, v3.0, and v2; unavailable scores remain Unknown. CVSS v2 does not define Critical severity. The dashboard groups score zero into its Low bucket.
- Publisher/product rankings contain the top 250/500 across the cached period. Monthly shards retain every CVE. Product averages describe the ranked products only.
- KEV membership reflects the current catalog; a year's KEV count means CVEs **published in that year** that are currently in KEV, not entries added to KEV during that year.
- When either compared year is partial, metrics, rankings, percent changes and benchmark trends use the same publication cutoff in both years. The period is displayed above the dashboard; historical complete-year comparisons use full-year totals. Raw monthly explorer data still covers the complete cached publication month.
- The single search field beneath the header searches the full KEV catalog and the explicitly loaded CVE publication month. Entering a query loads the KEV catalog on demand; CVE months are loaded explicitly. Result links show the matching counts for each scope. Weakness/impact filters apply to the loaded month.

## Strategic and tactical insights

The overview shows known-exploitation concentration, remotely reachable vulnerabilities that need no authentication, the most frequent reported weakness, and the leading potential impact. Cause rankings use reported CWE weakness mappings, with official MITRE names from the bundled catalog. They describe reported weaknesses rather than a forensic finding about each incident. Each cause is deduplicated per CVE; multiple causes can overlap. Missing/unspecified CWE information remains missing and coverage is shown.

Potential confidentiality, integrity and availability impacts come from the selected CVSS vector. CVSS v2/v3 use C/I/A; v4 includes vulnerable and subsequent system impacts. No-impact values differ from unknown impact data. These are consequences of successful exploitation, not observed breaches. Remote unauthenticated reach uses AV:N plus PR:N (v3/v4) or Au:N (v2). Data coverage is visible alongside the analysis.

Top-product and top-publisher rows include signed percent changes and trend indicators. A zero prior baseline displays New, without an infinite percentage. Rising disclosure counts do not establish that a product is less secure. Rankings are still limited to the top cached product/publisher candidates.

The benchmark supports either a product or publisher, with causes, potential impacts and publication trends for the selection. Product counts and publisher totals have different scopes and must not be added together. Recent known-exploited advisories give tactical investigation leads, with CISA actions and source links. Review applicability against your deployed versions; the dashboard does not contain an asset inventory or personalized risk score.

CWE label data is bundled in `pipeline/cwe_names.json`, with version, source, copyright and license. Refreshing vulnerability data does not silently change that vocabulary. CWE is a trademark of The MITRE Corporation; its license and attribution travel with the exported label catalog.

## Executive PDF reports

Select a ranked product or a category and choose **Create executive report**. The report opens as a PDF in a new tab, with a download link as a fallback. Product selections follow the benchmark; category selections follow the ranking category or the report selector. The report uses the selected reference/comparison years and **all severities**, with matched publication periods for partial years.

The exporter creates compressed fact packs for all 500 ranked products and the five category scopes. Each includes historical counts, CWE weaknesses, potential CVSS impacts, assessment/classification coverage, all relevant KEV advisories, and up to ten high-CVSS non-KEV examples. Category top-ten products consider all cached product identities before the dashboard ranking cap. Legacy/CISA-only advisories appear separately and do not inflate NVD metrics. Long source descriptions, product associations and reference lists have disclosed limits; each CVE links to its full source record. A build guard verifies that every report pack belongs to the current snapshot and is at most 8 MB decoded.

PDF generation happens locally in the browser using lazy-loaded jsPDF, self-hosted Noto Sans fonts and the cached public data. It adds an executive synthesis, evidence-linked strategic controls and a suggested 30/60/90-day plan. Recommendations are conditional on asset/version applicability; the report does not infer an organization's inventory, threat actors, incidents, likelihood or financial losses. CISA due dates apply to its federal directive audience. No AI provider, API key or PDF server is required. The PDF module and fonts are downloaded only when requested; Noto Sans licensing is included in `public/fonts/OFL.txt`.

## Verify

```sh
python -m unittest discover -s tests -v
npm audit --audit-level=high
node --test tests/report-content.test.mjs
npm run build
```

Tests cover ingestion checkpoints, incremental updates, KEV reconciliation, export deduplication, score handling, classification evidence priority, rejected-record exclusion, aligned comparison windows, cause/impact deduplication and malformed CVSS vectors. See [SECURITY.md](SECURITY.md) for implemented controls and operational boundaries.

Sources: [MITRE CWE catalog](https://cwe.mitre.org/data/downloads.html), [FIRST CVSS specification](https://www.first.org/cvss/v4.0/specification-document), [NVD API documentation](https://nvd.nist.gov/developers/vulnerabilities), [NVD rate-limit guidance](https://nvd.nist.gov/developers/start-here), [CISA KEV catalog and official mirror](https://github.com/cisagov/kev-data).
