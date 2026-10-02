# Security

The deployed site serves public static data. It has no database credentials, mutation endpoints, authentication session, or public importer. Python and deployment credentials are supplied through process environments or GitHub Actions secrets and are excluded from the frontend build.

Implemented controls:

- Fixed HTTPS upstream endpoints, verified TLS, timeouts, bounded retries, and rate limiting in ingestion. Redirects do not forward NVD API credentials to other hosts.
- Parameterized SQLite statements, payload validation, transactional checkpoints, and atomic export publication. Invalid upstream responses fail the sync rather than publish an apparently successful empty snapshot.
- Safe text rendering of vulnerability descriptions, vendors, products, and advisory fields. Reference links are restricted to HTTPS and reject embedded credentials. External links use `noopener` and `noreferrer`.
- Vercel Content Security Policy allows scripts, styles, and data only from the site; framing, object plugins, form submission, and base-URL changes are blocked. Additional headers enforce MIME types and restrict referrers and device permissions.
- Lockfile-pinned frontend dependencies, GitHub Actions pinned to commit IDs, a pinned Vercel CLI version, dependency-audit checks, read-only repository-content permissions, default-branch refreshes, and serial cache updates. Only the refresh job has Actions write permission to prune its own verified old artifacts; code checks remain read-only. Backup restores and pruning verify the originating workflow, repository, branch, and event. Pull-request checks do not receive deployment secrets.
- The Python cache, source scripts, environment files, and tests are excluded from Vercel source uploads. Only build output is sent by the CI deployment.
- Executive reports use fixed, validated same-origin fact-pack paths, bounded compressed/decoded reads and snapshot consistency checks. PDF text is drawn directly with an audited, pinned jsPDF dependency; upstream content is never interpreted as HTML or PDF JavaScript. PDF source links accept HTTPS only. Fonts are self-hosted. New PDF tabs have their opener removed, generated Blob URLs expire after 30 minutes, and blocked popups retain a download fallback. No new server endpoint or API credential is needed.

The SQLite cache and generated JSON contain public upstream vulnerability information, not secrets. Public repository workflow artifacts may be publicly downloadable. Do not add private inventory data or credentials to these payloads.

Keep Node/Python, GitHub Actions, the Vercel CLI, and npm dependencies updated. Use a deployment token scoped to your project/team and rotate it when needed. Cache artifacts have finite retention; retain a local or external backup for long-term recovery. The exporter refuses partial bootstrap data by default. Only use `--allow-incomplete` for clearly identified local smoke checks.

These controls were reviewed and tested locally; they are not a claim of an independent penetration test or a guarantee against every future dependency vulnerability.
