# Project guide for coding agents

## What this project does

Look-See (`@shubhambattoo/look-see` on npm, `look-see` executable) is a read-only Node.js CLI for finding known vulnerabilities in project dependencies. It discovers supported lockfiles, identifies resolved packages with Package URLs (PURLs), queries OSV for ecosystem-aware package/version matches, and enriches matching CVEs with NVD data. It emits JSON and self-contained HTML reports and opens the HTML report by default.

The project is an early MVP. It does not automatically upgrade dependencies or modify the scanned project. Do not add implicit package-manager execution or project-file changes.

## Runtime and commands

- Use Node.js 22 or newer and ECMAScript modules.
- Install dependencies with `npm install`.
- Run tests with `npm test` (`node --test`).
- Run locally with `npm start -- <project-directory> --no-open`, or `./bin/look-see.js <project-directory>`.
- `package.json` defines the npm package as `@shubhambattoo/look-see` and executable as `look-see`.

Keep dependencies focused. Chalk is used for CLI progress, `yaml` for YAML lockfiles, and `@yarnpkg/lockfile` for classic Yarn lockfiles.

## Scan flow and code map

The normal flow is:

1. `src/cli.js` parses arguments and coordinates the scan.
2. `src/discovery/` locates supported files and extracts package identities, versions, and direct/indirect status.
3. `src/purl.js` creates PURLs. The OSV package query uses the PURL identity and supplies the resolved version separately.
4. `src/advisories/osv.js` checks packages with OSV and fetches full advisory records for batch results.
5. `src/advisories/nvd.js` looks up CVE IDs to enrich findings with NVD metadata.
6. `src/analyze.js` normalizes findings and remediation hints.
7. `src/report.js` writes the versioned JSON data and HTML report.
8. `src/progress.js` prints the startup ASCII wordmark and provides colored interactive spinner output and plain progress messages for non-interactive runs.

Other modules: `src/cache.js` manages local advisory-response caching; `bin/look-see.js` is the executable entry point.

## Current support and limitations

- npm: `package-lock.json`, `pnpm-lock.yaml`, and `yarn.lock` (classic and metadata-based Yarn formats).
- Go: `go.mod` requirements, including `// indirect` entries.
- npm lockfiles provide resolved versions and transitive packages. Go scanning does not run `go list`, resolve the complete selected module graph, or apply `replace` directives.
- OSV performs package-aware matching. NVD is used to enrich CVEs found through OSV; do not treat NVD keyword/CPE matches as exact package matches without a reliable mapping.
- Unsupported manifests are not scanned. Missing lockfiles, parser failures, and advisory-source failures must remain visible in report coverage; do not present an incomplete scan as a clean result.
- NVD may rate-limit requests. `NVD_API_KEY` can increase limits; `--no-nvd` skips enrichment. Cache location can be set with `LOOK_SEE_CACHE_DIR`.
- Automated fixes and ecosystem formats beyond those listed above are not implemented.

## Implementation guidance

- Preserve the read-only behavior of scans. Do not invoke build scripts or package managers against the target project by default.
- Keep ecosystem identity and version handling accurate. Add or reuse ecosystem-specific parsing/comparison rather than applying npm SemVer assumptions to every ecosystem.
- Keep advisory provenance, aliases, affected ranges, and uncertainty/coverage visible in output. Do not fabricate fixed versions or remediation advice when source data does not provide them.
- Escape all dependency/advisory text in HTML. Only render HTTP(S) advisory links; keep the report usable offline and do not add remote scripts.
- If changing the JSON report structure, update/document `schemaVersion` and corresponding tests.
- Keep user-facing progress useful for both TTYs and non-TTY logs, and retain Chalk's normal color detection (including `NO_COLOR`).
- Add tests for parser and PURL changes, report escaping/schema changes, and CLI behavior. Avoid network-dependent tests; live API checks should remain manual smoke tests.
