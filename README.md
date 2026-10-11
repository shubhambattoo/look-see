# Look-See

Look-See is a Node.js CLI that scans supported dependency lockfiles, identifies packages with PURLs, checks exact package versions against OSV, and enriches matching CVEs with NVD data. It writes JSON and HTML reports and opens the HTML report by default.

> Early MVP: npm lockfiles and Go `go.mod` requirements are supported. Automated dependency fixes are not implemented yet.

## Usage

Requires Node.js 22 or newer. Use the CLI with `npx` without a global install, or install it globally to use the `look-see` command directly.

### Run with npx

```bash
npx @shubhambattoo/look-see /path/to/project
```

### Install globally

```bash
npm install -g @shubhambattoo/look-see
look-see /path/to/project
```

To run from this checkout:

```bash
npm install
npm start -- /path/to/project --no-open
```

The default output directory is `<project>/.look-see/`:

- `look-see-output.html`
- `look-see-output.json`

The CLI scans `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, and `go.mod` files below the project directory. It skips common generated/dependency directories such as `node_modules`, `vendor`, and `.git`.

## Options

```text
look-see [project-directory]
  --out <directory>     Report output directory
  --format html,json    Select one or both report formats
  --no-open             Do not open the HTML report
  --no-nvd              Skip NVD CVE enrichment
  --fail-on <severity>  Exit 1 if a finding meets the severity threshold
  --help                Show help
```

Set `NVD_API_KEY` for higher NVD API request limits. Advisory responses are cached locally; use `LOOK_SEE_CACHE_DIR` to choose a cache location.

## Matching and coverage

Each locked dependency is represented by a Package URL. OSV is queried using the package identity and resolved version, which provides ecosystem-aware matching. Matching CVE IDs are then looked up in NVD for CVSS and reference enrichment. NVD is not used as a fuzzy package-name search: its CPE records do not reliably map to every package-manager coordinate.

The npm lockfile parsers report resolved versions, including transitive packages. Go scanning currently reads requirements from `go.mod`; it does not run `go list`, resolve the complete selected/transitive module graph, or apply `replace` directives. Unsupported manifests are not scanned. Review the report's coverage and errors before interpreting an empty result as clean.

NVD may rate-limit unauthenticated lookups. Enrichment errors are included in both reports; OSV matching results remain available if NVD is unavailable. The CLI does not modify project files.

## Development

```bash
npm install
npm test
```
