# Local testing guide

This guide covers the automated test suite and a manual scan from a local checkout. Scans read the target project's dependency files and write reports; they do not install, upgrade, or otherwise modify its dependencies.

## 1. Set up the checkout

Use Node.js 22 or newer. From the repository root, install the locked dependencies:

```sh
npm install
```

Check the executable entry point and CLI options:

```sh
npm start -- --version
npm start -- --help
```

## 2. Run the automated tests

```sh
npm test
```

The suite uses Node's built-in test runner (`node --test`). It covers CLI argument handling, npm/Go/Python dependency parsing and PURLs, advisory response handling and caching, finding analysis, and report generation. Advisory-client tests stub network fetches, so the automated suite does not need live advisory services.

## 3. Run a local scan

Choose a project directory containing at least one supported dependency file: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.mod`, `requirements.txt`, or `requirements-*.txt`. From this checkout, run:

```sh
npm start -- "C:/path/to/project" --no-open --out "C:/path/to/project/.look-see-local"
```

On macOS or Linux, use the target project's regular absolute path, for example `/home/me/project`.

The scan queries OSV and cve.now, and enriches matching CVEs with NVD by default. It needs network access. To skip NVD enrichment (useful when NVD is rate-limiting), add `--no-nvd`; OSV and cve.now are still queried. Set `NVD_API_KEY` if you have an NVD key and want higher NVD request limits. Advisory responses are cached; set `LOOK_SEE_CACHE_DIR` to use a separate cache directory during development.

The command writes `look-see-output.html` and `look-see-output.json` to the selected output directory. Review `coverage.errors`, `coverage.lockfiles`, and `coverage.dependencyResolution` in JSON, because an empty findings list alone does not mean every dependency was scanned successfully. Python unpinned or ranged requirements can produce potential advisories because their resolved versions are unknown.

### Exit codes

- `0`: scan completed without discovery or OSV coverage errors. Findings can still be present.
- `1`: a confirmed finding met the `--fail-on` severity threshold.
- `2`: no supported dependency file was found, dependency discovery failed, an OSV error occurred, or report writing failed. Review the JSON coverage when available.

For example, to check that no confirmed high or critical findings are present:

```sh
npm start -- "C:/path/to/project" --no-open --no-nvd --fail-on high
```

Potential package-only advisories do not trigger `--fail-on`. The scan can still contact OSV and cve.now in this example.

## 4. Try the CLI against a project with no supported files

To check the incomplete-scan path without making advisory requests, use an empty temporary directory:

```sh
npm start -- "C:/path/to/empty-project" --format json --no-open
```

The command should exit with code `2` and write a JSON report that explains no supported dependency files were found. Create the directory first if it does not exist.

## 5. Inspect changes before committing

After editing parsers, PURLs, CLI behavior, or reports, run `npm test` again. Keep smoke scans pointed at disposable or known test projects, direct report output to a separate directory, and verify both the report contents and coverage details.
