import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { discoverDependencies } from './discovery/index.js';
import { queryOsv } from './advisories/osv.js';
import { nvdHelpers, queryNvd } from './advisories/nvd.js';
import { buildFindings, summarize } from './analyze.js';
import { writeReports } from './report.js';
import { createProgress } from './progress.js';

const HELP = `Look-See - scan locked dependencies for known vulnerabilities

Usage: look-see [project-directory] [options]

Options:
  --out <directory>     Report output directory (default: <project>/.look-see)
  --format <formats>    html,json (default: html,json)
  --no-open             Do not open the HTML report automatically
  --no-nvd              Skip NVD CVE enrichment
  --fail-on <severity>  Exit with code 1 for this severity or higher
  -h, --help            Show this help
  -v, --version         Show the version

Environment:
  NVD_API_KEY           Optional NVD API key for higher request limits
  LOOK_SEE_CACHE_DIR    Override the local advisory cache directory`;

const VERSION = '0.2.1';
const SEVERITY_RANK = { UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function parseArgs(args) {
  const options = {
    root: process.cwd(), out: null, formats: ['html', 'json'], open: true,
    nvd: true, failOn: null, help: false, version: false,
  };
  let rootWasSet = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '-h' || arg === '--help') options.help = true;
    else if (arg === '-v' || arg === '--version') options.version = true;
    else if (arg === '--no-open') options.open = false;
    else if (arg === '--no-nvd') options.nvd = false;
    else if (arg === '--out' || arg === '--format' || arg === '--fail-on') {
      const value = args[++index];
      if (!value || value.startsWith('--')) throw new Error(`${arg} requires a value`);
      if (arg === '--out') options.out = value;
      if (arg === '--format') {
        options.formats = value.split(',').map((format) => format.trim().toLowerCase());
        if (!options.formats.length || options.formats.some((format) => !['html', 'json'].includes(format))) {
          throw new Error('--format must contain html, json, or both (comma-separated)');
        }
        options.formats = [...new Set(options.formats)];
      }
      if (arg === '--fail-on') {
        const severity = value.toUpperCase();
        if (!(severity in SEVERITY_RANK) || severity === 'UNKNOWN') {
          throw new Error('--fail-on must be low, medium, high, or critical');
        }
        options.failOn = severity;
      }
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (!rootWasSet) {
      options.root = arg;
      rootWasSet = true;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }
  return options;
}

function openInBrowser(file) {
  const absolute = path.resolve(file);
  const target = process.platform === 'win32' ? absolute : pathToFileURL(absolute).href;
  const command = process.platform === 'darwin' ? 'open'
    : process.platform === 'win32' ? 'cmd'
      : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', target] : [target];
  return new Promise((resolve) => {
    const child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
    child.once('error', () => resolve(false));
    child.once('spawn', () => {
      child.unref();
      resolve(true);
    });
  });
}

function allOsvVulnerabilities(byPackage) {
  return [...byPackage.values()].flat();
}

export async function run(args = process.argv.slice(2), io = console) {
  let options;
  try {
    options = parseArgs(args);
  } catch (error) {
    io.error(`look-see: ${error.message}\nUse --help for usage.`);
    return 2;
  }
  if (options.help) {
    io.log(HELP);
    return 0;
  }
  if (options.version) {
    io.log(VERSION);
    return 0;
  }

  const root = path.resolve(options.root);
  let stats;
  try {
    stats = await fs.stat(root);
    if (!stats.isDirectory()) throw new Error('Project path must be a directory');
  } catch (error) {
    io.error(`look-see: cannot read project directory ${root}: ${error.message}`);
    return 2;
  }

  const outputDirectory = options.out
    ? path.resolve(options.out)
    : path.join(root, '.look-see');
  const progress = createProgress(io);
  progress.banner();
  progress.start(`Scanning ${root}`);
  let discovery;
  try {
    discovery = await discoverDependencies(root);
    progress.complete(`Discovered ${discovery.packages.length} locked dependency version(s) across ${discovery.lockfiles.length} file(s).`);
  } catch (error) {
    progress.warn(`Dependency discovery failed: ${error.message}`);
    return 2;
  }

  progress.start(`Checking ${discovery.packages.length} dependency version(s) against OSV`);
  const osv = await queryOsv(discovery.packages, {
    onProgress: ({ stage, completed, total }) => {
      if (stage === 'packages' && total > 0) progress.update(`OSV package checks: ${completed}/${total}`);
      if (stage === 'advisories' && total > 0) progress.update(`Loading advisory details: ${completed}/${total}`);
    },
  });
  const osvVulnerabilities = allOsvVulnerabilities(osv.byPackage);
  progress.complete(`OSV checks complete: ${osvVulnerabilities.length} advisory finding(s).`);

  const cveIds = nvdHelpers.cveIdsFrom(osvVulnerabilities);
  let nvd = { byCve: new Map(), errors: [] };
  if (!options.nvd) {
    progress.skip('NVD enrichment disabled (--no-nvd).');
  } else if (cveIds.length === 0) {
    progress.skip('No CVE IDs found for NVD enrichment.');
  } else {
    progress.start(`Enriching ${cveIds.length} CVE(s) with NVD data`);
    nvd = await queryNvd(osvVulnerabilities, {
      onProgress: ({ completed, total }) => progress.update(`NVD CVE enrichment: ${completed}/${total}`),
    });
    const enriched = [...nvd.byCve.values()].filter(Boolean).length;
    progress.complete(`NVD enrichment complete: ${enriched}/${cveIds.length} CVE record(s) retrieved.`);
  }
  const packages = buildFindings(discovery.packages, osv.byPackage, nvd.byCve);
  const summary = summarize(packages);
  const errors = [
    ...discovery.errors.map((error) => ({ source: 'Discovery', ...error })),
    ...osv.errors,
    ...nvd.errors,
  ];
  if (!discovery.lockfiles.length) {
    errors.push({ source: 'Discovery', message: 'No supported lockfiles were found; no dependencies were checked.' });
  }
  const report = {
    schemaVersion: '1.0.0',
    tool: { name: 'look-see', version: VERSION },
    generatedAt: new Date().toISOString(),
    project: root,
    summary,
    coverage: {
      lockfiles: discovery.lockfiles,
      packagesScanned: discovery.packages.length,
      advisoryMatching: 'OSV package and version matching using PURLs',
      nvdEnrichment: options.nvd ? 'NVD CVE enrichment for OSV advisories with CVE aliases' : 'disabled by --no-nvd',
      dependencyResolution: 'npm lockfiles provide resolved dependency versions; Go scans go.mod requirements without resolving the full module graph or applying replace directives.',
      errors,
    },
    packages,
  };

  progress.start('Writing HTML and JSON reports');
  let written;
  try {
    written = await writeReports(report, outputDirectory, options.formats);
  } catch (error) {
    progress.warn(`Could not write reports: ${error.message}`);
    return 2;
  }
  progress.complete('Reports written.');
  for (const [format, file] of Object.entries(written)) progress.note(`${format.toUpperCase()} report: ${file}`);
  progress.complete(`Scan complete: ${summary.vulnerabilities} finding(s) in ${summary.vulnerableDependencies} dependency version(s).`);
  if (errors.length) progress.warn(`${errors.length} scan/data-source issue(s); review coverage.errors in the JSON report.`);

  if (options.open && written.html) {
    const opened = await openInBrowser(written.html);
    if (!opened) progress.warn('Could not open a browser automatically. Open the HTML report path above.');
  }

  if (options.failOn) {
    const threshold = SEVERITY_RANK[options.failOn];
    if (packages.some((item) => item.vulnerabilities.some((finding) =>
      SEVERITY_RANK[String(finding.severity?.severity ?? 'UNKNOWN').toUpperCase()] >= threshold))) return 1;
  }
  if (discovery.errors.length || osv.errors.length || !discovery.lockfiles.length) return 2;
  return 0;
}

export const cliHelpers = { parseArgs, openInBrowser };
