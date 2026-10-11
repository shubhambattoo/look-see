import fs from 'node:fs/promises';

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function safeLink(url) {
  return /^https?:\/\//i.test(url ?? '') ? url : null;
}

function formatGeneratedAt(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function findingMarkup(item, finding) {
  const severity = String(finding.severity?.severity ?? 'UNKNOWN').toUpperCase();
  const score = finding.severity?.score ?? '';
  const potential = finding.match?.status === 'potential';
  const version = item.version ?? 'unknown version';
  const refs = finding.references.map((url) => safeLink(url)).filter(Boolean);
  const aliases = [...new Set([finding.id, ...finding.aliases].filter(Boolean))];
  const ranges = finding.affected.flatMap((affected) => affected.ranges.map((range) => {
    const events = range.events.map((event) => {
      const [kind, version] = Object.entries(event)[0] ?? [];
      return kind ? `${kind}: ${version}` : null;
    }).filter(Boolean);
    return `${range.type ?? 'version'} (${events.join(', ')})`;
  }));
  return `<article class="finding" data-severity="${escapeHtml(severity)}" data-package="${escapeHtml(item.name)}" data-score="${escapeHtml(score)}">
    <div class="finding-heading">${potential ? '<span class="badge potential" style="background:#8250df">POTENTIAL</span>' : ''}<span class="badge ${escapeHtml(severity.toLowerCase())}">${escapeHtml(severity)}</span><strong>${escapeHtml(item.name)}@${escapeHtml(version)}</strong><span class="ids">${escapeHtml(aliases.join(' · '))}</span></div>
    <p>${escapeHtml(finding.summary)}</p>
    <p class="meta">${escapeHtml(item.purl)} · ${escapeHtml(item.direct ? 'Direct' : 'Transitive / indirect')} · Sources: ${escapeHtml(finding.sources.join(', '))}</p>
    ${item.specifiers?.length ? `<p><strong>Requirement constraints:</strong> ${escapeHtml(item.specifiers.join(', '))}</p>` : ''}
    ${potential ? '<p><strong>Potential match only:</strong> OSV has advisories for this package, but the resolved version is unknown. Verify the installed version against the affected range before treating this as vulnerable.</p>' : ''}
    ${ranges.length ? `<p><strong>Affected range:</strong> ${escapeHtml(ranges.join('; '))}</p>` : ''}
    <p><strong>Fix guidance:</strong> ${escapeHtml(finding.remediation)}</p>
    ${finding.details ? `<details><summary>Advisory details</summary><p>${escapeHtml(finding.details)}</p></details>` : ''}
    ${refs.length ? `<p class="refs">${refs.map((url) => `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">Reference</a>`).join(' ')}</p>` : ''}
  </article>`;
}

export function renderHtml(report) {
  const { summary, packages, coverage } = report;
  const rows = packages.flatMap((item) => [
    ...(item.vulnerabilities ?? []),
    ...(item.potentialAdvisories ?? []),
  ].map((finding) => findingMarkup(item, finding)));
  const body = rows.length
    ? rows.join('\n')
    : '<p class="empty">No vulnerabilities were returned for the dependencies scanned. Check scan coverage below before treating this as a clean bill of health.</p>';
  const severityRows = Object.entries(summary.severityCounts)
    .map(([severity, count]) => `<li><span class="badge ${escapeHtml(severity.toLowerCase())}">${escapeHtml(severity)}</span> ${count}</li>`)
    .join('');
  const coverageErrors = coverage.errors.length
    ? `<ul>${coverage.errors.map((error) => `<li><strong>${escapeHtml(error.source ?? 'Discovery')}:</strong> ${escapeHtml(error.file ? `${error.file}: ` : '')}${escapeHtml(error.message)}</li>`).join('')}</ul>`
    : '<p>No scan or data-source errors were reported.</p>';
  const lockfiles = coverage.lockfiles.length
    ? `<ul>${coverage.lockfiles.map((file) => `<li><code>${escapeHtml(file)}</code></li>`).join('')}</ul>`
    : '<p>No supported dependency files were found.</p>';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Look-See dependency vulnerability report</title>
<style>
:root{color-scheme:light dark;font:15px/1.55 system-ui,sans-serif;--bg:#fff;--fg:#202124;--muted:#5f6368;--card:#f6f8fa;--border:#d0d7de;--link:#0969da}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--card:#161b22;--border:#30363d;--link:#58a6ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg)}main{max-width:1100px;margin:auto;padding:32px 20px}h1{margin-bottom:4px}.muted,.meta{color:var(--muted)}.summary{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}.stat,details,.finding{background:var(--card);border:1px solid var(--border);border-radius:8px}.stat{padding:12px 16px;min-width:140px}.stat strong{display:block;font-size:1.35rem}.finding{padding:16px;margin:12px 0}.finding-heading{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.ids{color:var(--muted);font-size:.9rem}.badge{border-radius:4px;padding:2px 7px;font-size:.75rem;font-weight:700;background:#8b949e;color:#fff}.critical,.high{background:#cf222e}.medium{background:#bf8700}.low{background:#0969da}.unknown{background:#6e7781}.meta{font-size:.85rem;overflow-wrap:anywhere}.refs a{margin-right:12px}a{color:var(--link)}details{padding:12px;margin:10px 0}summary{cursor:pointer}.empty{padding:20px;background:var(--card);border-radius:8px}code{overflow-wrap:anywhere}section{margin-top:32px}.controls{display:flex;align-items:end;flex-wrap:wrap;gap:18px;margin:16px 0 20px}.controls label{display:flex;flex-direction:column;gap:6px;font-size:1.05rem;font-weight:500}.controls input,.controls select{min-height:40px;padding:8px 11px;font:inherit;font-size:1.05rem;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--fg)}.controls input[type=search]{min-width:260px}
</style></head><body><main>
<h1>Look-See dependency vulnerability report</h1>
<p class="muted">Project: <code>${escapeHtml(report.project)}</code> · Generated: ${escapeHtml(formatGeneratedAt(report.generatedAt))}</p>
 <div class="summary"><div class="stat"><strong>${summary.dependencies}</strong>dependencies scanned</div><div class="stat"><strong>${summary.vulnerableDependencies}</strong>with confirmed findings</div><div class="stat"><strong>${summary.vulnerabilities}</strong>confirmed vulnerabilities</div><div class="stat"><strong>${summary.potentialAdvisories ?? 0}</strong>potential advisory matches</div></div>
<h2>Confirmed vulnerability severity</h2><ul>${severityRows}</ul>
<section><h2>Findings</h2><div class="controls"><label>Filter <input id="filter" type="search" placeholder="Package, CVE, or text"></label><label>Severity <select id="severity-filter"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>UNKNOWN</option></select></label><label>Sort <select id="sort"><option value="severity">Severity</option><option value="package">Package</option><option value="score">CVSS score</option></select></label></div><div id="findings">${body}</div></section>
 <section><h2>Scan coverage</h2><p>Advisory matching uses OSV package/version records. Package-only matches are potential advisories: the installed version is unknown, and declared constraints are not cross-checked against OSV affected ranges. NVD records enrich matching CVEs where available. This report does not imply coverage of ecosystems without a supported dependency-file parser.</p><p>Dependency resolution: ${escapeHtml(coverage.dependencyResolution)}</p><h3>Files scanned</h3>${lockfiles}<h3>Errors and limitations</h3>${coverageErrors}</section>
<footer class="muted"><p>Generated by Look-See. Verify fixes against upstream advisories and rerun the scan.</p></footer>
</main><script>
(() => {
  const list = document.getElementById('findings');
  const search = document.getElementById('filter');
  const severity = document.getElementById('severity-filter');
  const sort = document.getElementById('sort');
  const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
  const update = () => {
    const query = search.value.toLowerCase();
    const cards = [...list.querySelectorAll('.finding')];
    for (const card of cards) {
      card.hidden = (query && !card.textContent.toLowerCase().includes(query)) || (severity.value && card.dataset.severity !== severity.value);
    }
    cards.sort((a, b) => {
      if (sort.value === 'package') return a.dataset.package.localeCompare(b.dataset.package);
      if (sort.value === 'score') return (Number(b.dataset.score) || -1) - (Number(a.dataset.score) || -1);
      return (rank[b.dataset.severity] ?? 0) - (rank[a.dataset.severity] ?? 0);
    }).forEach((card) => list.append(card));
  };
  search.addEventListener('input', update);
  severity.addEventListener('change', update);
  sort.addEventListener('change', update);
  update();
})();
</script></body></html>`;
}

export async function writeReports(report, outputDirectory, formats) {
  await fs.mkdir(outputDirectory, { recursive: true });
  const written = {};
  if (formats.includes('json')) {
    const file = `${outputDirectory}/look-see-output.json`;
    await fs.writeFile(file, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    written.json = file;
  }
  if (formats.includes('html')) {
    const file = `${outputDirectory}/look-see-output.html`;
    await fs.writeFile(file, renderHtml(report), 'utf8');
    written.html = file;
  }
  return written;
}

export const reportHelpers = { escapeHtml, safeLink, formatGeneratedAt };
