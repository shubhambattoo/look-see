import test from 'node:test';
import assert from 'node:assert/strict';
import { renderHtml, reportHelpers } from '../src/report.js';
import { buildFindings, summarize } from '../src/analyze.js';

test('escapes HTML and rejects unsafe links', () => {
  assert.equal(reportHelpers.escapeHtml('<script>"x"</script>'), '&lt;script&gt;&quot;x&quot;&lt;/script&gt;');
  assert.equal(reportHelpers.safeLink('javascript:alert(1)'), null);
  assert.equal(reportHelpers.safeLink('https://example.com'), 'https://example.com');
});

test('formats report dates and styles filter controls with spacing', () => {
  const timestamp = '2026-10-11T04:56:28.042Z';
  assert.notEqual(reportHelpers.formatGeneratedAt(timestamp), timestamp);
  assert.equal(reportHelpers.formatGeneratedAt('not a date'), 'not a date');
  const html = renderHtml({
    project: '/tmp/project', generatedAt: timestamp,
    summary: { dependencies: 0, vulnerableDependencies: 0, vulnerabilities: 0, severityCounts: {} },
    packages: [], coverage: { lockfiles: [], dependencyResolution: 'test', errors: [] },
  });
  assert.match(html, /gap:18px/);
  assert.match(html, /font-size:1\.05rem/);
});

test('builds JSON findings and takes NVD severity when available', () => {
  const pkg = { ecosystem: 'npm', name: 'demo', version: '1.0.0', purl: 'pkg:npm/demo@1.0.0', direct: true, files: ['package-lock.json'] };
  const advisory = {
    id: 'OSV-2025-1', aliases: ['CVE-2025-1234'], summary: 'Example issue',
    affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }] }],
    references: [{ url: 'https://example.com/advisory' }],
  };
  const findings = buildFindings([pkg], new Map([[pkg.purl, [advisory]]]), new Map([
    ['CVE-2025-1234', { id: 'CVE-2025-1234', descriptions: [{ lang: 'en', value: 'NVD details' }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.1, baseSeverity: 'HIGH', version: '3.1' } }] } }],
  ]));
  assert.equal(findings[0].vulnerabilities[0].severity.severity, 'HIGH');
  assert.deepEqual(findings[0].vulnerabilities[0].fixedVersions, ['1.0.1']);
  assert.equal(summarize(findings).vulnerabilities, 1);
  const html = renderHtml({
    project: '/tmp/project', generatedAt: 'now', summary: summarize(findings), packages: findings,
    coverage: { lockfiles: [], dependencyResolution: 'test', errors: [] },
  });
  assert.match(html, /CVE-2025-1234/);
  assert.match(html, /Upgrade to 1\.0\.1/);
});

test('labels package-only OSV matches as potential and excludes them from confirmed counts', () => {
  const pkg = {
    ecosystem: 'PyPI', name: 'attrs', version: null, specifiers: ['>=21.2.0'],
    purl: 'pkg:pypi/attrs', direct: true, files: ['requirements.txt'],
  };
  const advisory = { id: 'PYSEC-2025-1', summary: 'Example Python advisory', affected: [] };
  const findings = buildFindings([pkg], new Map([[pkg.purl, [advisory]]]), new Map());
  assert.equal(findings[0].potentialAdvisories[0].match.status, 'potential');
  assert.match(findings[0].potentialAdvisories[0].remediation, /resolved version is unknown/i);
  assert.deepEqual(summarize(findings), {
    dependencies: 1,
    vulnerableDependencies: 0,
    vulnerabilities: 0,
    potentialDependencies: 1,
    potentialAdvisories: 1,
    severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
  });

  const html = renderHtml({
    project: '/tmp/project', generatedAt: 'now', summary: summarize(findings), packages: findings,
    coverage: { lockfiles: [], dependencyResolution: 'test', errors: [] },
  });
  assert.match(html, /POTENTIAL/);
  assert.match(html, /attrs@unknown version/);
  assert.match(html, /&gt;=21\.2\.0/);
  assert.match(html, /constraints are not cross-checked against OSV affected ranges/i);
});
