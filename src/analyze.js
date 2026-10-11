function highestNvdMetric(cve) {
  const metrics = cve?.metrics ?? {};
  const candidates = Object.values(metrics).flat().filter((metric) => metric?.cvssData?.baseScore != null);
  candidates.sort((a, b) => b.cvssData.baseScore - a.cvssData.baseScore);
  if (!candidates.length) return null;
  const metric = candidates[0];
  return {
    score: metric.cvssData.baseScore,
    severity: metric.cvssData.baseSeverity ?? metric.baseSeverity ?? null,
    version: metric.cvssData.version ?? null,
    vector: metric.cvssData.vectorString ?? null,
  };
}

function englishDescription(entries = []) {
  return entries.find((entry) => entry.lang === 'en')?.value ?? entries[0]?.value ?? null;
}

function nvdData(cve) {
  if (!cve) return null;
  return {
    id: cve.id,
    published: cve.published ?? null,
    lastModified: cve.lastModified ?? null,
    description: englishDescription(cve.descriptions),
    severity: highestNvdMetric(cve),
    references: (cve.references ?? []).map((reference) => reference.url).filter(Boolean),
  };
}

function fixedVersions(vulnerability) {
  const versions = new Set();
  for (const affected of vulnerability.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) versions.add(event.fixed);
      }
    }
    for (const version of affected.ecosystem_specific?.fixed ?? []) versions.add(version);
  }
  return [...versions];
}

function advisoryReferences(vulnerability, nvd) {
  return [...new Set([
    ...(vulnerability.references ?? []).map((reference) => reference.url),
    ...(nvd?.references ?? []),
  ].filter((url) => typeof url === 'string' && /^https?:\/\//i.test(url)))];
}

function severityOf(vulnerability, nvd) {
  const nvdSeverity = nvd?.severity;
  if (nvdSeverity?.severity) return { ...nvdSeverity, source: 'NVD' };
  const databaseSeverity = vulnerability.database_specific?.severity;
  if (databaseSeverity) {
    const raw = String(databaseSeverity).toUpperCase();
    const severity = ({ MODERATE: 'MEDIUM', IMPORTANT: 'HIGH', SEVERE: 'HIGH' })[raw] ?? raw;
    return { severity, score: null, source: 'OSV' };
  }
  return { severity: 'UNKNOWN', score: null, source: null };
}

function guidance(versions) {
  if (!versions.length) {
    return 'Check the linked upstream advisory for a patched release. No fixed version was provided by the advisory data.';
  }
  return `Upgrade to ${versions.join(' or ')} (or a later compatible release), then rerun the scan. Review release notes for breaking changes.`;
}

export function buildFindings(packages, osvByPackage, nvdByCve) {
  return packages.map((item) => {
    const vulnerabilities = osvByPackage.get(item.purl) ?? [];
    const findings = vulnerabilities.map((vulnerability) => {
      const cveId = [vulnerability.id, ...(vulnerability.aliases ?? [])]
        .find((id) => /^CVE-\d{4}-\d+$/i.test(id ?? ''))?.toUpperCase() ?? null;
      const nvd = cveId ? nvdData(nvdByCve.get(cveId)) : null;
      const fixes = fixedVersions(vulnerability);
      return {
        id: vulnerability.id,
        aliases: vulnerability.aliases ?? [],
        cveId,
        match: { type: 'package-version', confidence: 'high', source: 'OSV' },
        summary: vulnerability.summary ?? nvd?.description ?? vulnerability.id,
        details: vulnerability.details ?? null,
        severity: severityOf(vulnerability, nvd),
        affected: (vulnerability.affected ?? []).map((affected) => ({
          ranges: (affected.ranges ?? []).map((range) => ({
            type: range.type,
            events: range.events ?? [],
          })),
          versions: affected.versions ?? [],
        })),
        fixedVersions: fixes,
        remediation: guidance(fixes),
        references: advisoryReferences(vulnerability, nvd),
        sources: [...new Set(['OSV', ...(nvd ? ['NVD'] : [])])],
        nvd,
      };
    });
    return { ...item, vulnerabilities: findings };
  });
}

export function summarize(packages) {
  const findings = packages.flatMap((item) => item.vulnerabilities);
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const counts = Object.fromEntries(severities.map((severity) => [severity, 0]));
  for (const finding of findings) {
    const severity = String(finding.severity?.severity ?? 'UNKNOWN').toUpperCase();
    counts[Object.hasOwn(counts, severity) ? severity : 'UNKNOWN'] += 1;
  }
  return {
    dependencies: packages.length,
    vulnerableDependencies: packages.filter((item) => item.vulnerabilities.length).length,
    vulnerabilities: findings.length,
    severityCounts: counts,
  };
}

export const analyzeHelpers = { fixedVersions, highestNvdMetric };
