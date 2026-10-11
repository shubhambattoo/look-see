import { getCached, setCached } from '../cache.js';
import { packagePurlName } from '../purl.js';

const OSV_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';
const CACHE_TTL = 24 * 60 * 60 * 1000;

async function fetchBatch(queries) {
  const response = await fetch(OSV_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ queries }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}`);
  return response.json();
}

async function fetchAdvisory(id) {
  const response = await fetch(`${OSV_VULN_URL}${encodeURIComponent(id)}`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`OSV advisory lookup returned HTTP ${response.status}`);
  return response.json();
}

async function hydrateAdvisories(byPackage, errors, onProgress) {
  const unique = new Map();
  for (const vulnerabilities of byPackage.values()) {
    for (const vulnerability of vulnerabilities) {
      if (vulnerability?.id) unique.set(vulnerability.id, vulnerability);
    }
  }

  const details = new Map();
  const missing = [];
  for (const [id, fallback] of unique) {
    const cached = await getCached(`osv-vuln:${id}`, CACHE_TTL);
    if (cached) details.set(id, cached);
    else missing.push([id, fallback]);
  }

  let completed = unique.size - missing.length;
  onProgress?.({ stage: 'advisories', completed, total: unique.size });
  for (let offset = 0; offset < missing.length; offset += 10) {
    const chunk = missing.slice(offset, offset + 10);
    const results = await Promise.all(chunk.map(async ([id, fallback]) => {
      try {
        const advisory = await fetchAdvisory(id);
        await setCached(`osv-vuln:${id}`, advisory);
        return [id, advisory];
      } catch (error) {
        errors.push({ source: 'OSV', advisoryId: id, message: error.message });
        return [id, fallback];
      }
    }));
    for (const [id, advisory] of results) details.set(id, advisory);
    completed += chunk.length;
    onProgress?.({ stage: 'advisories', completed, total: unique.size });
  }

  for (const [purl, vulnerabilities] of byPackage) {
    byPackage.set(purl, vulnerabilities.map((vulnerability) => details.get(vulnerability.id) ?? vulnerability));
  }
}

export async function queryOsv(packages, { onProgress } = {}) {
  const byPackage = new Map();
  const errors = [];
  const missing = [];
  for (const item of packages) {
    const key = `osv:${item.purl}`;
    const cached = await getCached(key, CACHE_TTL);
    if (cached) byPackage.set(item.purl, cached);
    else missing.push(item);
  }

  let packageCompleted = packages.length - missing.length;
  onProgress?.({ stage: 'packages', completed: packageCompleted, total: packages.length });
  for (let offset = 0; offset < missing.length; offset += 100) {
    const batch = missing.slice(offset, offset + 100);
    const queries = batch.map((item) => ({
      version: item.version,
      package: { purl: packagePurlName(item.ecosystem, item.name) },
    }));
    try {
      const result = await fetchBatch(queries);
      if (!Array.isArray(result.results) || result.results.length !== batch.length) {
        throw new Error('OSV returned an unexpected batch response');
      }
      for (let index = 0; index < batch.length; index += 1) {
        const item = batch[index];
        const response = result.results[index];
        if (response?.error) {
          errors.push({ source: 'OSV', package: item.purl, message: response.error });
          continue;
        }
        const vulnerabilities = response?.vulns ?? [];
        byPackage.set(item.purl, vulnerabilities);
        await setCached(`osv:${item.purl}`, vulnerabilities);
      }
    } catch (error) {
      errors.push({ source: 'OSV', message: error.message });
    }
    packageCompleted += batch.length;
    onProgress?.({ stage: 'packages', completed: packageCompleted, total: packages.length });
  }
  await hydrateAdvisories(byPackage, errors, onProgress);
  return { byPackage, errors };
}
