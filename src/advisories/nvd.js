import { getCached, setCached } from '../cache.js';

const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CACHE_TTL = 7 * 24 * 60 * 60 * 1000;
const NVD_API_KEY = process.env.NVD_API_KEY;
const MIN_INTERVAL_MS = NVD_API_KEY ? 700 : 6_100;
const MAX_CVES_PER_REQUEST = 100;

function cveIdsFrom(vulnerabilities) {
  const ids = new Set();
  for (const vulnerability of vulnerabilities) {
    for (const alias of vulnerability.aliases ?? []) {
      if (/^CVE-\d{4}-\d+$/i.test(alias)) ids.add(alias.toUpperCase());
    }
    if (/^CVE-\d{4}-\d+$/i.test(vulnerability.id ?? '')) ids.add(vulnerability.id.toUpperCase());
  }
  return [...ids].sort();
}

async function fetchCves(cveIds) {
  const url = new URL(NVD_URL);
  url.searchParams.set('cveIds', cveIds.join(','));
  const headers = { accept: 'application/json' };
  if (NVD_API_KEY) headers.apiKey = NVD_API_KEY;
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`NVD returned HTTP ${response.status}`);
  const body = await response.json();
  return new Map((body.vulnerabilities ?? [])
    .map(({ cve }) => [cve?.id, cve])
    .filter(([id]) => id));
}

export async function queryNvd(vulnerabilities, { onProgress } = {}) {
  const ids = cveIdsFrom(vulnerabilities);
  const byCve = new Map();
  const errors = [];
  let lastRequestAt = 0;
  let completed = 0;
  const missing = [];
  onProgress?.({ stage: 'nvd', completed, total: ids.length });
  for (const cveId of ids) {
    const cacheKey = `nvd:${cveId}`;
    const cached = await getCached(cacheKey, CACHE_TTL);
    if (cached !== null) {
      byCve.set(cveId, cached && Object.hasOwn(cached, 'cve') ? cached.cve : cached);
      completed += 1;
      onProgress?.({ stage: 'nvd', completed, total: ids.length });
    } else missing.push(cveId);
  }

  for (let offset = 0; offset < missing.length; offset += MAX_CVES_PER_REQUEST) {
    const batch = missing.slice(offset, offset + MAX_CVES_PER_REQUEST);
    const waitMs = Math.max(0, MIN_INTERVAL_MS - (Date.now() - lastRequestAt));
    if (waitMs) await new Promise((resolve) => setTimeout(resolve, waitMs));
    try {
      const cves = await fetchCves(batch);
      lastRequestAt = Date.now();
      await Promise.all(batch.map(async (cveId) => {
        const cve = cves.get(cveId) ?? null;
        byCve.set(cveId, cve);
        await setCached(`nvd:${cveId}`, { cve });
      }));
      completed += batch.length;
      onProgress?.({ stage: 'nvd', completed, total: ids.length });
    } catch (error) {
      lastRequestAt = Date.now();
      for (const cveId of batch) {
        errors.push({ source: 'NVD', cveId, message: error.message });
      }
      completed += batch.length;
      onProgress?.({ stage: 'nvd', completed, total: ids.length });
      if (/HTTP 403|HTTP 429/.test(error.message)) {
        errors.push({ source: 'NVD', message: 'Stopped further NVD lookups after a rate-limit response.' });
        break;
      }
    }
  }
  return { byCve, errors };
}

export const nvdHelpers = { cveIdsFrom };
