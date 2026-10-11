import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { queryNvd } from '../src/advisories/nvd.js';

test('fetches NVD records for multiple CVEs in one request and caches each result', async () => {
  const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), 'look-see-nvd-'));
  const previousCacheDir = process.env.LOOK_SEE_CACHE_DIR;
  const originalFetch = globalThis.fetch;
  const requests = [];
  process.env.LOOK_SEE_CACHE_DIR = cacheDir;
  globalThis.fetch = async (url) => {
    requests.push(new URL(url));
    return new Response(JSON.stringify({
      vulnerabilities: [
        { cve: { id: 'CVE-2024-1001', descriptions: [{ value: 'First advisory' }] } },
        { cve: { id: 'CVE-2024-1002', descriptions: [{ value: 'Second advisory' }] } },
        { cve: { id: 'CVE-2024-1003', descriptions: [{ value: 'Third advisory' }] } },
      ],
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  };

  const vulnerabilities = [
    { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2024-1001', 'CVE-2024-1002'] },
    { id: 'CVE-2024-1003', aliases: ['CVE-2024-1001'] },
  ];

  try {
    const result = await queryNvd(vulnerabilities);

    assert.equal(requests.length, 1);
    assert.equal(requests[0].searchParams.get('cveIds'), 'CVE-2024-1001,CVE-2024-1002,CVE-2024-1003');
    assert.equal(result.byCve.size, 3);
    assert.equal(result.byCve.get('CVE-2024-1002').descriptions[0].value, 'Second advisory');
    assert.deepEqual(result.errors, []);

    const cachedResult = await queryNvd(vulnerabilities);
    assert.equal(requests.length, 1);
    assert.equal(cachedResult.byCve.size, 3);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousCacheDir === undefined) delete process.env.LOOK_SEE_CACHE_DIR;
    else process.env.LOOK_SEE_CACHE_DIR = previousCacheDir;
    await fs.rm(cacheDir, { recursive: true, force: true });
  }
});
