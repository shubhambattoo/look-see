import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { queryOsv } from '../src/advisories/osv.js';

test('queries packages with unknown versions without sending a version to OSV', async () => {
  const cacheDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'look-see-osv-'));
  const previousCacheDirectory = process.env.LOOK_SEE_CACHE_DIR;
  const originalFetch = globalThis.fetch;
  let requestBody;
  process.env.LOOK_SEE_CACHE_DIR = cacheDirectory;
  globalThis.fetch = async (_url, options) => {
    requestBody = JSON.parse(options.body);
    return new Response(JSON.stringify({ results: [{ vulns: [] }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    await queryOsv([{
      ecosystem: 'PyPI', name: 'no-version-package', version: null,
      purl: 'pkg:pypi/no-version-package',
    }]);
    assert.deepEqual(requestBody, {
      queries: [{ package: { purl: 'pkg:pypi/no-version-package' } }],
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (previousCacheDirectory == null) delete process.env.LOOK_SEE_CACHE_DIR;
    else process.env.LOOK_SEE_CACHE_DIR = previousCacheDirectory;
    await fs.rm(cacheDirectory, { recursive: true, force: true });
  }
});
