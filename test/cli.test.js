import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { cliHelpers, run } from '../src/cli.js';

test('reports the package version in the CLI', async () => {
  const packageJson = JSON.parse(await fs.readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const messages = [];
  const io = { log: (message) => messages.push(message), error() {} };

  assert.equal(await run(['--version'], io), 0);
  assert.deepEqual(messages, [packageJson.version]);
});

test('parses report and threshold options', () => {
  const options = cliHelpers.parseArgs(['./project', '--no-open', '--format', 'json', '--fail-on', 'high']);
  assert.equal(options.root, './project');
  assert.deepEqual(options.formats, ['json']);
  assert.equal(options.open, false);
  assert.equal(options.failOn, 'HIGH');
  assert.throws(() => cliHelpers.parseArgs(['--fail-on', 'urgent']), /--fail-on/);
});

test('reports missing supported dependency files as incomplete and exits non-zero', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'look-see-empty-'));
  try {
    const output = path.join(root, 'reports');
    const messages = [];
    const io = { log: (message) => messages.push(message), error: (message) => messages.push(message), warn: (message) => messages.push(message) };
    const exitCode = await run([root, '--out', output, '--format', 'json', '--no-open'], io);
    const report = JSON.parse(await fs.readFile(path.join(output, 'look-see-output.json'), 'utf8'));
    assert.equal(exitCode, 2);
    assert.equal(report.summary.dependencies, 0);
    assert.match(report.coverage.errors[0].message, /No supported dependency files/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
