import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { npmParsers } from '../src/discovery/npm.js';
import { goParser, parseGoMod } from '../src/discovery/go.js';
import { parseRequirements } from '../src/discovery/python.js';
import { discoverDependencies } from '../src/discovery/index.js';

test('reads npm v2/v3 lockfile packages and marks top-level dependencies', () => {
  const result = npmParsers.parseNpmPackageLock({
    packages: {
      '': { dependencies: { lodash: '^4.0.0', '@acme/widget': '^1.0.0' } },
      'node_modules/lodash': { version: '4.17.21' },
      'node_modules/@acme/widget': { version: '1.2.0' },
      'node_modules/@acme/widget/node_modules/lodash': { version: '4.17.20' },
    },
  }, 'package-lock.json');
  assert.deepEqual(result.map(({ name, version, direct }) => ({ name, version, direct })), [
    { name: 'lodash', version: '4.17.21', direct: true },
    { name: '@acme/widget', version: '1.2.0', direct: true },
    { name: 'lodash', version: '4.17.20', direct: false },
  ]);
});

test('parses pnpm package keys', () => {
  assert.deepEqual(npmParsers.parsePnpmPackageKey('/lodash@4.17.21', {}), {
    name: 'lodash', version: '4.17.21',
  });
  assert.deepEqual(npmParsers.parsePnpmPackageKey('/@scope/name@2.0.0(peer@1.0.0)', {}), {
    name: '@scope/name', version: '2.0.0',
  });
});

test('parses a Go module requirements block and marks indirect modules', () => {
  assert.equal(goParser.cleanGoVersion('v1.2.3'), 'v1.2.3');
  const packages = parseGoMod(`module example.test/app

go 1.22
require example.com/direct v1.2.3
require (
  example.com/indirect v2.3.4 // indirect
  example.com/another v1.0.0
)
`, 'go.mod');
  assert.deepEqual(packages.map(({ name, version, direct }) => ({ name, version, direct })), [
    { name: 'example.com/direct', version: 'v1.2.3', direct: true },
    { name: 'example.com/indirect', version: 'v2.3.4', direct: false },
    { name: 'example.com/another', version: 'v1.0.0', direct: true },
  ]);
});

test('parses exact pins, ranges, unpinned requirements, extras, markers, and canonical names', () => {
  const result = parseRequirements(`
# generated requirements
Requests[security]==2.31.0; python_version >= "3.8"
zope.interface===5.4.0 --hash=sha256:abc
unlocked>=1.0
certifi
legacy=1.2.3
bounded>=2.0,<=5.0
`, 'requirements.txt');

  assert.deepEqual(result.packages.map(({ ecosystem, name, version, direct, specifiers }) => ({
    ecosystem, name, version, direct, specifiers,
  })), [
    { ecosystem: 'PyPI', name: 'requests', version: '2.31.0', direct: true, specifiers: ['==2.31.0'] },
    { ecosystem: 'PyPI', name: 'zope-interface', version: '5.4.0', direct: true, specifiers: ['===5.4.0'] },
    { ecosystem: 'PyPI', name: 'unlocked', version: null, direct: true, specifiers: ['>=1.0'] },
    { ecosystem: 'PyPI', name: 'certifi', version: null, direct: true, specifiers: undefined },
    { ecosystem: 'PyPI', name: 'legacy', version: '1.2.3', direct: true, specifiers: ['=1.2.3'] },
    { ecosystem: 'PyPI', name: 'bounded', version: null, direct: true, specifiers: ['>=2.0,<=5.0'] },
  ]);
  assert.deepEqual(result.errors, []);
});

test('follows local requirements includes recursively and scans included files once', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'look-see-python-includes-'));
  try {
    await fs.mkdir(path.join(root, 'requirements'));
    await fs.writeFile(path.join(root, 'requirements', 'requirements-all.txt'), [
      '-r base.txt',
      '-r nested/dev.txt',
    ].join('\n'));
    await fs.writeFile(path.join(root, 'requirements', 'base.txt'), 'requests==2.31.0\n-r nested/shared.txt\n');
    await fs.mkdir(path.join(root, 'requirements', 'nested'));
    await fs.writeFile(path.join(root, 'requirements', 'nested', 'dev.txt'), 'pytest==8.1.1\n');
    await fs.writeFile(path.join(root, 'requirements', 'nested', 'shared.txt'), 'urllib3==2.2.1\n');

    const result = await discoverDependencies(root);
    assert.deepEqual(result.packages.map(({ purl }) => purl).sort(), [
      'pkg:pypi/pytest@8.1.1',
      'pkg:pypi/requests@2.31.0',
      'pkg:pypi/urllib3@2.2.1',
    ]);
    assert.deepEqual(result.lockfiles, [
      'requirements/base.txt',
      'requirements/nested/dev.txt',
      'requirements/nested/shared.txt',
      'requirements/requirements-all.txt',
    ]);
    assert.deepEqual(result.errors, []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('discovers multiple Python requirements files recursively', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'look-see-python-'));
  try {
    const nested = path.join(root, 'services', 'api');
    await fs.mkdir(nested, { recursive: true });
    await fs.writeFile(path.join(root, 'requirements.txt'), 'Flask==3.0.0\n');
    await fs.writeFile(path.join(nested, 'requirements-dev.txt'), 'pytest==8.1.1\n');
    const result = await discoverDependencies(root);
    assert.deepEqual(result.lockfiles, ['requirements.txt', 'services/api/requirements-dev.txt']);
    assert.deepEqual(result.packages.map(({ purl }) => purl), [
      'pkg:pypi/flask@3.0.0',
      'pkg:pypi/pytest@8.1.1',
    ]);
    assert.deepEqual(result.errors, []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('parses classic Yarn lock entries', () => {
  const result = npmParsers.parseYarnLock(`# yarn lockfile v1
left-pad@^1.0.0:
  version "1.3.0"
  resolved "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"

"@scope/pkg@^2.0.0":
  version "2.1.0"
`, 'yarn.lock', new Set(['left-pad']));
  assert.deepEqual(result.map(({ name, version, direct }) => ({ name, version, direct })), [
    { name: 'left-pad', version: '1.3.0', direct: true },
    { name: '@scope/pkg', version: '2.1.0', direct: false },
  ]);
});

test('parses modern pnpm lockfile package records', () => {
  const result = npmParsers.parsePnpmLock(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.0.0
        version: 4.17.21
packages:
  lodash@4.17.21: {}
`, 'pnpm-lock.yaml', new Set(['lodash']));
  assert.deepEqual(result.map(({ name, version, direct }) => ({ name, version, direct })), [
    { name: 'lodash', version: '4.17.21', direct: true },
  ]);
});
