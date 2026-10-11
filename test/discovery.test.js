import test from 'node:test';
import assert from 'node:assert/strict';
import { npmParsers } from '../src/discovery/npm.js';
import { goParser, parseGoMod } from '../src/discovery/go.js';

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
