import test from 'node:test';
import assert from 'node:assert/strict';
import { createPurl, packagePurlName } from '../src/purl.js';

test('creates npm PURLs, including scoped names', () => {
  assert.equal(createPurl('npm', 'lodash', '4.17.21'), 'pkg:npm/lodash@4.17.21');
  assert.equal(packagePurlName('npm', '@acme/widget'), 'pkg:npm/%40acme/widget');
  assert.equal(createPurl('npm', '@acme/widget', '1.2.3'), 'pkg:npm/%40acme/widget@1.2.3');
});

test('creates Go PURLs and escapes uppercase module path characters', () => {
  assert.equal(createPurl('Go', 'github.com/example/module', 'v1.2.3'), 'pkg:golang/github.com/example/module@v1.2.3');
  assert.equal(packagePurlName('Go', 'github.com/BurntSushi/toml'), 'pkg:golang/github.com/!burnt!sushi/toml');
});

test('normalizes Python distribution names in PyPI PURLs', () => {
  assert.equal(packagePurlName('PyPI', 'ZoPe.Interface'), 'pkg:pypi/zope-interface');
  assert.equal(createPurl('PyPI', 'Django_REST-framework', '3.14.0'), 'pkg:pypi/django-rest-framework@3.14.0');
  assert.equal(createPurl('PyPI', 'certifi', null), 'pkg:pypi/certifi');
});
