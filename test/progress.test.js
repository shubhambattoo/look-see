import test from 'node:test';
import assert from 'node:assert/strict';
import { createProgress, progressHelpers } from '../src/progress.js';

function stripAnsi(value) {
  return value.replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, '');
}

test('prints the Look-See ASCII banner before progress', () => {
  const messages = [];
  const progress = createProgress({ log: (message) => messages.push(message) }, { interactive: false });
  progress.banner();
  progress.start('Scanning project');
  const banner = stripAnsi(messages[0]);
  assert.equal(banner, progressHelpers.BANNER);
  assert.match(banner, /___        ______      ______/);
  assert.match(banner, /\\_______\)/);
  assert.match(messages[1], /Scanning project/);
});
