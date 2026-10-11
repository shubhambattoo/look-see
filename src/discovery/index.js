import path from 'node:path';
import { findFiles } from './helpers.js';
import { scanNpmLocks } from './npm.js';
import { scanGoModules } from './go.js';
import { scanRequirements } from './python.js';
import { createPurl } from '../purl.js';

export async function discoverDependencies(root) {
  const [npmFiles, goFiles, pythonFiles] = await Promise.all([
    findFiles(root, new Set(['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'])),
    findFiles(root, new Set(['go.mod'])),
    findFiles(root, new Set(['requirements.txt']), (name) => /^requirements-.*\.txt$/.test(name)),
  ]);
  const [npmResult, goResult, pythonResult] = await Promise.all([
    scanNpmLocks(npmFiles), scanGoModules(goFiles), scanRequirements(pythonFiles, root),
  ]);
  const packages = [...npmResult.packages, ...goResult.packages, ...pythonResult.packages].map((item) => ({
    ...item,
    files: item.files.map((file) => path.relative(root, file) || '.'),
    purl: createPurl(item.ecosystem, item.name, item.version),
  }));
  return {
    packages,
    lockfiles: [...npmFiles, ...goFiles, ...pythonResult.files].map((file) => path.relative(root, file)),
    errors: [...npmResult.errors, ...goResult.errors, ...pythonResult.errors].map((error) => ({
      ...error, file: path.relative(root, error.file),
    })),
  };
}
