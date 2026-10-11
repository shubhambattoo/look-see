import path from 'node:path';
import { findFiles } from './helpers.js';
import { scanNpmLocks } from './npm.js';
import { scanGoModules } from './go.js';
import { createPurl } from '../purl.js';

export async function discoverDependencies(root) {
  const [npmFiles, goFiles] = await Promise.all([
    findFiles(root, new Set(['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'])),
    findFiles(root, new Set(['go.mod'])),
  ]);
  const [npmResult, goResult] = await Promise.all([
    scanNpmLocks(npmFiles), scanGoModules(goFiles),
  ]);
  const packages = [...npmResult.packages, ...goResult.packages].map((item) => ({
    ...item,
    files: item.files.map((file) => path.relative(root, file) || '.'),
    purl: createPurl(item.ecosystem, item.name, item.version),
  }));
  return {
    packages,
    lockfiles: [...npmFiles, ...goFiles].map((file) => path.relative(root, file)),
    errors: [...npmResult.errors, ...goResult.errors].map((error) => ({
      ...error, file: path.relative(root, error.file),
    })),
  };
}
