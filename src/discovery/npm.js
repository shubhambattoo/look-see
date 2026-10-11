import fs from 'node:fs/promises';
import path from 'node:path';
import lockfile from '@yarnpkg/lockfile';
import YAML from 'yaml';
import { addPackage, dependencyNames, packageNameFromNodeModulesPath, readJson } from './helpers.js';

function walkNpmV1(dependencies, packages, file, directNames, isDirect = false) {
  for (const [name, dependency] of Object.entries(dependencies ?? {})) {
    if (dependency?.version) {
      addPackage(packages, {
        ecosystem: 'npm', name, version: dependency.version,
        direct: isDirect && directNames.has(name), file,
      });
    }
    walkNpmV1(dependency?.dependencies, packages, file, directNames, false);
  }
}

function parseNpmPackageLock(lock, file) {
  const packages = new Map();
  const directNames = dependencyNames(lock.packages?.[''] ?? lock);
  if (lock.packages && typeof lock.packages === 'object') {
    for (const [packagePath, metadata] of Object.entries(lock.packages)) {
      if (!packagePath || !metadata || metadata.link || !metadata.version) continue;
      const name = metadata.name ?? packageNameFromNodeModulesPath(packagePath);
      if (!name) continue;
      addPackage(packages, {
        ecosystem: 'npm', name, version: String(metadata.version),
        direct: directNames.has(name) && !packagePath.slice(1).includes('node_modules/'),
        file,
      });
    }
  } else {
    walkNpmV1(lock.dependencies, packages, file, directNames, true);
  }
  return [...packages.values()];
}

function nameFromYarnDescriptor(descriptor) {
  const value = descriptor.trim().replace(/^['"]|['"]$/g, '');
  const at = value.lastIndexOf('@');
  if (at <= 0) return null;
  return value.slice(0, at);
}

function parseYarnLock(content, file, directNames) {
  const packages = new Map();
  if (content.startsWith('__metadata:')) {
    const parsed = YAML.parse(content);
    for (const [descriptor, metadata] of Object.entries(parsed ?? {})) {
      if (descriptor === '__metadata' || !metadata?.version) continue;
      const name = nameFromYarnDescriptor(metadata.resolution ?? descriptor.split(',')[0]);
      if (!name) continue;
      addPackage(packages, {
        ecosystem: 'npm', name, version: String(metadata.version),
        direct: directNames.has(name), file,
      });
    }
  } else {
    const parsed = lockfile.parse(content);
    if (parsed.type !== 'success') throw new Error(`Could not parse Yarn lockfile: ${parsed.type}`);
    for (const [descriptor, metadata] of Object.entries(parsed.object)) {
      if (!metadata?.version) continue;
      const name = nameFromYarnDescriptor(descriptor.split(',')[0]);
      if (!name) continue;
      addPackage(packages, {
        ecosystem: 'npm', name, version: String(metadata.version),
        direct: directNames.has(name), file,
      });
    }
  }
  return [...packages.values()];
}

function parsePnpmPackageKey(key, metadata) {
  if (metadata?.name && metadata?.version) return { name: metadata.name, version: String(metadata.version) };
  let value = key.replace(/^\//, '');
  value = value.replace(/\([^)]*\)$/g, '');
  const at = value.lastIndexOf('@');
  if (at > value.indexOf('/')) {
    const name = value.slice(0, at);
    const version = value.slice(at + 1).split('_')[0];
    if (name && version) return { name, version };
  }
  const slash = value.lastIndexOf('/');
  if (slash > 0) {
    const name = value.slice(0, slash);
    const version = value.slice(slash + 1).split('_')[0];
    if (name && version && /^\d|^v\d/.test(version)) return { name, version };
  }
  return null;
}

function parsePnpmLock(content, file, directNames) {
  const parsed = YAML.parse(content) ?? {};
  const packages = new Map();
  for (const [key, metadata] of Object.entries(parsed.packages ?? {})) {
    const item = parsePnpmPackageKey(key, metadata);
    if (!item) continue;
    addPackage(packages, {
      ecosystem: 'npm', ...item, direct: directNames.has(item.name), file,
    });
  }
  return [...packages.values()];
}

async function readDirectNames(lockPath) {
  const manifestPath = path.join(path.dirname(lockPath), 'package.json');
  try {
    return dependencyNames(await readJson(manifestPath));
  } catch {
    return new Set();
  }
}

export async function scanNpmLocks(lockPaths) {
  const combined = new Map();
  const errors = [];
  for (const file of lockPaths) {
    try {
      let found;
      if (path.basename(file) === 'package-lock.json') {
        found = parseNpmPackageLock(await readJson(file), file);
      } else {
        const content = await fs.readFile(file, 'utf8');
        const directNames = await readDirectNames(file);
        found = path.basename(file) === 'pnpm-lock.yaml'
          ? parsePnpmLock(content, file, directNames)
          : parseYarnLock(content, file, directNames);
      }
      for (const item of found) {
        const key = `${item.ecosystem}\0${item.name}\0${item.version}`;
        const current = combined.get(key) ?? { ...item, files: [] };
        current.direct ||= item.direct;
        if (!current.files.includes(file)) current.files.push(file);
        combined.set(key, current);
      }
    } catch (error) {
      errors.push({ file, message: error.message });
    }
  }
  return { packages: [...combined.values()], errors };
}

export const npmParsers = { parseNpmPackageLock, parsePnpmLock, parseYarnLock, parsePnpmPackageKey };
