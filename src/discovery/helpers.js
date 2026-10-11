import fs from 'node:fs/promises';
import path from 'node:path';

export async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

export function dependencyNames(manifest) {
  return new Set([
    ...Object.keys(manifest.dependencies ?? {}),
    ...Object.keys(manifest.devDependencies ?? {}),
    ...Object.keys(manifest.optionalDependencies ?? {}),
    ...Object.keys(manifest.peerDependencies ?? {}),
  ]);
}

export function packageNameFromNodeModulesPath(packagePath) {
  const marker = 'node_modules/';
  const index = packagePath.lastIndexOf(marker);
  if (index < 0) return null;
  const remainder = packagePath.slice(index + marker.length).split('/');
  if (!remainder[0]) return null;
  return remainder[0].startsWith('@')
    ? (remainder[1] ? `${remainder[0]}/${remainder[1]}` : null)
    : remainder[0];
}

export function addPackage(packages, { ecosystem, name, version, direct = false, file, specifier }) {
  if (!name || typeof name !== 'string' || (version != null && typeof version !== 'string')) return;
  const normalizedVersion = version ?? null;
  const key = `${ecosystem}\0${name}\0${normalizedVersion ?? ''}`;
  const current = packages.get(key) ?? {
    ecosystem,
    name,
    version: normalizedVersion,
    direct: false,
    files: [],
  };
  current.direct ||= direct;
  if (file && !current.files.includes(file)) current.files.push(file);
  if (specifier) {
    current.specifiers ??= [];
    if (!current.specifiers.includes(specifier)) current.specifiers.push(specifier);
  }
  packages.set(key, current);
}

export async function findFiles(root, wantedNames, matchesName = () => false) {
  const found = [];
  const ignored = new Set([
    '.git', '.hg', '.svn', 'node_modules', 'vendor', 'dist', 'build',
    '.next', '.nuxt', 'coverage', '.look-see',
  ]);

  async function visit(directory) {
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!ignored.has(entry.name)) await visit(fullPath);
      } else if (entry.isFile() && (wantedNames.has(entry.name) || matchesName(entry.name))) {
        found.push(fullPath);
      }
    }
  }

  await visit(root);
  return found.sort();
}
