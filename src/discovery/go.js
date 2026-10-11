import fs from 'node:fs/promises';
import path from 'node:path';
import { addPackage } from './helpers.js';

function cleanGoVersion(version) {
  return version?.trim();
}

export async function scanGoModules(goModPaths) {
  const packages = new Map();
  const errors = [];
  for (const file of goModPaths) {
    try {
      const content = await fs.readFile(file, 'utf8');
      for (const item of parseGoMod(content, file)) {
        addPackage(packages, item);
      }
    } catch (error) {
      errors.push({ file, message: error.message });
    }
  }
  return { packages: [...packages.values()], errors };
}

export function parseGoMod(content, file = 'go.mod') {
  const packages = new Map();
  let inRequire = false;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/\/\/.*$/, '').trim();
    if (!line) continue;
    if (/^require\s+\($/.test(line)) {
      inRequire = true;
      continue;
    }
    if (inRequire && line === ')') {
      inRequire = false;
      continue;
    }
    if (line.startsWith('require ')) {
      const fields = line.slice('require '.length).trim().split(/\s+/);
      if (fields.length >= 2) {
        addPackage(packages, {
          ecosystem: 'Go', name: fields[0], version: cleanGoVersion(fields[1]),
          direct: !rawLine.includes('// indirect'), file,
        });
      }
      continue;
    }
    if (inRequire) {
      const fields = line.split(/\s+/);
      if (fields.length >= 2) {
        addPackage(packages, {
          ecosystem: 'Go', name: fields[0], version: cleanGoVersion(fields[1]),
          direct: !rawLine.includes('// indirect'), file,
        });
      }
    }
  }
  return [...packages.values()];
}

export const goParser = { cleanGoVersion };
