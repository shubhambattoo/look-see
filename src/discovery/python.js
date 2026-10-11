import fs from 'node:fs/promises';
import path from 'node:path';
import { addPackage } from './helpers.js';

export function normalizePythonName(name) {
  return name.toLowerCase().replace(/[._-]+/g, '-');
}

function logicalLines(content) {
  const lines = [];
  let text = '';
  let startLine = 0;
  for (const [index, rawLine] of content.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!text) startLine = index + 1;
    text += `${text ? ' ' : ''}${line.replace(/\\\s*$/, '').trim()}`;
    if (/\\\s*$/.test(line)) continue;
    lines.push({ line: startLine, text });
    text = '';
  }
  if (text) lines.push({ line: startLine, text });
  return lines;
}

function parseRequirementLine(rawText, file, lineNumber) {
  const text = rawText.replace(/\s+#.*$/, '').trim();
  if (!text || text.startsWith('#')) return { ignored: true };

  const shortInclude = text.match(/^-r(?:\s+|=)?(.+)$/i);
  const longInclude = text.match(/^--requirement(?:\s+|=)(.+)$/i);
  const include = shortInclude?.[1] ?? longInclude?.[1];
  if (include) {
    return {
      include: {
        file: include.trim().replace(/^(?:"([^"]+)"|'([^']+)')$/, '$1$2'),
        line: lineNumber,
      },
    };
  }

  // Hash-checking options may follow a pinned requirement.
  const requirement = text.replace(/\s+--hash(?:=|\s+)\S+/g, '').trim();
  const nameMatch = requirement.match(/^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[A-Za-z0-9._,-]+\])?(.*)$/);
  if (!nameMatch) {
    // Index and binary-selection options do not identify dependencies. Includes,
    // editable installs, and other directives do, but cannot be resolved here.
    if (/^-(?:r|c|e)(?:$|\s|=|\S)|^--(?:requirement|constraint|editable)(?:$|\s|=)/i.test(requirement)) {
      return { error: { file, line: lineNumber, message: `Unsupported requirements directive: ${requirement}` } };
    }
    if (requirement.startsWith('-')) return { ignored: true };
    return { error: { file, line: lineNumber, message: `Could not parse requirement: ${requirement}` } };
  }

  const remainder = nameMatch[2].split(';', 1)[0].trim();
  if (remainder.startsWith('@')) {
    return { error: { file, line: lineNumber, message: `Direct URL requirements are not supported: ${nameMatch[1]}` } };
  }
  const specifierPattern = /^(?:===|==|=|~=|!=|<=|>=|<|>)\s*[^,\s]+(?:\s*,\s*(?:===|==|=|~=|!=|<=|>=|<|>)\s*[^,\s]+)*$/;
  if (remainder && !specifierPattern.test(remainder)) {
    return { error: { file, line: lineNumber, message: `Could not parse version constraint for ${nameMatch[1]}: ${remainder}` } };
  }

  const pin = remainder.match(/^(?:===|==|=)\s*([^\s,;]+)$/);
  const version = pin && !pin[1].includes('*') ? pin[1] : null;

  return {
    package: {
      ecosystem: 'PyPI',
      name: normalizePythonName(nameMatch[1]),
      version,
      direct: true,
      file,
      ...(remainder ? { specifier: remainder } : {}),
    },
  };
}

export function parseRequirements(content, file = 'requirements.txt') {
  const packages = new Map();
  const errors = [];
  const includes = [];
  for (const { line, text } of logicalLines(content)) {
    const result = parseRequirementLine(text, file, line);
    if (result.package) addPackage(packages, result.package);
    if (result.error) errors.push(result.error);
    if (result.include) includes.push(result.include);
  }
  return { packages: [...packages.values()], errors, includes };
}

export async function scanRequirements(requirementPaths, root) {
  const packages = new Map();
  const errors = [];
  const files = new Set();
  const scanned = new Set();
  const rootPath = path.resolve(root);
  const pending = requirementPaths.map((file) => ({ file, from: null }));

  while (pending.length) {
    const { file, from } = pending.shift();
    const absoluteFile = path.resolve(file);
    if (scanned.has(absoluteFile)) continue;
    scanned.add(absoluteFile);

    try {
      const stat = await fs.lstat(absoluteFile);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Requirements include is not a regular file');
      const result = parseRequirements(await fs.readFile(absoluteFile, 'utf8'), absoluteFile);
      files.add(absoluteFile);
      for (const item of result.packages) addPackage(packages, item);
      errors.push(...result.errors);
      for (const include of result.includes) {
        if (/^(?:[a-z][a-z\d+.-]*:|\/|\\)/i.test(include.file)) {
          errors.push({
            file: absoluteFile,
            line: include.line,
            message: `Only local requirements includes are supported: ${include.file}`,
          });
          continue;
        }
        const includedFile = path.resolve(path.dirname(absoluteFile), include.file);
        const relative = path.relative(rootPath, includedFile);
        if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
          errors.push({
            file: absoluteFile,
            line: include.line,
            message: `Requirements include is outside the project directory: ${include.file}`,
          });
          continue;
        }
        pending.push({
          file: includedFile,
          from: { file: absoluteFile, line: include.line },
        });
      }
    } catch (error) {
      errors.push({
        file: from?.file ?? absoluteFile,
        ...(from ? { line: from.line } : {}),
        message: from
          ? `Could not read included requirements file ${path.relative(rootPath, absoluteFile)}: ${error.message}`
          : error.message,
      });
    }
  }
  return { packages: [...packages.values()], errors, files: [...files].sort() };
}
