import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

function cacheDirectory() {
  if (process.env.LOOK_SEE_CACHE_DIR) return process.env.LOOK_SEE_CACHE_DIR;
  if (process.env.XDG_CACHE_HOME) return path.join(process.env.XDG_CACHE_HOME, 'look-see');
  if (process.platform === 'win32' && process.env.LOCALAPPDATA) {
    return path.join(process.env.LOCALAPPDATA, 'look-see', 'cache');
  }
  return path.join(os.homedir(), '.cache', 'look-see');
}

function cachePath(key) {
  const digest = crypto.createHash('sha256').update(key).digest('hex');
  return path.join(cacheDirectory(), `${digest}.json`);
}

export async function getCached(key, maxAgeMs) {
  try {
    const value = JSON.parse(await fs.readFile(cachePath(key), 'utf8'));
    if (Date.now() - value.cachedAt > maxAgeMs) return null;
    return value.data;
  } catch {
    return null;
  }
}

export async function setCached(key, data) {
  try {
    const file = cachePath(key);
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, JSON.stringify({ cachedAt: Date.now(), data }), 'utf8');
  } catch {
    // Cache failures should not interrupt a scan.
  }
}
