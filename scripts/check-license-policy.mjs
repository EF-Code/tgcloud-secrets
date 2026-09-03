import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8'));
const allowed = new Set(['MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD', 'CC0-1.0', 'Unlicense']);
const findings = [];
for (const [path, metadata] of Object.entries(lock.packages || {})) {
  if (!path.startsWith('node_modules/') || !metadata.version) continue;
  let packageMetadata;
  try { packageMetadata = JSON.parse(await readFile(join(root, path, 'package.json'), 'utf8')); } catch { findings.push(`${path}: package metadata is unavailable`); continue; }
  const license = typeof packageMetadata.license === 'string' ? packageMetadata.license : packageMetadata.license?.type;
  if (!license || !allowed.has(license)) findings.push(`${path}: unapproved or undisclosed license ${license || 'unknown'}`);
}
if (findings.length > 0) {
  console.error('License policy check failed:');
  for (const finding of findings) console.error(`- ${finding}`);
  process.exitCode = 1;
} else console.log('License policy check passed');
