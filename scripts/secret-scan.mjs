import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';

const files = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
const patterns = [
  { name: 'PEM private key', expression: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { name: 'AWS access key', expression: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', expression: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/ },
  { name: 'Slack token', expression: /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/ },
  { name: 'capability token literal', expression: /\btgscap_[A-Za-z0-9_-]{32,}\b/ },
];
const findings = [];
for (const file of files) {
  let source;
  try { source = await readFile(file, 'utf8'); } catch { continue; }
  for (const pattern of patterns) {
    const match = pattern.expression.exec(source);
    if (match && !(pattern.name === 'capability token literal' && /REPLACE/i.test(match[0]))) findings.push(`${file}: ${pattern.name}`);
  }
}
if (findings.length > 0) {
  console.error('Secret scan failed:');
  for (const finding of findings) console.error(`- ${finding}`);
  process.exitCode = 1;
} else console.log(`Secret scan passed for ${files.length} tracked files`);
