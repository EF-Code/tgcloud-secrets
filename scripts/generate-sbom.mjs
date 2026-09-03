import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const lock = JSON.parse(await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'));
const components = [];
for (const [path, metadata] of Object.entries(lock.packages || {})) {
  if (!path.startsWith('node_modules/') || !metadata.version) continue;
  const packageName = path.slice('node_modules/'.length);
  const purl = `pkg:npm/${packageName.replace(/^@/, '%40')}@${metadata.version}`;
  const component = { type: 'library', 'bom-ref': purl, name: packageName, version: metadata.version, purl };
  if (metadata.integrity) component.externalReferences = [{ type: 'distribution', url: metadata.resolved || '', comment: metadata.integrity }];
  components.push(component);
}
components.sort((left, right) => left.purl.localeCompare(right.purl));
const digest = createHash('sha256').update(await readFile(new URL('../package-lock.json', import.meta.url))).digest('hex');
const serial = `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(12, 15)}-8${digest.slice(15, 18)}-${digest.slice(18, 30)}`;
console.log(JSON.stringify({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${serial}`,
  version: 1,
  metadata: { component: { type: 'application', name: lock.name || 'tgcloud-secrets', version: lock.version || '0.0.0' } },
  components,
}, null, 2));
