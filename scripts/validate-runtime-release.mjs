import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const manifest = JSON.parse(
  await readFile(new URL('../runtime-release.json', import.meta.url), 'utf8'),
);
const pinnedImage = /^[a-z0-9.-]+(?::[0-9]+)?\/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$/;

assert.equal(manifest.schemaVersion, 1);
assert.equal(manifest.channel, 'stable');
assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
assert.equal(manifest.protocolVersion, 3);
assert.ok(Number.isFinite(Date.parse(manifest.publishedAt)));
assert.match(manifest.releaseUrl, /^https:\/\/github\.com\/stoicsoft\/servercompass-client-portal\/releases\/tag\/v/);
assert.equal(manifest.sourceUrl, 'https://github.com/stoicsoft/servercompass-client-portal');
assert.match(manifest.images.gateway, pinnedImage);
assert.match(manifest.images.broker, pinnedImage);
assert.equal(typeof manifest.capabilities.restart, 'boolean');
assert.equal(typeof manifest.capabilities.lifecycle, 'boolean');
assert.equal(typeof manifest.capabilities.logs, 'boolean');

console.log(`runtime release manifest ${manifest.version}: ok`);
