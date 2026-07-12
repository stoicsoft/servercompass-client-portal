import assert from 'node:assert/strict';
import { createPublicKey, verify as edVerify } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const manifestBytes = await readFile(new URL('../runtime-release.json', import.meta.url));
const manifest = JSON.parse(manifestBytes.toString('utf8'));
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
assert.match(manifest.images.gateway, /^ghcr\.io\/stoicsoft\/servercompass-client-portal\/gateway@/);
assert.match(manifest.images.broker, /^ghcr\.io\/stoicsoft\/servercompass-client-portal\/broker@/);
assert.equal(typeof manifest.capabilities.restart, 'boolean');
assert.equal(typeof manifest.capabilities.lifecycle, 'boolean');
assert.equal(typeof manifest.capabilities.logs, 'boolean');

console.log(`runtime release manifest ${manifest.version}: ok`);

// Once signing is enrolled (both files committed), guard that the detached
// signature verifies against the committed public key so a manifest can never be
// published with a stale or missing signature.
const [signatureB64, publicKeyB64] = await Promise.all([
  readFile(new URL('../runtime-release.json.sig', import.meta.url), 'utf8').catch(() => ''),
  readFile(new URL('../runtime-release.pubkey', import.meta.url), 'utf8').catch(() => ''),
]);
if (signatureB64.trim() && publicKeyB64.trim()) {
  const publicKey = createPublicKey({ key: Buffer.from(publicKeyB64.trim(), 'base64'), format: 'der', type: 'spki' });
  assert.equal(publicKey.asymmetricKeyType, 'ed25519', 'runtime-release.pubkey must be an Ed25519 SPKI key');
  const signature = Buffer.from(signatureB64.trim(), 'base64');
  assert.equal(signature.length, 64, 'runtime-release.json.sig must be a 64-byte Ed25519 signature');
  assert.ok(edVerify(null, manifestBytes, publicKey, signature), 'runtime-release.json.sig does not verify against runtime-release.pubkey');
  console.log('runtime release manifest signature: verified');
} else {
  assert.ok(
    !signatureB64.trim() && !publicKeyB64.trim(),
    'runtime-release.json.sig and runtime-release.pubkey must be committed together',
  );
  console.log('runtime release manifest signature: not enrolled');
}
