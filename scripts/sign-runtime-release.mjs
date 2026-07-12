// Sign runtime-release.json with the Ed25519 private key and write the detached
// signature to runtime-release.json.sig (base64 of the 64-byte signature).
//
//   PORTAL_MANIFEST_SIGNING_KEY="$(cat key.pem)" node scripts/sign-runtime-release.mjs
//   # or
//   PORTAL_MANIFEST_SIGNING_KEY_FILE=key.pem node scripts/sign-runtime-release.mjs
//
// Run this whenever runtime-release.json changes, then commit both files together.
import { createPrivateKey, sign as edSign } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const inlineKey = process.env.PORTAL_MANIFEST_SIGNING_KEY;
const keyFile = process.env.PORTAL_MANIFEST_SIGNING_KEY_FILE;
const keyPem = (inlineKey ?? (keyFile ? await readFile(keyFile, 'utf8') : '')).trim();
if (!keyPem) {
  console.error('Set PORTAL_MANIFEST_SIGNING_KEY (PEM contents) or PORTAL_MANIFEST_SIGNING_KEY_FILE (path).');
  process.exit(1);
}

const privateKey = createPrivateKey(keyPem);
if (privateKey.asymmetricKeyType !== 'ed25519') {
  console.error('The signing key must be an Ed25519 private key.');
  process.exit(1);
}

const manifestUrl = new URL('../runtime-release.json', import.meta.url);
const manifestBytes = await readFile(manifestUrl);
const signature = edSign(null, manifestBytes, privateKey);
await writeFile(new URL('../runtime-release.json.sig', import.meta.url), `${signature.toString('base64')}\n`);
console.log(`Wrote runtime-release.json.sig (${signature.length}-byte Ed25519 signature, base64).`);
