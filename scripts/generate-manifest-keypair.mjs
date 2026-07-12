// One-time helper: generate the Ed25519 keypair used to sign runtime-release.json.
//
//   node scripts/generate-manifest-keypair.mjs
//
// - Commit the printed base64 SPKI public key to runtime-release.pubkey and pin
//   the same value in the desktop (CLIENT_PORTAL_MANIFEST_PUBLIC_KEY_B64).
// - Store the printed PKCS8 private key PEM as the GitHub secret
//   PORTAL_MANIFEST_SIGNING_KEY (or keep it offline). Never commit the private key.
import { generateKeyPairSync } from 'node:crypto';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString().trim();

console.log('# Public key (base64 SPKI) — commit to runtime-release.pubkey and pin in the desktop:');
console.log(publicKeyB64);
console.log('');
console.log('# Private key (PKCS8 PEM) — store as the GitHub secret PORTAL_MANIFEST_SIGNING_KEY. Keep offline, never commit:');
console.log(privateKeyPem);
