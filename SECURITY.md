# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting for this repository. Include the affected version or image digest, reproduction steps, expected impact, and any evidence that the issue crosses an application or permission boundary.

Please avoid accessing data that is not yours, disrupting a production service, or publishing details before a fix is available.

## Supported versions

This project is pre-1.0. Only the most recent signed release is supported. Server Compass Desktop additionally enforces runtime protocol compatibility and immutable image digests.

## Runtime manifest signing

`runtime-release.json` may carry a detached Ed25519 signature so the desktop can reject a tampered or downgraded manifest even if the hosting/transport is compromised. Enrollment:

1. `npm run manifest:keygen` — generate the keypair. Commit the base64 SPKI public key to `runtime-release.pubkey` and pin the same value in the desktop (`CLIENT_PORTAL_MANIFEST_PUBLIC_KEY_B64`). Store the private key as the `PORTAL_MANIFEST_SIGNING_KEY` secret; never commit it.
2. Whenever `runtime-release.json` changes, run `PORTAL_MANIFEST_SIGNING_KEY_FILE=key.pem npm run manifest:sign` and commit `runtime-release.json` and `runtime-release.json.sig` together.
3. `npm run test:manifest` verifies the committed signature against the committed public key in CI. Until a key is pinned, the desktop keeps enforcing HTTPS, the strict manifest schema, and immutable cosign-signed image digests.

## Security boundaries

- The public gateway must not have the Docker socket, host mounts, SSH credentials, application secrets, or broker admin credentials.
- The private broker must not be publicly routed.
- All Docker reads and mutations must derive scope from the stored link policy and exact immutable labels.
- State-changing requests require permission, CSRF, idempotency, rate-limit, mutation-lease, and audit checks.
- Revocation and rotation must invalidate existing sessions.
- The fronting reverse proxy must set or append `X-Forwarded-For`. The gateway trusts exactly `PORTAL_TRUSTED_PROXY_HOPS` proxy hop(s) (default 1) and treats every value further from the proxy as untrusted, so a client cannot spoof the source used for rate-limiting and audit attribution. Set the variable to match the real number of trusted proxies in front of the gateway (`0` disables `X-Forwarded-For` trust entirely).

