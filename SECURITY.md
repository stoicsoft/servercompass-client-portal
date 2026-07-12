# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting for this repository. Include the affected version or image digest, reproduction steps, expected impact, and any evidence that the issue crosses an application or permission boundary.

Please avoid accessing data that is not yours, disrupting a production service, or publishing details before a fix is available.

## Supported versions

This project is pre-1.0. Only the most recent signed release is supported. Server Compass Desktop additionally enforces runtime protocol compatibility and immutable image digests.

## Security boundaries

- The public gateway must not have the Docker socket, host mounts, SSH credentials, application secrets, or broker admin credentials.
- The private broker must not be publicly routed.
- All Docker reads and mutations must derive scope from the stored link policy and exact immutable labels.
- State-changing requests require permission, CSRF, idempotency, rate-limit, mutation-lease, and audit checks.
- Revocation and rotation must invalidate existing sessions.

