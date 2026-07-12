# Server Compass Client Portal

Server Compass Client Portal is the open-source, self-hosted runtime that lets an application owner share narrowly scoped status and operations access with a client. It is normally provisioned onto a VPS by [Server Compass Desktop](https://github.com/stoicsoft/server-compass-desktop).

The project publishes two containers:

- **Gateway** — the public, unprivileged web application. It has no Docker socket, SSH credentials, application environment, or administrative API.
- **Broker** — the private policy and metrics service. It is the only component with the Docker socket and exposes a fixed, stack-scoped operation allowlist.

The containers are separate security boundaries but are versioned and released together from this repository.

## Architecture

```text
Client browser
      |
      | HTTPS + capability-scoped session
      v
Public gateway (no host privileges)
      |
      | authenticated internal API
      v
Private broker (fixed API + policy + audit)
      |
      | exact stack/project label scope
      v
Docker Engine
```

Server Compass Desktop is the desired-state controller. It provisions the runtime over SSH/SFTP, applies link policies, configures the public route, and pins both runtime images by immutable digest. The portal remains available when the desktop application is closed.

## Current capabilities

- Private expiring links with an optional passcode.
- CPU, memory, network rate/total, writable-layer storage, block I/O, uptime, health, and retained history.
- Optional bounded and redacted application logs.
- Optional whole-application Start, Restart, and Suspend actions.
- Per-link permissions, revision checks, session invalidation, rate limits, mutation leases, idempotency, and audit events.
- Separate managed-Traefik, external-proxy, and loopback-preview paths.

Reinstall and arbitrary Docker, shell, file, database, or environment access are intentionally not exposed. Backup execution remains owner-managed until an always-on scoped backup executor is available.

## Repository layout

```text
packages/
  client-portal-protocol/  Versioned policy and compatibility contract
  client-portal-runtime/
    gateway/               Public browser gateway and portal assets
    broker/                Private policy, metrics, audit, and action service
    shared/                Bounded HTTP helpers
    test/                  Protocol and security-focused runtime tests
```

## Development

Requirements:

- Node.js 22 or later.
- Docker with Buildx for container builds.

Install the broker's native runtime dependency and run the test suite:

```sh
npm run install:runtime
npm test
```

Build the containers locally:

```sh
docker build \
  -f packages/client-portal-runtime/gateway/Dockerfile \
  -t servercompass-client-portal-gateway:dev \
  packages

docker build \
  -f packages/client-portal-runtime/broker/Dockerfile \
  -t servercompass-client-portal-broker:dev \
  packages
```

## Releases

Pushing a `v*` tag runs tests, builds `linux/amd64` and `linux/arm64` images, generates SBOM/provenance, scans HIGH and CRITICAL vulnerabilities, and keylessly signs each accepted immutable digest.

Published image names:

```text
ghcr.io/stoicsoft/servercompass-client-portal/gateway
ghcr.io/stoicsoft/servercompass-client-portal/broker
```

Do not configure Server Compass with a mutable tag. Copy the manifest digests from a successful release workflow and use `image@sha256:...` references. An image from a failed security workflow is not an accepted release.

Runtime and desktop compatibility is enforced with an integer protocol version. A runtime must fail closed when its protocol differs from the desktop's supported version.

## Security

The broker's Docker socket access is a privileged boundary. Public routes must never reach its admin API, and client input must never select a stack, project, service, container, Docker path, or command. See [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

Copyright © StoicSoft contributors.

Licensed under the [GNU Affero General Public License v3.0](LICENSE), SPDX identifier `AGPL-3.0-only`.
