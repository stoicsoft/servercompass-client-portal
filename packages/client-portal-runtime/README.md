# Server Compass client portal runtime

The runtime is split into an unprivileged public gateway and a private broker. Only the broker receives the Docker socket; its fixed API allowlist and dual-label scope checks are the authorization boundary. The broker collects metrics in the background and serves cached snapshots. The browser exchanges a capability from the URL fragment for a `__Host-` HttpOnly, Secure, SameSite session; fragments are removed before any request.

Production releases build both images for `linux/amd64` and `linux/arm64`, pin immutable digests in desktop runtime configuration, and must pass this repository's tests and security scan. The desktop feature remains disabled unless both image references are configured.
