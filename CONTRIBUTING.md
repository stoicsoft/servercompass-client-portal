# Contributing

Thank you for helping improve Server Compass Client Portal.

1. Open an issue before making a substantial product or protocol change.
2. Keep the gateway unprivileged and the broker API fixed and stack-scoped.
3. Add tests for happy, denied, replayed, cross-scope, partial-failure, and malformed-input paths.
4. Run `npm run install:runtime && npm test` before submitting a pull request.
5. Never commit credentials, capabilities, passcodes, client data, or production image exceptions.

Protocol changes must document backward compatibility, increment the protocol version when incompatible, and coordinate with Server Compass Desktop.

By contributing, you agree that your contribution is licensed under AGPL-3.0-only.

