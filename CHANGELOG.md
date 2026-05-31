# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

- fix: guard `JSON.parse` in dest_domains and force_routing
- style: explicit `return` on terminal deny path in `dest_domains`
- test: refactored against test-fixtures 1.7.0

### [1.0.2] - 2026-05-15

- feat: allow comments in relay_acl_allow
- deps(all): bump versions
- test: runner is now node:test
- test: fix for testing registered hooks
- test: remove done callbacks in async tests #3

### [1.0.1] - 2025-01-26

- style: move prettier config into package.json

### [1.0.0] - 2025-01-09

- imported from haraka/Haraka

[1.0.0]: https://github.com/haraka/haraka-plugin-relay/releases/tag/v1.0.0
[1.0.1]: https://github.com/haraka/haraka-plugin-relay/releases/tag/v1.0.1
[1.0.2]: https://github.com/haraka/haraka-plugin-relay/releases/tag/v1.0.2
