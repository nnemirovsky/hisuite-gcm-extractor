# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] — unreleased alpha

First public shape of the project. Everything below is new.

### Added

- `inspect`, `extract`, `copy-shared`, and `manifest` commands.
- Streaming AES-GCM decryption that publishes plaintext only after the
  authentication tag verifies, with `fsync` before the atomic rename.
- Discovery of encrypted payloads from `info.xml`, restricted to files the
  backup attributes to a named module.
- Conservative TAR expansion: no links, no devices, no traversal, no absolute
  paths, with refused entries reported instead of silently dropped.
- A pre-flight password check that samples the smallest payloads and stops
  before decrypting a whole backup with the wrong password.
- Support for a module listed more than once in `info.xml`: every distinct
  `encMsgV3` is tried, and only the one that authenticates is used.
- SHA-256 manifests in `sha256sum` format, including coreutils-style escaping.
- `export-contacts`, which exports live contacts through Android's own vCard
  provider: opaque keys are listed first, records are fetched in batches with
  a per-contact fallback, and the file is published only after every contact
  is accounted for.
- `adapters` and `export` commands, and a documented plugin interface for
  human-readable database exports, with a schema-agnostic `sqlite-tables`
  adapter.
- `tools/privacy_scan.py`, run before a release to check tracked files for
  absolute home paths, contact details, and key material.
- Synthetic test suite covering corrupted tags, truncated payloads, malicious
  module and archive names, duplicate metadata, output collisions, mocked ADB,
  and the CLI surface.

### Security

- Module names and TAR member names are validated as single path components on
  POSIX **and** Windows semantics, so a name such as `C:evil` can never escape
  the destination through a drive-relative join.
- `info.xml` documents declaring a DTD are refused, and metadata size is
  bounded, so entity expansion cannot exhaust memory.
- ADB is invoked as an argument array with a timeout on state queries; the
  password is never accepted on the command line.

[Unreleased]: https://github.com/nnemirovsky/hisuite-gcm-extractor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nnemirovsky/hisuite-gcm-extractor/releases/tag/v0.1.0
