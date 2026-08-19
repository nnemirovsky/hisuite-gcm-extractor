# Project instructions for Claude Code

This is a clean public interoperability project. Work only inside this
repository. Never inspect sibling directories: they may contain private family
backups, recovered messages/media, passwords, device identifiers, or research
artifacts.

Priorities, in order:

1. Never weaken AES-GCM authentication or TAR path safety.
2. Never add real backup fixtures, proprietary Huawei artifacts, decompiled
   code, binaries, or code of unclear license.
3. Keep the extraction layer lossless and independent from version-sensitive
   presentation adapters.
4. Keep password handling off argv and logs.
5. Require synthetic tests for every supported format/schema.

Before proposing a release, run the tests, lint, build the wheel/sdist, inspect
their file lists, scan tracked files for secrets/private paths, and replace all
`OWNER` placeholders after asking the repository owner for the GitHub account.

Read `README.md`, `docs/FORMAT.md`, `SECURITY.md`, and `CONTRIBUTING.md` before
making architectural changes.

