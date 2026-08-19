# Contributing

Contributions that improve format compatibility, diagnostics, tests, and safe
human-readable exports are welcome. So are plain bug reports — including "the
error message did not tell me what to do next", which is a real bug in a tool
people reach for on a bad day.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/python tools/privacy_scan.py
```

All five must pass. CI runs them on Linux, macOS, and Windows against Python
3.10 through 3.13.

## Testing rules

Every format change needs a synthetic fixture and a failure-mode test. Tests
must demonstrate that wrong passwords and corrupted tags never publish
plaintext. Archive changes need traversal and link-safety coverage. Shared
builders live in `tests/conftest.py`; use them rather than inventing a fourth
way to write an `info.xml`.

Never weaken these two properties to make a test pass:

1. AES-GCM authentication gates every byte of published plaintext.
2. Nothing is ever written outside the destination directory.

## Privacy and provenance rules

Do not commit or attach:

- Real backups, databases, photos, contacts, messages, identifiers, or
  metadata.
- Passwords, private server configurations, device serials, or absolute user
  paths.
- Huawei APKs, binaries, resources, or decompiled/disassembled source.
- Code copied from repositories that do not grant a license.

`tools/privacy_scan.py` checks tracked files for these patterns mechanically.
When a line must contain something that looks like a secret — a test fixture
for the scanner itself, for instance — mark that line with
`# privacy-scan: allow` so a reviewer sees the claim and the evidence together.
Do not add blanket file exclusions.

State the provenance and license of any adapted code, and preserve upstream
notices where required. Reverse-engineering notes should describe observable
behavior needed for interoperability, not reproduce proprietary implementation
text.

## Commit and pull-request conventions

Use scoped [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): description`, lowercase description. Pull request titles use the
same format. Keep commits focused; a format change, its fixture, and its
documentation belong together, while unrelated cleanups do not.

## Human-readable adapters

Readable exports are valuable, but application schemas change frequently. Read
[docs/ADAPTERS.md](docs/ADAPTERS.md) first. In short, a new adapter must:

- Detect supported schemas through table and column introspection.
- Operate read-only on databases.
- State its app and schema compatibility explicitly, without claiming
  universality.
- Escape HTML and spreadsheet output safely.
- Preserve timestamps, sender/direction meaning, and media references, or warn
  when it cannot.
- Degrade on its own without blocking raw authenticated extraction.
- Use entirely synthetic databases in its tests.

## Being a good neighbour

This project is used by people recovering data after a death, a theft, or a
failed device. Assume good faith, keep review comments about the code, and
remember that a confused bug report is usually a documentation problem. Report
conduct concerns to the maintainers through the contact channel named in
[SECURITY.md](SECURITY.md).
