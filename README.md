# hisuite-gcm

[![CI](https://github.com/nnemirovsky/hisuite-gcm-extractor/actions/workflows/ci.yml/badge.svg)](https://github.com/nnemirovsky/hisuite-gcm-extractor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

Command-line tool that decrypts recent Huawei HiSuite/KoBackup backups. Recent
backups use authenticated AES-GCM for their file payloads. This tool
authenticates every payload before writing it, decrypts module databases and
application-data archives, and can copy shared storage and contacts from a
connected phone.

You need the backup directory and the password that was set when the backup was
created. The tool cannot bypass a device lock, break Android encryption, recover
a forgotten password, or reach cloud accounts. It is not affiliated with Huawei.

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Output layout](#output-layout)
- [Exit codes](#exit-codes)
- [Troubleshooting](#troubleshooting)
- [How it works](#how-it-works)
- [Compatibility](#compatibility)
- [Security and privacy](#security-and-privacy)
- [Contributing](#contributing)
- [License](#license)

## Features

- Authenticated AES-GCM decryption of module databases and application-data
  archives. Plaintext is written only after its GCM tag verifies.
- No fallback to unauthenticated AES-CTR, so a format mismatch fails loudly
  instead of producing corrupted output.
- Conservative TAR expansion. Links, devices, absolute paths, and traversal
  paths are never written, on POSIX or Windows.
- Pre-flight password check, so a wrong password stops in seconds instead of
  after processing the whole backup.
- Read-only ADB helpers for shared storage and for contacts, exported through
  Android's own vCard provider.
- SHA-256 manifests in `sha256sum` format for later verification.
- Plugin interface for human-readable database exports, with a schema-agnostic
  CSV adapter included.

## Installation

### Prerequisites

**Python 3.10 or newer.** Check what you have:

```sh
python3 --version
```

If that command is missing or reports an older version:

| Platform | Install |
| --- | --- |
| macOS | `brew install python` or the installer from [python.org](https://www.python.org/downloads/) |
| Debian, Ubuntu | `sudo apt install python3 python3-venv python3-pip` |
| Fedora, RHEL | `sudo dnf install python3` |
| Arch | `sudo pacman -S python` |
| Windows | The installer from [python.org](https://www.python.org/downloads/windows/), with "Add python.exe to PATH" ticked, or `winget install Python.Python.3.12` |

**Git**, to clone the repository. Alternatively download the ZIP from the
repository page and skip the `git clone` step.

**Disk space** of roughly twice the size of the backup, since both the
encrypted originals and the decrypted output have to fit.

**PyCryptodome** is the only runtime dependency and is installed automatically
by `pip`. Nothing else is needed for `inspect`, `extract`, `manifest`,
`adapters`, or `export`.

### Prerequisites for the phone commands

`copy-shared` and `export-contacts` talk to a connected phone and additionally
need **Android Platform Tools**, which provide `adb`:

| Platform | Install |
| --- | --- |
| macOS | `brew install --cask android-platform-tools` |
| Debian, Ubuntu | `sudo apt install android-tools-adb` |
| Fedora, RHEL | `sudo dnf install android-tools` |
| Arch | `sudo pacman -S android-tools` |
| Windows | `winget install Google.PlatformTools`, or the ZIP from [developer.android.com](https://developer.android.com/tools/releases/platform-tools) |

Confirm it is on `PATH`:

```sh
adb version
```

If `adb` is installed somewhere else, pass its full path with `--adb` instead of
adding it to `PATH`.

On the phone itself, enable Developer options, turn on USB debugging, connect by
USB, unlock the screen, and accept the debugging prompt. Then check the computer
is authorized:

```sh
adb devices     # the device must be listed as "device", not "unauthorized"
```

### From source

```sh
git clone https://github.com/nnemirovsky/hisuite-gcm-extractor.git
cd hisuite-gcm-extractor
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/hisuite-gcm --help
```

On Windows use `.venv\Scripts\pip` and `.venv\Scripts\hisuite-gcm`.

To put the command on `PATH` for the current shell, activate the environment
first with `source .venv/bin/activate` (`.venv\Scripts\activate` on Windows),
after which plain `hisuite-gcm` works.

### With pipx

[pipx](https://pipx.pypa.io/) installs the command globally without touching
your system Python packages:

```sh
pipx install git+https://github.com/nnemirovsky/hisuite-gcm-extractor.git
hisuite-gcm --version
```

### For development

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/python tools/privacy_scan.py
```

## Quick start

Work on a copy of the backup. Every command reads the backup directory and
writes elsewhere, and `extract` refuses a destination inside the backup.

```sh
# 1. List what can be recovered. No password needed.
hisuite-gcm inspect "/path/to/HUAWEI Phone_2026-01-01"

# 2. Decrypt into a new directory. The password is asked for at a hidden prompt.
hisuite-gcm extract "/path/to/HUAWEI Phone_2026-01-01" ./recovered

# 3. Record checksums for later verification.
hisuite-gcm manifest ./recovered
```

## Commands

### `inspect`

Lists the encrypted payloads a backup contains. Requires no password.

```sh
hisuite-gcm inspect BACKUP [--json]
```

```text
Backup: /path/to/HUAWEI Phone_2026-01-01
Modules with encryption metadata: 12
Recoverable payloads found: 14
  database  com.example.messages: com.example.messages.db (2411520 bytes)
  app-data  com.example.notes: com.example.notes_appDataTar/data.tar (18104320 bytes)
```

`BACKUP` may be the backup directory, a parent directory containing it (searched
up to three levels), or the `info.xml` file itself.

### `extract`

Authenticates and decrypts every discovered payload.

```sh
hisuite-gcm extract BACKUP DESTINATION [--no-expand] [--no-keep-tars] [--password-stdin]
```

| Option | Effect |
| --- | --- |
| `--no-expand` | Keep decrypted TAR archives without expanding them |
| `--no-keep-tars` | Delete each archive once expanded, to save disk space |
| `--password-stdin` | Read one password line from standard input |

The password is read from a hidden prompt by default. It is never accepted as a
command-line argument, printed, or written to disk. `--password-stdin` is
intended for automation. Shell history and process listings can expose secrets,
so prefer the prompt for interactive use.

`DESTINATION` must not already exist, which prevents mixing two attempts.

### `copy-shared`

Copies shared storage from a connected phone. Runs `adb pull /sdcard/.` and
nothing else. Nothing is installed, deleted, or written on the device.

```sh
hisuite-gcm copy-shared DESTINATION [--adb PATH] [--serial SERIAL]
```

Needs the phone prerequisites above. Pass `--serial` when more than one device
is attached. HiSuite backups usually do not contain the photo library, so this
is a separate source worth keeping.

### `export-contacts`

Exports live contacts through Android's own vCard provider.

```sh
hisuite-gcm export-contacts DESTINATION.vcf [--adb PATH] [--serial SERIAL] [--batch-size N]
```

The provider is first asked for opaque record keys, with no names or numbers
requested, then asked to serialize those records. Contacts are fetched in
batches with a per-contact retry, so one unreadable record costs one contact
rather than the whole export. The file is written only after every contact is
accounted for.

### `manifest`

Writes a SHA-256 manifest of a directory tree.

```sh
hisuite-gcm manifest ROOT [--output NAME]
```

The output matches the `sha256sum` format, so any machine can verify it later:

```sh
cd recovered && sha256sum -c MANIFEST-SHA256.txt   # shasum -a 256 -c on macOS
```

### `adapters` and `export`

Recovered databases are ordinary SQLite files, kept exactly as they were.
Optional adapters turn one into something readable.

```sh
hisuite-gcm adapters [DATABASE] [--json]
hisuite-gcm export DATABASE DESTINATION [--adapter NAME]
```

The built-in `sqlite-tables` adapter writes one CSV per table plus the
database's own `schema.sql`, and makes no claim about what the columns mean.
Adapters that understand a specific application schema plug in through a
documented interface and must prove they recognize the schema before writing
anything. See [docs/ADAPTERS.md](docs/ADAPTERS.md).

## Output layout

```text
recovered/
|-- databases/          decrypted module databases, unchanged
|-- decrypted_tars/     authenticated application-data archives
`-- app_data/           those archives, expanded into ordinary directories
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The command finished and everything it touched succeeded |
| `1` | The command ran, but something it tried to recover failed |
| `2` | The command could not run: bad input, missing device, unsafe paths |
| `130` | Interrupted with Ctrl-C |

## Troubleshooting

| Message | Cause | Fix |
| --- | --- | --- |
| `The password did not authenticate the backup` | Wrong password, or `info.xml` and the payloads come from different backups | Check capitals and keyboard layout. Confirm the whole backup directory was copied |
| `authentication failed: <file>` | That single file is damaged or was altered | Everything else still recovers. Re-copy the backup from its original disk |
| `multiple backups found below <path>` | The path holds several backups | Pass one backup directory |
| `no info.xml found in <path>` | Not a HiSuite backup directory | Locate the directory containing `info.xml` |
| `destination already exists` | The output path is not new | Choose a new path |
| `the destination must be outside the backup directory` | Output would be written into the source | Choose a path outside the backup |
| `ADB executable not found` | Platform Tools missing or not on `PATH` | Install them, or pass `--adb /full/path/to/adb` |
| `the phone is in state 'unauthorized'` | The computer is not authorized on the device | Unlock the phone and accept the USB debugging prompt |
| `no exportable contacts` | Contacts live in an account the provider does not expose | Check which account holds them in the phone's Contacts app |

## How it works

`info.xml` lists backed-up modules. Each carries an `encMsgV3` value of 96
hexadecimal characters: a 32-byte PBKDF2 salt followed by a 16-byte AES-GCM
nonce. The key is PBKDF2-HMAC-SHA256 over the UTF-8 password with 5,000
iterations and a 32-byte output. Each payload is stored as `ciphertext` followed
by a 16-byte GCM tag.

Decryption streams everything except the final 16 bytes into a temporary file in
the destination directory, verifies the tag, calls `fsync`, and only then
renames the file into place. A wrong password, an altered file, or mismatched
metadata fails at the verification step, so unauthenticated plaintext never
appears at the final path.

A module's key is applied only to files the backup attributes to that module:
`<module>.db` and `<module>_appDataTar/**/*.tar`. Full details are in
[docs/FORMAT.md](docs/FORMAT.md), and the reasoning behind those matching rules
is in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Compatibility

This alpha targets the format observed in recent Security V3 backups. The
initial verified recovery was from a Huawei Pura 70 (model ADY-LX9), and the
code contains no model-specific branches, so other devices using the same format
should work.

Older backups use an unauthenticated AES-CTR variant, which this tool does not
decrypt and never falls back to. AES-CTR applied to a GCM payload produces
plausible-looking corrupted output with nothing to signal the error, which is
the failure mode this project is built to avoid.

Read [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) before assuming support for
another device or HiSuite version, and see
[docs/RECOVERY_GUIDE.md](docs/RECOVERY_GUIDE.md) for the full procedure.

## Security and privacy

- Plaintext is published only after its AES-GCM tag verifies.
- TAR expansion refuses traversal paths and never creates links or devices.
- Passwords are never accepted as command-line arguments, logged, or stored.
- Symlinks are never followed when discovering payloads or hashing a tree.
- ADB is executed as an argument array without a shell, using read-only verbs.
- Recovered databases and media are sensitive personal data. Treat the output
  directory the way you would treat the device it came from.
- Never attach a real backup, `info.xml`, database, device identifier, or
  password to an issue. [SECURITY.md](SECURITY.md) explains what to send
  instead, and how to report a vulnerability privately.

## Contributing

Bug reports, format variants, and tested adapters are welcome. Unclear error
messages count as bugs. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup, the synthetic-fixtures rule, and the provenance rules this
project follows.

## Acknowledgments

The MIT-licensed
[RealityNet/kobackupdec](https://github.com/RealityNet/kobackupdec) documented
Huawei Security V3 metadata and the older AES-CTR variant. This implementation
contains no Huawei application binaries, decompiled source, real backups, or
code copied from unlicensed repositories.

The project exists for interoperability and authorized data recovery. Laws vary
by jurisdiction, and users are responsible for ensuring their use is lawful.
Huawei, HiSuite, Android, and WhatsApp are trademarks of their respective
owners.

## License

MIT. See [LICENSE](LICENSE).
