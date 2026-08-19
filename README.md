# hisuite-gcm

**Recover your own Huawei phone backup when HiSuite will not restore it.**

[![CI](https://github.com/nnemirovsky/hisuite-gcm-extractor/actions/workflows/ci.yml/badge.svg)](https://github.com/nnemirovsky/hisuite-gcm-extractor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

`hisuite-gcm` opens recent Huawei HiSuite/KoBackup backups whose files are
encrypted with authenticated AES-GCM, and writes their contents to a folder you
choose. You need the backup folder and the password that was typed when the
backup was made.

It is a command-line tool. Three commands do the whole job:

```sh
hisuite-gcm inspect  "/path/to/HUAWEI Phone_2026-01-01"          # what is in there
hisuite-gcm extract  "/path/to/HUAWEI Phone_2026-01-01" ./recovered
hisuite-gcm manifest ./recovered                                  # checksums, for later
```

---

## If you are here after a loss

Take your time. Nothing below is urgent, and none of it can damage the backup:
every command reads the original folder and writes somewhere else.

Two things are worth doing before anything else:

1. **Copy the backup folder to a second disk.** Work from a copy. If a step
   goes wrong, you still have the original.
2. **Do not factory-reset or reuse the phone yet.** A phone that still turns on
   usually holds photos and videos that were never part of the HiSuite backup.
   [The recovery guide](docs/RECOVERY_GUIDE.md) covers copying those too.

If the password turns out to be wrong, the tool says so plainly and stops. It
cannot guess or recover a forgotten password, and neither can anyone else — the
encryption is doing exactly what it was designed to do.

## What it recovers

| From the backup | What you get |
| --- | --- |
| Encrypted module databases | The original `.db` files (contacts, messages, calls, calendar, and others, depending on what was backed up) |
| Encrypted application-data archives | The app's own files, safely expanded into folders |
| Shared storage on a connected phone | Photos, videos, downloads, documents, app media |
| Live contacts on a connected phone | A standard `.vcf` any address book can import |
| Anything you recovered | A SHA-256 manifest so you can verify the copy years from now |

It does **not** unlock a phone, break Android encryption, recover a forgotten
password, or reach cloud accounts. It is not affiliated with Huawei.

## Install

Python 3.10 or newer.

```sh
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/hisuite-gcm --help
```

On Windows, use `.venv\Scripts\pip` and `.venv\Scripts\hisuite-gcm`.

## Step 1 — look inside, no password needed

```sh
hisuite-gcm inspect "/path/to/HUAWEI Phone_2026-01-01"
```

```text
Backup: /path/to/HUAWEI Phone_2026-01-01
Modules with encryption metadata: 12
Recoverable payloads found: 14
  database  com.example.messages: com.example.messages.db (2411520 bytes)
  app-data  com.example.notes: com.example.notes_appDataTar/data.tar (18104320 bytes)
  ...
```

If you point it at the folder that *contains* the backup, it finds the backup
itself. Add `--json` if you want the same list for a script.

## Step 2 — decrypt

```sh
hisuite-gcm extract "/path/to/HUAWEI Phone_2026-01-01" ./recovered
```

The password is asked for at a hidden prompt. It is never taken as a
command-line argument, printed, or written anywhere. Make sure the destination
disk has room for roughly twice the size of the backup.

You get:

```text
recovered/
├── databases/       # decrypted module databases, exactly as they were
├── decrypted_tars/  # the authenticated app-data archives
└── app_data/        # those archives, expanded into ordinary folders
```

Useful options:

| Option | Use it when |
| --- | --- |
| `--no-expand` | You only want the archives, not their expanded contents |
| `--no-keep-tars` | Disk space is tight: each archive is deleted once expanded |
| `--password-stdin` | You are scripting this, and understand shell history |

## Step 3 — record checksums

```sh
hisuite-gcm manifest ./recovered
```

This writes `MANIFEST-SHA256.txt` in the standard `sha256sum` format, so any
machine can verify the copy later:

```sh
cd recovered && sha256sum -c MANIFEST-SHA256.txt   # shasum -a 256 -c on macOS
```

## Photos and videos from the phone itself

HiSuite backups usually do **not** contain your photo library. If the phone
still works, copy its shared storage directly. Install Google's Android
Platform Tools, enable USB debugging on the phone, connect it, unlock it, and
accept the prompt that appears:

```sh
hisuite-gcm copy-shared ./shared_storage
hisuite-gcm manifest ./shared_storage
```

This runs `adb pull /sdcard/.` and nothing else. It never writes to the phone.

Contacts usually live in a database rather than in shared storage. If the phone
still works, Android can hand them over in the standard vCard format, which
every phone and address book can import:

```sh
hisuite-gcm export-contacts ./contacts.vcf
```

The command asks the contacts provider for opaque record keys, then asks
Android itself to serialise each record. If a contact cannot be read, the rest
are still saved and the shortfall is reported.

## Reading the databases

Recovered databases are ordinary SQLite files. The tool keeps them exactly as
they were rather than reshaping them, because every app's schema differs and
changes between versions. To get a first readable view:

```sh
hisuite-gcm adapters ./recovered/databases/com.example.messages.db
hisuite-gcm export   ./recovered/databases/com.example.messages.db ./readable
```

The built-in `sqlite-tables` adapter writes one CSV per table plus the
database's own `schema.sql`. It makes no claim about what the columns mean —
that is deliberate. Adapters that *do* understand a specific app schema plug in
through a documented interface; see [docs/ADAPTERS.md](docs/ADAPTERS.md).

## When something goes wrong

Every failure is meant to be readable. The common ones:

| Message | What it means | What to do |
| --- | --- | --- |
| `The password did not authenticate the backup` | The password is wrong, or `info.xml` and the encrypted files are from different backups | Recheck capitals and layout; make sure the whole backup folder was copied |
| `authentication failed: <file>` | That one file is damaged or was altered | The rest still recovers; re-copy the backup from its original disk |
| `multiple backups found below <path>` | You pointed at a folder holding several backups | Pass one backup folder |
| `no info.xml found in <path>` | That folder is not a HiSuite backup | Look for the folder containing `info.xml` |
| `destination already exists` | The output folder is not new | Choose a new folder, so a previous attempt is never mixed in |
| `ADB executable not found` | Platform Tools are not installed or not on `PATH` | Install them, or pass `--adb /full/path/to/adb` |
| `no exportable contacts` | The contacts live in an account the provider does not expose | Check the phone's Contacts app for the account they are stored in |

Exit codes: `0` success, `1` ran but something failed, `2` could not run,
`130` interrupted.

## Compatibility

This alpha implements the format seen in recent Security V3 backups: each
payload is `ciphertext || 16-byte GCM tag`, and `encMsgV3` holds a 32-byte
PBKDF2 salt followed by a 16-byte GCM nonce.

Older backups use an unauthenticated AES-CTR variant. **This tool never falls
back to it.** Applying CTR to a newer backup produces plausible-looking garbage
with nothing to warn you, which is precisely the failure mode this project
exists to avoid. See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) before
assuming support for another device or HiSuite version, and
[docs/FORMAT.md](docs/FORMAT.md) for the format itself.

## Safety and privacy

- Work on copies. Never point the tool at your only backup as its destination —
  it refuses, but the habit matters more.
- Recovered databases and media are sensitive personal data. Treat the output
  folder the way you would treat the phone.
- Never attach a real backup, `info.xml`, database, device identifier, or
  password to an issue. [SECURITY.md](SECURITY.md) explains what to send
  instead.
- Plaintext is written only after its AES-GCM tag verifies. TAR extraction
  refuses traversal paths and never creates links or devices.

## Contributing

Bug reports, format variants, and tested adapters are all welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) — it covers the development setup, the
synthetic-fixtures rule, and the provenance rules this project holds itself to.

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy
```

## Acknowledgments and legal note

The earlier MIT-licensed
[RealityNet/kobackupdec](https://github.com/RealityNet/kobackupdec) documented
Huawei Security V3 metadata and the older AES-CTR variant. This implementation
contains no Huawei application binaries, decompiled source, real backups, or
code copied from unlicensed repositories.

The project exists for interoperability and authorized data recovery. Laws vary
by jurisdiction; you are responsible for ensuring your use is lawful. Huawei,
HiSuite, Android, and WhatsApp are trademarks of their respective owners.

## License

MIT. See [LICENSE](LICENSE).
