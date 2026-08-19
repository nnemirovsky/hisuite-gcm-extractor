# Compatibility and testing

The project is alpha software. Compatibility is determined by backup format,
not by phone model.

## Expected compatible shape

- A HiSuite/KoBackup directory containing `info.xml`.
- Module rows carrying a 96-hexadecimal-character `encMsgV3` value.
- Encrypted module databases named `<module>.db`, and/or TARs below
  `<module>_appDataTar/`.
- AES-GCM payloads with a 16-byte tag appended to the ciphertext.

The initial real-world recovery was from a Huawei Pura 70 (model ADY-LX9), but
the code contains no model-specific branches. Other devices should work when
they use the same format.

## How payloads are matched to modules

Each module in `info.xml` carries its own key material. The rules that decide
which files that material may be applied to are deliberately narrow:

| Rule | Matched |
| --- | --- |
| `<backup>/<module>.db` | The module's encrypted database |
| `<backup>/<module>_appDataTar/**/*.tar` | The module's encrypted app-data archives, at any depth |

Nothing else is ever decrypted with that module's key.

### Decision: how tolerant these rules should be

Reviewed for the 0.1.0 release. One rule was loosened and the rest were
deliberately left strict.

**Loosened.** App-data archives are now found at any depth below
`<module>_appDataTar/`, not only in its top level. The directory is already
attributed to exactly one module by the backup itself, so recursing inside it
cannot reach an unrelated file, and a layout that nests archives one level
deeper would otherwise be silently skipped. Symlinked directories and files are
not followed, and any path that resolves outside the module directory is
dropped.

**Left strict, with reasons.**

- *Matching `*.tar` or `*.db` anywhere in the backup.* A file's location is the
  only evidence tying it to a module. Losing that link means guessing which key
  to use.
- *Trying every module key against every unmatched file.* AES-GCM fails closed,
  so this is not a decryption risk — but it is a usability and honesty risk. On
  a large backup it turns a bounded run into an N×M grind, and it replaces one
  precise error ("this file failed to authenticate") with a wall of expected
  failures that nobody can interpret. A recovery tool that cannot explain its
  own output is not doing its job.
- *Case-insensitive name matching.* On a case-sensitive filesystem this would
  begin matching files the backup did not name.
- *Falling back to AES-CTR for payloads that fail GCM.* Unauthenticated output
  can look plausible and be wrong. If support for older backups is added, it
  must be an explicit, separately named format handler.

**Known gap.** If a HiSuite version splits a large archive into numbered
continuation files (for example `data.tar.1`), those are not recognised today,
because no synthetic evidence of that naming exists. Report the naming pattern
— never the data — and it can be added with a fixture.

## Known boundaries

- Older AES-CTR backups are not decrypted.
- HiSuite layout and metadata variations not represented by synthetic tests may
  require parser changes.
- `copy-shared` depends on the ADB permissions the phone exposes.
- TAR archives without the `ustar` magic (very old `v7` archives) are decrypted
  and kept, but not expanded automatically.
- Human-readable database conversion is schema-specific and is not part of the
  stable extraction layer. See [ADAPTERS.md](ADAPTERS.md).

## Reporting a new variant safely

Never attach a real backup or metadata file. Instead report:

- HiSuite and phone software versions, if known.
- File and directory naming patterns with personal values replaced.
- The length and character class of relevant metadata, never its real value.
- Encrypted file size and expected plaintext type, without file contents.
- The exact command, its exit code, and the redacted error.

Contributors should build a fully synthetic fixture for each new handler.
