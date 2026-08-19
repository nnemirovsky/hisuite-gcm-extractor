# Observed Security V3 AES-GCM payload format

This document records interoperable behavior observed in authorized recent
Huawei HiSuite/KoBackup backups. It is descriptive, not an official Huawei
specification, and may be incomplete.

## Module metadata

`info.xml` contains rows for backed-up modules. Relevant rows identify a module
using `packageName`, `name`, or `appName`, and carry `encMsgV3` as 96
hexadecimal characters (48 bytes):

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 32 bytes | PBKDF2 salt |
| 32 | 16 bytes | AES-GCM nonce |

A module may appear in more than one row. Every distinct `encMsgV3` for a name
is kept in document order; recovery tries each in turn and uses only the one
whose authentication tag verifies.

The parser reads a bounded subset of the document. Files declaring a DTD are
refused outright, because entity expansion can exhaust memory, and metadata
larger than 64 MiB is refused rather than parsed.

## Key derivation

```text
password_bytes = UTF-8(password)
key = PBKDF2-HMAC-SHA256(
    password=password_bytes,
    salt=encMsgV3[0:32],
    iterations=5000,
    output_length=32,
)
```

The result is a 256-bit AES key. The remaining 16 bytes of `encMsgV3` are the
GCM nonce. A 16-byte nonce is not the 12-byte GCM default; it is what the
observed metadata provides, and GCM derives its counter block accordingly.

## File layout

Observed encrypted database and app-data TAR payloads have this layout:

```text
ciphertext (same length as plaintext) || GCM authentication tag (16 bytes)
```

No additional authenticated data (AAD) was observed. A module's metadata is
used for that module's database and app-data TAR payloads.

## How this implementation reads it

1. Stream everything except the final 16 bytes through AES-GCM, writing
   plaintext to a temporary file in the destination directory.
2. Read the final 16 bytes and verify the tag.
3. `fsync` the temporary file, then rename it over the destination.

A wrong password, an altered file, or mismatched metadata fails at step 2, so
no unauthenticated plaintext ever appears at the final path. An interrupted run
leaves at most a hidden `.part` file, never a half-written result that looks
complete.

## Earlier backups

Earlier Security V3 tooling uses AES-CTR payload processing. The shared label
does not guarantee the same file cipher. This project deliberately does not
fall back to unauthenticated CTR: CTR output is never wrong-looking, only
wrong. Supporting older backups should be an explicit future format handler
with independent tests and clearly labelled output.
