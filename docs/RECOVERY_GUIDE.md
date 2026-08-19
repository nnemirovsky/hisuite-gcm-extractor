# Recovery guide

This guide separates the three sources that are often conflated as "the phone
backup". For the broadest authorized preservation, keep all three:

1. The untouched HiSuite backup, as an archival source.
2. Authenticated databases and private application files recovered by this
   tool.
3. Shared storage copied from the unlocked phone: photos, videos, downloads,
   documents, and app media.

## 1. Preserve the source

Copy the complete HiSuite backup directory to reliable storage. Do not rename
or edit anything inside the only copy. Make sure the destination disk has room
for both the encrypted and the decrypted data — roughly twice the backup size.

Then look inside. This needs no password:

```sh
hisuite-gcm inspect BACKUP
```

If you pass a parent directory, the backup below it is found automatically, up
to three levels deep. If several backups are found, the command lists them and
asks you to choose one.

## 2. Recover authenticated payloads

```sh
hisuite-gcm extract BACKUP DESTINATION
```

The destination must be new, which prevents accidental mixing with a previous
attempt, and must sit outside the backup, so the original is never modified.
By default decrypted archives are kept *and* expanded. Use `--no-expand` to
keep only the archives, or `--no-keep-tars` to delete each archive once it has
been expanded when disk space is tight.

Before decrypting anything, the tool authenticates the smallest payloads from
up to three modules. If none of them authenticate, it stops immediately and
explains that the password looks wrong, instead of grinding through the whole
backup first. A single damaged file cannot trigger that stop.

Exit codes:

- `0`: every discovered payload recovered successfully.
- `1`: the command ran, but one or more payloads failed.
- `2`: it could not run — invalid input, missing device, unsafe destination, or
  another operational error.
- `130`: interrupted with Ctrl-C.

An authentication failure means a wrong backup password, a mismatched
`info.xml`, a damaged file, or an unsupported format. It never means "try a
different cipher": unauthenticated output from another cipher mode is not
recovered data, however plausible it looks.

## 3. Copy shared storage

On an unlocked and authorized phone:

1. Install Google's Android Platform Tools so `adb` is available.
2. Enable Developer options and USB debugging.
3. Connect by USB, unlock the phone, and accept its debugging prompt.
4. Confirm `adb devices` reports `device`, not `unauthorized`.
5. Run `hisuite-gcm copy-shared DESTINATION`.

If more than one device is attached, pass `--serial SERIAL`. The command issues
only `get-state` and `pull`; it does not install, delete, or modify anything on
the phone. A large copy can legitimately run for hours.

Some Android versions block ADB access to `Android/data` and private app
storage. That is expected. Media in `DCIM`, `Pictures`, `Movies`, `Download`,
and `Android/media` is normally the most important part of this copy, and
HiSuite app-data recovery complements it.

## 3b. Export contacts from the phone

Contacts are stored in a database, not in shared storage, and the database
schema differs between Android versions. Rather than interpreting it, ask
Android to export the contacts itself, in the vCard format every address book
understands:

```sh
hisuite-gcm export-contacts ./contacts.vcf
```

The tool first asks the contacts provider for opaque lookup keys — no names or
numbers — then asks Android to serialise those records. Contacts are requested
in batches; if a batch fails, each contact in it is retried individually, so a
single unreadable record costs one contact rather than the whole export. The
count of exported and skipped contacts is printed, and the exit code is `1` if
anything was skipped.

The resulting `.vcf` is plain text containing real personal data. Store it
where you would store the phone itself.

## 4. Understand the result

System databases may include contacts, SMS, calls, or calendar records.
Application data may include live SQLite databases, preferences, encryption
keys, caches, and attachments. Treat all of it as sensitive.

Schemas change by Android version, EMUI version, app, and app version. Open
SQLite databases read-only, and work on a copy before experimenting:

```sh
hisuite-gcm adapters DATABASE          # what can be exported, and why
hisuite-gcm export   DATABASE ./readable
```

The built-in adapter transcribes tables to CSV without interpreting them.
Anything that claims to understand a specific app's schema must prove it first;
see [ADAPTERS.md](ADAPTERS.md). WhatsApp recovery, as one example, may involve
a live `msgstore.db`, a separate contacts database, media under shared storage,
and encrypted local backup files — a successful query on one version proves
nothing about another.

## 5. Verify and duplicate

```sh
hisuite-gcm manifest ./recovered
hisuite-gcm manifest ./shared_storage
```

Keep at least two copies on independent storage, and verify representative
photos, videos, documents, and databases before resetting or reusing the phone.
Later, on any machine:

```sh
cd recovered && sha256sum -c MANIFEST-SHA256.txt
```
