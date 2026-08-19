# Security policy

## Reporting a vulnerability

Report privately through GitHub, not in a public issue:

**[Open a private security advisory](https://github.com/nnemirovsky/hisuite-gcm-extractor/security/advisories/new)**

That form is visible only to the maintainers ([@nnemirovsky](https://github.com/nnemirovsky))
until an advisory is published, so nothing sensitive is exposed while a fix is
being prepared. Expect an acknowledgement within a week.

If the form is unavailable, open a normal issue that says only "I would like a
private channel for a security report" — with no details — and a private
advisory will be opened for you.

Never attach a real backup, `info.xml`, database, recovered file, device
identifier, or password to a report. Describe the shape of the problem instead;
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) lists what is useful and safe to
send.

### Scope

In scope: anything that lets unauthenticated data reach a recovered output,
writes outside the destination directory, exposes a password, or crashes the
tool in a way that hides a failure.

Out of scope: the fact that recovered data is unencrypted on disk (that is the
purpose of the tool), and anything requiring an attacker who already controls
the machine.

## Data-handling guarantees

- Backup passwords are read from a hidden prompt and are never accepted as
  command-line arguments, logged, or written to disk. `--password-stdin` exists
  for controlled automation only.
- Plaintext is written to a temporary file in the destination directory, given
  owner-only permissions by the operating system, `fsync`ed, and renamed into
  place **only** after its AES-GCM tag verifies. A failed run removes it.
- The tool never falls back from authenticated AES-GCM to an unauthenticated
  cipher.
- The destination for `extract` and `copy-shared` must not already exist, and
  the destination may not sit inside the backup directory.
- TAR expansion never creates links, devices, or FIFOs, never writes outside
  the destination, and refuses names that would escape on POSIX or Windows.
  Refused entries are reported, not silently dropped.
- `info.xml` parsing refuses documents with a DTD and bounds the file size.
- ADB is executed as an argument array, without a shell, and only with the
  read-only verbs the tool needs: `get-state`, `pull`, and — for
  `export-contacts` — a `content query` for opaque contact keys followed by
  `content read` of Android's own vCard endpoint. Nothing is installed,
  deleted, or written on the phone.
- `export-contacts` writes a plain-text `.vcf` containing real names and
  numbers. It is created with owner-only permissions and published only
  after every requested contact is accounted for; contacts the provider
  refuses are counted and reported rather than silently missing.
- Symlinks are never followed when discovering payloads or hashing a tree.

## Threat model and limits

The tool assumes the local machine, the Python environment, the PyCryptodome
package, and the original backup directory are trusted. It does not protect
plaintext after recovery, erase temporary filesystem blocks, defend against a
compromised operating system, or validate the semantics of recovered
application databases.

Recovered data is as sensitive as the phone it came from. Treat the output
directory accordingly, and prefer an encrypted disk.

Passing secrets through shell history, environment variables, process
substitution, CI logs, or pipes can expose them; the interactive prompt is
safer for normal use.

Third-party export adapters run in the same process as the tool. Install only
adapters you trust; a malicious plugin is ordinary untrusted code.

Use this software only on data you own or are explicitly authorized to handle.
