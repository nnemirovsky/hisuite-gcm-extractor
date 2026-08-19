# Human-readable adapters

Extraction and presentation are separated on purpose.

The extraction layer is lossless: it authenticates a payload and writes it out
byte for byte. It depends only on the backup format, which changes rarely.
Turning a recovered database into something a person can read depends on an
application's schema, which changes often and without notice. Mixing the two
would make the safe part as fragile as the fragile part.

Adapters therefore live behind a small interface, must prove they recognise a
schema before writing anything, and can fail without affecting extraction.

## Using an adapter

```sh
hisuite-gcm adapters                      # what is registered
hisuite-gcm adapters path/to/recovered.db # what each one says about this file
hisuite-gcm export path/to/recovered.db ./readable
hisuite-gcm export path/to/recovered.db ./readable --adapter sqlite-tables
```

Without `--adapter`, a schema-specific adapter is preferred over the generic
one. If nothing recognises the database, the command explains why per adapter
rather than guessing.

## What ships today

| Adapter | Claim | Output |
| --- | --- | --- |
| `sqlite-tables` | Any SQLite database. Column meanings are **not** interpreted. | One CSV per table, plus `schema.sql` |

That is the whole built-in list, and the honesty is the point: this project
does not ship a "contacts exporter" or a "WhatsApp exporter" it cannot back
with a tested schema. Values that would be read as formulas by a spreadsheet
are prefixed with `'`, and binary values are summarised rather than mangled —
the authenticated database keeps the real bytes.

## Writing an adapter

An adapter is any object with three attributes and two methods:

```python
import pathlib
import sqlite3

from hisuite_gcm.adapters import DetectionResult, ExportResult, requires_schema


class ExampleMessagesAdapter:
    name = "example-messages"
    summary = "messages and participants as CSV"
    supports = "Example Messenger 5.x (tables 'message', 'participant')"

    def detect(self, connection: sqlite3.Connection) -> DetectionResult:
        return requires_schema(
            connection,
            {"message": ["_id", "body", "sent_at"], "participant": ["display_name"]},
            label="the Example Messenger 5.x schema",
        )

    def export(self, connection: sqlite3.Connection, destination: pathlib.Path) -> ExportResult:
        destination.mkdir(parents=True, exist_ok=True)
        ...
        return ExportResult(files=[...], rows=..., warnings=[])
```

Register it from your own package:

```toml
[project.entry-points."hisuite_gcm.adapters"]
example-messages = "example_package.adapter:ExampleMessagesAdapter"
```

The entry point may name a class or an instance. A plugin that cannot be
imported is reported and skipped; it never blocks extraction.

## Rules an adapter must follow

- **Detect, do not assume.** Use `requires_schema` or equivalent introspection.
  A file name proves nothing. `detect` must name what is missing so an
  unsupported version produces an explanation instead of a wrong export.
- **State the version you support** in `supports`. "Any Android contacts
  database" is not a claim anyone can verify; "AOSP contacts2, schema version
  N, tables X and Y" is.
- **Read only.** Connections come from `open_readonly`. Never write, migrate,
  or `VACUUM` a recovered database.
- **Expect damage.** Recovered rows can hold invalid UTF-8 and unexpected
  types. Text arrives as `bytes`; decode with `as_text`. One bad row must not
  abort an export — put it in `ExportResult.warnings`.
- **Escape your output.** Prefix spreadsheet formula characters in CSV; escape
  HTML if you emit HTML.
- **Preserve meaning.** Keep timestamps, direction (sent/received), and media
  references intact, or say in a warning that you could not.
- **Test synthetically.** Every adapter needs a database built inside the test
  suite: one that matches, and at least one that does not. Never a real one.

`tests/test_adapters.py` contains a complete worked example
(`SyntheticMessagesAdapter`) that exists only to prove the interface holds.
