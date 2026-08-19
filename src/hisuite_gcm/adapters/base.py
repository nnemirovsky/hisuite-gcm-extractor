"""Plugin interface for human-readable exports of recovered databases.

The extraction layer is lossless and version-independent. Anything that turns
an application database into something a person can read is, by definition,
tied to a schema that the application's authors are free to change. Adapters
therefore live behind this interface, declare exactly what they recognise, and
must prove recognition before they are allowed to write anything.

An adapter is any object satisfying :class:`Adapter`:

* ``name`` -- stable identifier used on the command line.
* ``summary`` -- one line describing the output.
* ``supports`` -- an honest statement of the schema it was written against.
* ``detect(connection)`` -- schema introspection returning a
  :class:`DetectionResult`. It must never claim support it cannot verify.
* ``export(connection, destination)`` -- write files into a fresh directory.

Third-party adapters are discovered through the ``hisuite_gcm.adapters``
entry-point group and are never trusted to be importable; a broken plugin is
reported, not fatal.
"""

from __future__ import annotations

import dataclasses
import pathlib
import sqlite3
from collections.abc import Iterable, Mapping
from typing import Protocol, runtime_checkable

SQLITE_MAGIC = b"SQLite format 3\x00"


@dataclasses.dataclass(frozen=True)
class DetectionResult:
    """Whether an adapter recognises a database, and why."""

    supported: bool
    reason: str

    def __bool__(self) -> bool:
        return self.supported


@dataclasses.dataclass
class ExportResult:
    """What an adapter produced."""

    files: list[pathlib.Path] = dataclasses.field(default_factory=list)
    rows: int = 0
    warnings: list[str] = dataclasses.field(default_factory=list)


@runtime_checkable
class Adapter(Protocol):
    """The contract every human-readable exporter implements."""

    name: str
    summary: str
    supports: str

    def detect(self, connection: sqlite3.Connection) -> DetectionResult: ...

    def export(
        self,
        connection: sqlite3.Connection,
        destination: pathlib.Path,
    ) -> ExportResult: ...


def is_sqlite(path: pathlib.Path) -> bool:
    """Return whether a file starts with the SQLite 3 magic header."""

    try:
        with path.open("rb") as handle:
            return handle.read(len(SQLITE_MAGIC)) == SQLITE_MAGIC
    except OSError:
        return False


def open_readonly(path: pathlib.Path) -> sqlite3.Connection:
    """Open a database read-only, refusing anything that is not SQLite.

    Recovered databases are evidence: nothing here may modify one. SQLite is
    asked for a read-only connection, so an accidental write fails loudly
    instead of altering the file.
    """

    path = path.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"no such database: {path}")
    if not is_sqlite(path):
        raise ValueError(
            f"{path} is not a SQLite database; the extraction layer keeps payloads in "
            "their original form, so check 'hisuite-gcm inspect' output for its type"
        )
    uri = f"file:{path.as_uri().removeprefix('file:')}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as error:
        raise ValueError(
            f"could not open {path} read-only: {error}. If a '-wal' or '-journal' file "
            "sits beside it, copy all of them to a writable directory and retry."
        ) from error
    connection.row_factory = sqlite3.Row
    connection.text_factory = bytes
    return connection


def quote_identifier(name: str) -> str:
    """Quote a table or column name for safe interpolation into SQL."""

    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def table_names(connection: sqlite3.Connection) -> list[str]:
    """Return user table names, excluding SQLite's internal bookkeeping."""

    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).fetchall()
    names = [as_text(row[0]) for row in rows]
    return [name for name in names if not name.startswith("sqlite_")]


def column_names(connection: sqlite3.Connection, table: str) -> list[str]:
    """Return the column names of one table, or an empty list if it is absent."""

    try:
        rows = connection.execute(f"PRAGMA table_info({quote_identifier(table)})").fetchall()
    except sqlite3.Error:
        return []
    return [as_text(row[1]) for row in rows]


def as_text(value: object) -> str:
    """Decode a SQLite value to text, tolerating the mixed encodings found in
    recovered databases. Connections from :func:`open_readonly` return text as
    bytes so a damaged row cannot abort an export."""

    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def requires_schema(
    connection: sqlite3.Connection,
    expected: Mapping[str, Iterable[str]],
    *,
    label: str,
) -> DetectionResult:
    """Detect a schema by required tables and columns.

    This is the building block adapters should use instead of guessing from a
    file name: it names the first thing that is missing, so an unsupported
    version produces a precise explanation rather than a wrong export.
    """

    present = set(table_names(connection))
    for table, columns in expected.items():
        if table not in present:
            return DetectionResult(False, f"not {label}: table {table!r} is missing")
        available = set(column_names(connection, table))
        missing = sorted(set(columns) - available)
        if missing:
            return DetectionResult(
                False,
                f"not {label}: table {table!r} has no column(s) {', '.join(missing)}",
            )
    return DetectionResult(True, f"matches {label}")
