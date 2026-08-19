"""A schema-agnostic CSV view of any recovered SQLite database.

This adapter claims no knowledge of contacts, messages, or calendars. It
transcribes whatever tables exist, which is honest for every schema and useful
as a first look before a schema-specific adapter exists.
"""

from __future__ import annotations

import csv
import pathlib
import sqlite3

from ..paths import safe_component
from .base import (
    DetectionResult,
    ExportResult,
    as_text,
    column_names,
    quote_identifier,
    table_names,
)

#: Leading characters that spreadsheets interpret as the start of a formula.
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
#: Binary columns are summarised rather than dumped; the authenticated
#: database keeps the real bytes.
BLOB_PLACEHOLDER = "[binary: {size} bytes]"


def csv_safe(value: str) -> str:
    """Neutralise spreadsheet formula injection without altering the reading."""

    if value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def cell(value: object) -> str:
    """Render one SQLite value as text suitable for a CSV cell."""

    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return csv_safe(value.decode("utf-8"))
        except UnicodeDecodeError:
            return BLOB_PLACEHOLDER.format(size=len(value))
    if isinstance(value, memoryview):
        return BLOB_PLACEHOLDER.format(size=len(value))
    return csv_safe(str(value))


class SqliteTablesAdapter:
    """Write one CSV per table, plus the database's own schema."""

    name = "sqlite-tables"
    summary = "one CSV per table, plus schema.sql; no interpretation of the data"
    supports = "any SQLite database; column meanings are not interpreted"

    def detect(self, connection: sqlite3.Connection) -> DetectionResult:
        tables = table_names(connection)
        if not tables:
            return DetectionResult(False, "the database contains no user tables")
        return DetectionResult(True, f"{len(tables)} table(s) can be transcribed to CSV")

    def export(self, connection: sqlite3.Connection, destination: pathlib.Path) -> ExportResult:
        destination.mkdir(parents=True, exist_ok=True)
        result = ExportResult()
        self._write_schema(connection, destination, result)
        used: set[str] = set()
        for table in table_names(connection):
            path = destination / _unique_csv_name(table, used)
            try:
                rows = self._write_table(connection, table, path)
            except sqlite3.Error as error:
                result.warnings.append(f"table {table!r} could not be read: {error}")
                path.unlink(missing_ok=True)
                continue
            result.files.append(path)
            result.rows += rows
        return result

    def _write_schema(
        self,
        connection: sqlite3.Connection,
        destination: pathlib.Path,
        result: ExportResult,
    ) -> None:
        rows = connection.execute(
            "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name"
        ).fetchall()
        path = destination / "schema.sql"
        text = "".join(f"{as_text(row[0]).strip()};\n" for row in rows)
        path.write_text(text, encoding="utf-8")
        result.files.append(path)

    def _write_table(
        self,
        connection: sqlite3.Connection,
        table: str,
        path: pathlib.Path,
    ) -> int:
        columns = column_names(connection, table)
        count = 0
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(columns)
            for row in connection.execute(f"SELECT * FROM {quote_identifier(table)}"):
                writer.writerow([cell(value) for value in row])
                count += 1
        return count


def _unique_csv_name(table: str, used: set[str]) -> str:
    base = safe_component(table) or "table"
    name = f"{base}.csv"
    counter = 2
    while name.lower() in used:
        name = f"{base}-{counter}.csv"
        counter += 1
    used.add(name.lower())
    return name
