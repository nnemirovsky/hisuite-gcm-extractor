from __future__ import annotations

import csv
import pathlib
import sqlite3

import pytest

from hisuite_gcm.adapters import (
    DetectionResult,
    ExportResult,
    SqliteTablesAdapter,
    available_adapters,
    detect_adapters,
    find_adapter,
    open_readonly,
    requires_schema,
    table_names,
)
from hisuite_gcm.adapters.tables import cell, csv_safe


def read_csv(path: pathlib.Path) -> list[list[str]]:
    return list(csv.reader(path.read_text(encoding="utf-8").splitlines()))


def make_database(path: pathlib.Path, statements: list[str]) -> pathlib.Path:
    connection = sqlite3.connect(path)
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()
    return path


@pytest.fixture
def messages_db(tmp_path: pathlib.Path) -> pathlib.Path:
    """A synthetic message-like schema invented purely for these tests."""

    return make_database(
        tmp_path / "messages.db",
        [
            "CREATE TABLE message (_id INTEGER PRIMARY KEY, body TEXT, sent_at INTEGER)",
            "CREATE TABLE participant (_id INTEGER PRIMARY KEY, display_name TEXT)",
            "INSERT INTO message VALUES (1, 'synthetic body', 1735689600)",
            "INSERT INTO message VALUES (2, '=cmd|calc', 1735689601)",
            "INSERT INTO participant VALUES (1, 'Example Person')",
        ],
    )


class SyntheticMessagesAdapter:
    """A test-only adapter proving the plugin contract is usable."""

    name = "synthetic-messages"
    summary = "test adapter for a synthetic message schema"
    supports = "the schema defined in this test module only"

    def detect(self, connection: sqlite3.Connection) -> DetectionResult:
        return requires_schema(
            connection,
            {"message": ["_id", "body", "sent_at"], "participant": ["display_name"]},
            label="the synthetic message schema",
        )

    def export(self, connection: sqlite3.Connection, destination: pathlib.Path) -> ExportResult:
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / "messages.txt"
        rows = connection.execute("SELECT body FROM message ORDER BY _id").fetchall()
        path.write_text(
            "\n".join(row[0].decode("utf-8") for row in rows) + "\n",
            encoding="utf-8",
        )
        return ExportResult(files=[path], rows=len(rows))


def test_schema_detection_recognises_a_known_schema(messages_db: pathlib.Path) -> None:
    connection = open_readonly(messages_db)
    try:
        result = SyntheticMessagesAdapter().detect(connection)
    finally:
        connection.close()
    assert result.supported
    assert "matches" in result.reason


def test_schema_detection_names_the_missing_table(tmp_path: pathlib.Path) -> None:
    database = make_database(tmp_path / "other.db", ["CREATE TABLE unrelated (a TEXT)"])
    connection = open_readonly(database)
    try:
        result = SyntheticMessagesAdapter().detect(connection)
    finally:
        connection.close()
    assert not result.supported
    assert "'message' is missing" in result.reason


def test_schema_detection_names_the_missing_column(tmp_path: pathlib.Path) -> None:
    database = make_database(
        tmp_path / "partial.db",
        [
            "CREATE TABLE message (_id INTEGER PRIMARY KEY, body TEXT)",
            "CREATE TABLE participant (_id INTEGER PRIMARY KEY, display_name TEXT)",
        ],
    )
    connection = open_readonly(database)
    try:
        result = SyntheticMessagesAdapter().detect(connection)
    finally:
        connection.close()
    assert not result.supported
    assert "sent_at" in result.reason


def test_registry_lists_and_finds_adapters(messages_db: pathlib.Path) -> None:
    names = [adapter.name for adapter in available_adapters()]
    assert "sqlite-tables" in names
    assert find_adapter("sqlite-tables").name == "sqlite-tables"
    with pytest.raises(ValueError, match="unknown adapter"):
        find_adapter("does-not-exist")

    results = detect_adapters(
        messages_db, adapters=[SqliteTablesAdapter(), SyntheticMessagesAdapter()]
    )
    assert {adapter.name: bool(result) for adapter, result in results} == {
        "sqlite-tables": True,
        "synthetic-messages": True,
    }


def test_generic_adapter_writes_one_csv_per_table(
    messages_db: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    connection = open_readonly(messages_db)
    try:
        result = SqliteTablesAdapter().export(connection, tmp_path / "export")
    finally:
        connection.close()

    written = sorted(path.name for path in result.files)
    assert written == ["message.csv", "participant.csv", "schema.sql"]
    assert result.rows == 3
    rows = list(
        csv.reader((tmp_path / "export/message.csv").read_text(encoding="utf-8").splitlines())
    )
    assert rows[0] == ["_id", "body", "sent_at"]
    assert rows[1] == ["1", "synthetic body", "1735689600"]
    assert "CREATE TABLE message" in (tmp_path / "export/schema.sql").read_text(encoding="utf-8")


def test_spreadsheet_formula_injection_is_neutralised(
    messages_db: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    connection = open_readonly(messages_db)
    try:
        SqliteTablesAdapter().export(connection, tmp_path / "export")
    finally:
        connection.close()
    rows = list(
        csv.reader((tmp_path / "export/message.csv").read_text(encoding="utf-8").splitlines())
    )
    assert rows[2][1] == "'=cmd|calc"


def test_cell_rendering_covers_nulls_and_binary() -> None:
    assert cell(None) == ""
    assert cell(b"text") == "text"
    assert cell(b"\xff\xfe\x00") == "[binary: 3 bytes]"
    assert cell(12) == "12"
    assert csv_safe("+1") == "'+1"
    assert csv_safe("plain") == "plain"


def test_export_never_modifies_the_database(
    messages_db: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    before = messages_db.read_bytes()
    connection = open_readonly(messages_db)
    try:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("INSERT INTO participant VALUES (2, 'nope')")
        SqliteTablesAdapter().export(connection, tmp_path / "export")
    finally:
        connection.close()
    assert messages_db.read_bytes() == before


def test_non_sqlite_input_is_refused(tmp_path: pathlib.Path) -> None:
    payload = tmp_path / "payload.tar"
    payload.write_bytes(b"not a database at all")
    with pytest.raises(ValueError, match="not a SQLite database"):
        open_readonly(payload)


def test_missing_database_is_reported(tmp_path: pathlib.Path) -> None:
    with pytest.raises(FileNotFoundError):
        open_readonly(tmp_path / "absent.db")


def test_empty_database_is_not_claimed(tmp_path: pathlib.Path) -> None:
    database = make_database(tmp_path / "empty.db", ["CREATE TABLE t (a)", "DROP TABLE t"])
    connection = open_readonly(database)
    try:
        assert table_names(connection) == []
        assert not SqliteTablesAdapter().detect(connection)
    finally:
        connection.close()


def test_odd_table_names_are_quoted_and_filed_safely(tmp_path: pathlib.Path) -> None:
    database = make_database(
        tmp_path / "odd.db",
        [
            'CREATE TABLE "weird ""name"" / here" (a TEXT)',
            'INSERT INTO "weird ""name"" / here" VALUES (\'v\')',
        ],
    )
    connection = open_readonly(database)
    try:
        result = SqliteTablesAdapter().export(connection, tmp_path / "export")
    finally:
        connection.close()
    assert result.rows == 1
    csv_files = [path for path in result.files if path.suffix == ".csv"]
    assert len(csv_files) == 1
    assert "/" not in csv_files[0].name
