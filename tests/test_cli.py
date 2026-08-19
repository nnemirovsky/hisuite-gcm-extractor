from __future__ import annotations

import io
import json
import pathlib
import sqlite3
import subprocess

import pytest
from conftest import MATERIAL_A, PASSWORD, encrypt, sqlite_payload, write_info

from hisuite_gcm import android, cli
from hisuite_gcm.cli import CANNOT_RUN, INCOMPLETE, INTERRUPTED, OK, main


def feed_password(monkeypatch: pytest.MonkeyPatch, password: bytes = PASSWORD) -> None:
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(password + b"\n")))


def test_version_names_the_program(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == OK
    assert capsys.readouterr().out.startswith("hisuite-gcm ")


def test_inspect_lists_payloads(backup: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["inspect", str(backup)]) == OK
    out = capsys.readouterr().out
    assert "Modules with encryption metadata: 1" in out
    assert "Recoverable payloads found: 2" in out
    assert "com.example.memories.db" in out


def test_inspect_json_is_machine_readable(
    backup: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["inspect", str(backup), "--json"]) == OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["modules_with_crypto_metadata"] == 1
    assert payload["encrypted_bytes"] > 0
    assert {item["kind"] for item in payload["payloads"]} == {"database", "app-data"}
    assert all(
        "/" not in item["path"] or item["path"].count("/") == 1 for item in payload["payloads"]
    )
    assert payload["tool_version"]


def test_inspect_accepts_the_parent_directory(
    backup: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["inspect", str(backup.parent), "--json"]) == OK
    assert json.loads(capsys.readouterr().out)["backup"] == str(backup)


def test_inspect_explains_a_missing_backup(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["inspect", str(tmp_path / "absent")]) == CANNOT_RUN
    assert "error:" in capsys.readouterr().err


def test_extract_reads_the_password_from_stdin(
    backup: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    feed_password(monkeypatch)
    assert main(["extract", str(backup), str(tmp_path / "out"), "--password-stdin"]) == OK
    assert "Authenticated payloads decrypted: 2" in capsys.readouterr().out
    assert (tmp_path / "out/app_data/com.example.memories/files/hello.txt").is_file()


def test_extract_uses_the_hidden_prompt_by_default(
    backup: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked: list[str] = []

    def prompt(message: str) -> str:
        asked.append(message)
        return PASSWORD.decode("utf-8")

    monkeypatch.setattr("getpass.getpass", prompt)
    assert main(["extract", str(backup), str(tmp_path / "out")]) == OK
    assert asked and "hidden" in asked[0]


def test_extract_with_a_wrong_password_explains_itself(
    backup: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    feed_password(monkeypatch, b"not the password")
    code = main(["extract", str(backup), str(tmp_path / "out"), "--password-stdin"])
    captured = capsys.readouterr()
    assert code == INCOMPLETE
    assert "password did not authenticate" in captured.err
    assert "lock screen PIN" in captured.err
    assert not list((tmp_path / "out").rglob("*.db"))


def test_extract_rejects_an_empty_password(
    backup: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    feed_password(monkeypatch, b"")
    code = main(["extract", str(backup), str(tmp_path / "out"), "--password-stdin"])
    assert code == CANNOT_RUN
    assert "empty" in capsys.readouterr().err


def test_extract_preserves_passwords_with_spaces(
    backup: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(PASSWORD + b"\r\n")))
    assert main(["extract", str(backup), str(tmp_path / "out"), "--password-stdin"]) == OK


def test_extract_refuses_contradictory_flags(
    backup: pathlib.Path, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["extract", str(backup), str(tmp_path / "out"), "--no-expand", "--no-keep-tars"])
    assert code == CANNOT_RUN
    assert "discard everything" in capsys.readouterr().err


def test_extract_refuses_a_destination_inside_the_backup(
    backup: pathlib.Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    feed_password(monkeypatch)
    code = main(["extract", str(backup), str(backup / "out"), "--password-stdin"])
    assert code == CANNOT_RUN
    assert "outside the backup directory" in capsys.readouterr().err


def test_keyboard_interrupt_is_reported_calmly(
    backup: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def interrupt(_from_stdin: bool) -> bytes:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_password", interrupt)
    assert main(["extract", str(backup), str(tmp_path / "out")]) == INTERRUPTED
    assert "interrupted" in capsys.readouterr().err


def test_manifest_command(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    assert main(["manifest", str(tmp_path)]) == OK
    assert "1 files" in capsys.readouterr().out
    assert (tmp_path / "MANIFEST-SHA256.txt").is_file()


def test_manifest_command_rejects_an_escaping_output(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["manifest", str(tmp_path), "--output", "../escape.txt"]) == CANNOT_RUN
    assert "inside the root" in capsys.readouterr().err


def test_copy_shared_reports_the_destination(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(android, "_resolve_executable", lambda name: f"/fake/{name}")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        stdout = "device" if "get-state" in command else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr("subprocess.run", runner)
    assert main(["copy-shared", str(tmp_path / "shared")]) == OK
    assert "Shared storage copied to" in capsys.readouterr().out


def test_copy_shared_explains_a_missing_adb(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert main(["copy-shared", str(tmp_path / "shared"), "--adb", "adb"]) == CANNOT_RUN
    assert "Android Platform Tools" in capsys.readouterr().err


def test_adapters_command_lists_and_detects(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["adapters"]) == OK
    assert "sqlite-tables" in capsys.readouterr().out

    database = tmp_path / "recovered.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE note (body TEXT)")
    connection.execute("INSERT INTO note VALUES ('synthetic')")
    connection.commit()
    connection.close()

    assert main(["adapters", str(database), "--json"]) == OK
    rows = json.loads(capsys.readouterr().out)
    assert any(row["name"] == "sqlite-tables" and row["detected"] for row in rows)


def test_export_writes_readable_files(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database = tmp_path / "recovered.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE note (body TEXT)")
    connection.execute("INSERT INTO note VALUES ('synthetic')")
    connection.commit()
    connection.close()

    assert main(["export", str(database), str(tmp_path / "readable")]) == OK
    out = capsys.readouterr().out
    assert "Adapter: sqlite-tables" in out
    assert (tmp_path / "readable/note.csv").read_text(encoding="utf-8").startswith("body")


def test_export_refuses_a_non_database(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = tmp_path / "payload.tar"
    payload.write_bytes(b"not a database")
    assert main(["export", str(payload), str(tmp_path / "readable")]) == CANNOT_RUN
    assert "not a SQLite database" in capsys.readouterr().err


def test_export_refuses_an_existing_destination(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database = tmp_path / "recovered.db"
    sqlite3.connect(database).close()
    (tmp_path / "readable").mkdir()
    assert main(["export", str(database), str(tmp_path / "readable")]) == CANNOT_RUN
    assert "already exists" in capsys.readouterr().err


def test_extract_reports_partial_failures(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "backup"
    write_info(
        root / "info.xml",
        [
            {"packageName": "com.example.good", "encMsgV3": MATERIAL_A},
            {"packageName": "com.example.bad", "encMsgV3": MATERIAL_A},
        ],
    )
    encrypt(root / "com.example.good.db", sqlite_payload())
    broken = encrypt(root / "com.example.bad.db", sqlite_payload())
    broken.write_bytes(broken.read_bytes()[:-1] + b"\x00")

    feed_password(monkeypatch)
    code = main(["extract", str(root), str(tmp_path / "out"), "--password-stdin"])
    captured = capsys.readouterr()
    assert code == INCOMPLETE
    assert "Failures: 1" in captured.err
    assert "Authenticated payloads decrypted: 1" in captured.out


def test_export_contacts_command(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(android, "_resolve_executable", lambda name: f"/fake/{name}")
    card = b"BEGIN:VCARD\nVERSION:3.0\nFN:Synthetic Person\nEND:VCARD\n"

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[object]:
        if "get-state" in command:
            return subprocess.CompletedProcess(command, 0, "device", "")
        if "query" in command:
            return subprocess.CompletedProcess(command, 0, "Row: 0 lookup=a1\n", "")
        return subprocess.CompletedProcess(command, 0, card, b"")

    monkeypatch.setattr("subprocess.run", runner)
    assert main(["export-contacts", str(tmp_path / "contacts.vcf")]) == OK
    out = capsys.readouterr().out
    assert "Contacts exported: 1 of 1" in out
    assert (tmp_path / "contacts.vcf").read_bytes() == card


def test_export_contacts_reports_a_failing_provider(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(android, "_resolve_executable", lambda name: f"/fake/{name}")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[object]:
        if "get-state" in command:
            return subprocess.CompletedProcess(command, 0, "device", "")
        return subprocess.CompletedProcess(command, 1, "", "Error: provider not found")

    monkeypatch.setattr("subprocess.run", runner)
    assert main(["export-contacts", str(tmp_path / "contacts.vcf")]) == CANNOT_RUN
    assert "contacts query failed" in capsys.readouterr().err
