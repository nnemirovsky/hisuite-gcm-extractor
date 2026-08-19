from __future__ import annotations

import pathlib

import pytest
from conftest import (
    MATERIAL_A,
    MATERIAL_B,
    PASSWORD,
    WRONG_PASSWORD,
    encrypt,
    requires_symlinks,
    sqlite_payload,
    tar_bytes,
    write_info,
)

from hisuite_gcm.recovery import _unique, discover, recover


def test_end_to_end_authenticated_recovery(backup: pathlib.Path, tmp_path: pathlib.Path) -> None:
    output = tmp_path / "recovered"
    messages: list[str] = []
    result = recover(backup, output, PASSWORD, progress=messages.append)

    assert result.decrypted == 2
    assert result.extracted_files == 1
    assert result.succeeded
    assert (
        (output / "databases/com.example.memories.db")
        .read_bytes()
        .startswith(b"SQLite format 3\x00")
    )
    assert (output / "app_data/com.example.memories/files/hello.txt").read_text() == (
        "hello from a synthetic backup\n"
    )
    assert (output / "decrypted_tars/com.example.memories/data.tar").is_file()
    assert any("SQLite" in message for message in messages)


def test_wrong_password_stops_before_writing_plaintext(
    backup: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    output = tmp_path / "wrong"
    result = recover(backup, output, WRONG_PASSWORD)

    assert result.password_failed
    assert result.decrypted == 0
    assert not result.succeeded
    assert "password appears to be wrong" in result.failures[0]
    assert list(output.rglob("*")) == []


def test_one_damaged_file_is_not_mistaken_for_a_wrong_password(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "backup"
    write_info(
        root / "info.xml",
        [
            {"packageName": "com.example.damaged", "encMsgV3": MATERIAL_A},
            {"packageName": "com.example.intact", "encMsgV3": MATERIAL_B},
        ],
    )
    damaged = encrypt(root / "com.example.damaged.db", sqlite_payload(), MATERIAL_A)
    damaged.write_bytes(damaged.read_bytes()[:-1] + b"\x00")
    encrypt(root / "com.example.intact.db", sqlite_payload(b"intact"), MATERIAL_B)

    result = recover(root, tmp_path / "out", PASSWORD)
    assert not result.password_failed
    assert result.decrypted == 1
    assert len(result.failures) == 1
    assert "authentication failed" in result.failures[0]
    assert (tmp_path / "out/databases/com.example.intact.db").is_file()
    assert not (tmp_path / "out/databases/com.example.damaged.db").exists()


def test_duplicate_metadata_tries_every_candidate_material(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "backup"
    write_info(
        root / "info.xml",
        [
            {"packageName": "com.example.dup", "encMsgV3": MATERIAL_A},
            {"packageName": "com.example.dup", "encMsgV3": MATERIAL_B},
            {"packageName": "com.example.other", "encMsgV3": MATERIAL_B},
        ],
    )
    # The payload is encrypted with the second listed material only.
    encrypt(root / "com.example.dup.db", sqlite_payload(b"dup"), MATERIAL_B)
    encrypt(root / "com.example.other.db", sqlite_payload(b"other"), MATERIAL_B)

    result = recover(root, tmp_path / "out", PASSWORD)
    assert result.succeeded
    assert result.decrypted == 2
    assert (tmp_path / "out/databases/com.example.dup.db").read_bytes().endswith(b"dup")


def test_application_tars_are_found_in_nested_directories(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "backup"
    module = "com.example.nested"
    write_info(root / "info.xml", [{"packageName": module, "encMsgV3": MATERIAL_A}])
    encrypt(root / f"{module}_appDataTar" / "0" / "data.tar", tar_bytes({"a.txt": b"a"}))
    encrypt(root / f"{module}_appDataTar" / "1" / "data.tar", tar_bytes({"b.txt": b"b"}))
    (root / f"{module}_appDataTar" / "notes.txt").write_text("ignored", encoding="utf-8")

    payloads = discover(root)
    assert sorted(payload.relative.as_posix() for payload in payloads) == [
        "0/data.tar",
        "1/data.tar",
    ]
    result = recover(root, tmp_path / "out", PASSWORD)
    assert result.decrypted == 2
    assert result.extracted_files == 2
    assert (tmp_path / "out/decrypted_tars" / module / "0/data.tar").is_file()
    assert (tmp_path / "out/app_data" / module / "a.txt").read_text() == "a"
    assert (tmp_path / "out/app_data" / module / "b.txt").read_text() == "b"


@pytest.mark.parametrize("name", ["../outside", "C:outside", "..", "a/b", ""])
def test_unsafe_module_names_never_reach_the_filesystem(tmp_path: pathlib.Path, name: str) -> None:
    root = tmp_path / "backup"
    write_info(root / "info.xml", [{"packageName": name, "encMsgV3": MATERIAL_A}])
    encrypt(tmp_path / "outside.db", sqlite_payload())
    encrypt(root / "..db", sqlite_payload())
    assert discover(root) == []


@requires_symlinks
def test_symlinked_payloads_are_ignored(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "backup"
    module = "com.example.linked"
    write_info(root / "info.xml", [{"packageName": module, "encMsgV3": MATERIAL_A}])
    target = encrypt(tmp_path / "elsewhere.db", sqlite_payload())
    (root / f"{module}.db").symlink_to(target)
    (root / f"{module}_appDataTar").mkdir()
    outside_tar = encrypt(tmp_path / "elsewhere.tar", tar_bytes())
    (root / f"{module}_appDataTar" / "data.tar").symlink_to(outside_tar)
    assert discover(root) == []


@requires_symlinks
def test_symlinked_app_data_directory_is_ignored(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "backup"
    module = "com.example.linkdir"
    write_info(root / "info.xml", [{"packageName": module, "encMsgV3": MATERIAL_A}])
    elsewhere = tmp_path / "elsewhere"
    encrypt(elsewhere / "data.tar", tar_bytes())
    (root / f"{module}_appDataTar").symlink_to(elsewhere, target_is_directory=True)
    assert discover(root) == []


def test_output_collisions_keep_both_payloads(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "backup"
    write_info(
        root / "info.xml",
        [
            {"packageName": "com.example.one", "encMsgV3": MATERIAL_A},
            {"packageName": "com.example.two", "encMsgV3": MATERIAL_A},
        ],
    )
    encrypt(root / "com.example.one.db", sqlite_payload(b"one"))
    encrypt(root / "com.example.two.db", sqlite_payload(b"two"))
    # Force every output name to collide.
    monkeypatch.setattr("hisuite_gcm.recovery.safe_component", lambda _name: "same.db")

    result = recover(root, tmp_path / "out", PASSWORD)
    assert result.decrypted == 2
    written = sorted(path.name for path in (tmp_path / "out" / "databases").iterdir())
    assert written == ["same-2.db", "same.db"]
    contents = {(tmp_path / "out/databases" / name).read_bytes()[-3:] for name in written}
    assert contents == {b"one", b"two"}


def test_unique_never_reuses_a_claimed_path(tmp_path: pathlib.Path) -> None:
    claimed: set[pathlib.Path] = set()
    first = _unique(tmp_path / "file.db", claimed)
    second = _unique(tmp_path / "file.db", claimed)
    third = _unique(tmp_path / "file.db", claimed)
    assert [first.name, second.name, third.name] == ["file.db", "file-2.db", "file-3.db"]


def test_expanded_archives_can_be_discarded(backup: pathlib.Path, tmp_path: pathlib.Path) -> None:
    output = tmp_path / "lean"
    result = recover(backup, output, PASSWORD, keep_tars=False)
    assert result.extracted_files == 1
    assert not list(output.rglob("*.tar"))
    assert (output / "app_data/com.example.memories/files/hello.txt").is_file()


def test_no_expand_keeps_only_the_authenticated_archive(
    backup: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    output = tmp_path / "tars-only"
    result = recover(backup, output, PASSWORD, expand_tars=False)
    assert result.extracted_files == 0
    assert (output / "decrypted_tars/com.example.memories/data.tar").is_file()
    assert not (output / "app_data").exists()


def test_unsafe_archive_entries_are_reported_as_failures(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "backup"
    module = "com.example.evil"
    write_info(root / "info.xml", [{"packageName": module, "encMsgV3": MATERIAL_A}])
    encrypt(
        root / f"{module}_appDataTar" / "data.tar",
        tar_bytes({"../escape.txt": b"nope", "files/keep.txt": b"kept"}),
    )
    result = recover(root, tmp_path / "out", PASSWORD)
    assert result.extracted_files == 1
    assert result.failures and "refused unsafe entry" in result.failures[0]
    assert not (tmp_path / "escape.txt").exists()


def test_destination_must_be_new(backup: pathlib.Path, tmp_path: pathlib.Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(FileExistsError, match="already exists"):
        recover(backup, output, PASSWORD)


def test_destination_may_not_sit_inside_the_backup(backup: pathlib.Path) -> None:
    with pytest.raises(ValueError, match="outside the backup directory"):
        recover(backup, backup / "recovered", PASSWORD)


def test_backup_may_not_sit_inside_the_destination(
    backup: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(ValueError, match="outside the backup directory"):
        recover(backup, backup.parent, PASSWORD)


def test_non_tar_payloads_are_left_untouched(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "backup"
    module = "com.example.raw"
    write_info(root / "info.xml", [{"packageName": module, "encMsgV3": MATERIAL_A}])
    encrypt(root / f"{module}_appDataTar" / "data.tar", b"not really a tar at all")
    result = recover(root, tmp_path / "out", PASSWORD)
    assert result.decrypted == 1
    assert result.extracted_files == 0
    assert result.succeeded
    assert (tmp_path / "out/decrypted_tars" / module / "data.tar").read_bytes() == (
        b"not really a tar at all"
    )


def test_payload_sizes_are_reported(backup: pathlib.Path) -> None:
    payloads = discover(backup)
    assert all(payload.size > 0 for payload in payloads)
    assert {payload.kind for payload in payloads} == {"database", "app-data"}
