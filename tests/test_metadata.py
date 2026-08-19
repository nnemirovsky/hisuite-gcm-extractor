from __future__ import annotations

import pathlib

import pytest
from conftest import MATERIAL_A, MATERIAL_B, write_info

from hisuite_gcm.metadata import MAX_SEARCH_DEPTH, find_backup, modules_from_info


def test_modules_are_named_sorted_and_validated(tmp_path: pathlib.Path) -> None:
    write_info(
        tmp_path / "info.xml",
        [
            {"packageName": "com.example.b", "encMsgV3": MATERIAL_B},
            {"packageName": "com.example.a", "encMsgV3": MATERIAL_A},
            {"packageName": "com.example.unencrypted", "encMsgV3": ""},
            {"packageName": "com.example.short", "encMsgV3": MATERIAL_A[:-2]},
            {"packageName": "com.example.nonhex", "encMsgV3": "z" * 96},
            {"encMsgV3": MATERIAL_A},
        ],
    )
    modules = modules_from_info(tmp_path / "info.xml")
    assert [module.name for module in modules] == ["com.example.a", "com.example.b"]
    assert modules[0].enc_msg_v3 == MATERIAL_A


def test_alternative_name_columns_are_accepted(tmp_path: pathlib.Path) -> None:
    write_info(
        tmp_path / "info.xml",
        [
            {"name": "calendar", "encMsgV3": MATERIAL_A},
            {"appName": "contacts", "encMsgV3": MATERIAL_B},
        ],
    )
    assert [module.name for module in modules_from_info(tmp_path / "info.xml")] == [
        "calendar",
        "contacts",
    ]


def test_value_may_be_element_text(tmp_path: pathlib.Path) -> None:
    (tmp_path / "info.xml").write_text(
        "<root><row><column name='packageName'><value> com.example.text </value></column>"
        f"<column name='encMsgV3'><value>{MATERIAL_A}</value></column></row></root>",
        encoding="utf-8",
    )
    modules = modules_from_info(tmp_path / "info.xml")
    assert [module.name for module in modules] == ["com.example.text"]


def test_duplicate_rows_keep_every_distinct_material_in_order(tmp_path: pathlib.Path) -> None:
    write_info(
        tmp_path / "info.xml",
        [
            {"packageName": "com.example.twice", "encMsgV3": MATERIAL_A},
            {"packageName": "com.example.twice", "encMsgV3": MATERIAL_B},
            {"packageName": "com.example.twice", "encMsgV3": MATERIAL_A},
        ],
    )
    (module,) = modules_from_info(tmp_path / "info.xml")
    assert module.materials == (MATERIAL_A, MATERIAL_B)
    assert module.enc_msg_v3 == MATERIAL_A


def test_uppercase_material_is_accepted(tmp_path: pathlib.Path) -> None:
    write_info(tmp_path / "info.xml", [{"packageName": "m", "encMsgV3": MATERIAL_A.upper()}])
    (module,) = modules_from_info(tmp_path / "info.xml")
    assert module.enc_msg_v3 == MATERIAL_A.upper()


def test_document_type_definitions_are_refused(tmp_path: pathlib.Path) -> None:
    info = tmp_path / "info.xml"
    info.write_text(
        "<?xml version='1.0'?><!-- comment -->"
        "<!DOCTYPE root [<!ENTITY a 'AA'><!ENTITY b '&a;&a;&a;&a;'>]>"
        "<root><row><column name='packageName'><value value='&b;'/></column></row></root>",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="document type definition"):
        modules_from_info(info)


def test_malformed_xml_reports_the_file(tmp_path: pathlib.Path) -> None:
    info = tmp_path / "info.xml"
    info.write_text("<root><row>", encoding="utf-8")
    with pytest.raises(ValueError, match="not well-formed XML"):
        modules_from_info(info)


def test_oversized_metadata_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("hisuite_gcm.metadata.MAX_INFO_XML_BYTES", 8)
    write_info(tmp_path / "info.xml", [{"packageName": "m", "encMsgV3": MATERIAL_A}])
    with pytest.raises(ValueError, match="larger than"):
        modules_from_info(tmp_path / "info.xml")


def test_find_backup_accepts_the_directory_itself(backup: pathlib.Path) -> None:
    assert find_backup(backup) == backup


def test_find_backup_accepts_a_parent_and_an_info_xml_path(backup: pathlib.Path) -> None:
    assert find_backup(backup.parent) == backup
    assert find_backup(backup / "info.xml") == backup


def test_find_backup_searches_nested_hisuite_layouts(tmp_path: pathlib.Path) -> None:
    nested = tmp_path / "HiSuite" / "backupFiles" / "Phone_2026-01-01"
    write_info(nested / "info.xml", [{"packageName": "m", "encMsgV3": MATERIAL_A}])
    assert find_backup(tmp_path) == nested
    assert MAX_SEARCH_DEPTH >= 3


def test_find_backup_reports_every_candidate_when_ambiguous(tmp_path: pathlib.Path) -> None:
    for name in ("one", "two"):
        write_info(tmp_path / name / "info.xml", [{"packageName": name, "encMsgV3": MATERIAL_A}])
    with pytest.raises(ValueError, match="2 backups found") as error:
        find_backup(tmp_path)
    assert "one" in str(error.value) and "two" in str(error.value)


def test_find_backup_explains_an_empty_directory(tmp_path: pathlib.Path) -> None:
    with pytest.raises(FileNotFoundError, match=r"no info\.xml found"):
        find_backup(tmp_path)


def test_find_backup_rejects_a_plain_file(tmp_path: pathlib.Path) -> None:
    other = tmp_path / "notes.txt"
    other.write_text("synthetic", encoding="utf-8")
    with pytest.raises(ValueError, match="expected a backup directory"):
        find_backup(other)


def test_find_backup_reports_a_missing_path(tmp_path: pathlib.Path) -> None:
    with pytest.raises(FileNotFoundError, match="no such directory"):
        find_backup(tmp_path / "absent")
