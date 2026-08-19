from __future__ import annotations

import pathlib

import pytest

from hisuite_gcm.paths import WINDOWS_RESERVED, is_safe_component, is_within, safe_component


@pytest.mark.parametrize(
    "name",
    [
        "com.example.app",
        "module_1",
        "a-name.db",
        "NUL",
        "spaced name",
        "ünïcode",
    ],
)
def test_plain_names_are_safe(name: str) -> None:
    assert is_safe_component(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "..",
        "../escape",
        "a/b",
        "a\\b",
        "/absolute",
        "C:evil",
        "c:/evil",
        "\\\\server\\share",
        "\\rooted",
        "with\x00null",
        "with\nnewline",
        "x" * 300,
    ],
)
def test_escaping_names_are_rejected(name: str) -> None:
    assert not is_safe_component(name)


def test_windows_drive_relative_names_would_escape_a_join() -> None:
    # pathlib on Windows resolves "backup" / "C:evil" to "C:evil", leaving the
    # backup directory entirely. is_safe_component is what prevents that.
    assert pathlib.PureWindowsPath("backup") / "C:evil" == pathlib.PureWindowsPath("C:evil")
    assert not is_safe_component("C:evil")


def test_safe_component_keeps_tame_names_and_separates_the_rest() -> None:
    assert safe_component("com.example.app") == "com.example.app"
    assert safe_component("a/b") != safe_component("a_b")
    assert safe_component("").startswith("unnamed--")
    assert safe_component("../x").startswith("x--")
    assert "/" not in safe_component("a/b") and "\\" not in safe_component("a\\b")


def test_safe_component_avoids_windows_device_names() -> None:
    for reserved in sorted(WINDOWS_RESERVED):
        result = safe_component(reserved)
        assert result.split(".")[0].upper() not in WINDOWS_RESERVED
        assert safe_component(f"{reserved}.db").split(".")[0].upper() not in WINDOWS_RESERVED


def test_safe_component_bounds_length() -> None:
    assert len(safe_component("m" * 500)) <= 180


def test_is_within(tmp_path: pathlib.Path) -> None:
    assert is_within(tmp_path, tmp_path)
    assert is_within(tmp_path, tmp_path / "child" / "leaf")
    assert not is_within(tmp_path / "child", tmp_path)
    assert not is_within(tmp_path, tmp_path.parent / "sibling")
