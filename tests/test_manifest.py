from __future__ import annotations

import os
import pathlib
import stat

import pytest
from conftest import requires_posix_permissions, requires_symlinks

from hisuite_gcm.manifest import sha256, write_manifest


def test_manifest_is_deterministic_and_excludes_itself(tmp_path: pathlib.Path) -> None:
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested/c.txt").write_text("c", encoding="utf-8")

    first = write_manifest(tmp_path)
    text = first.path.read_text(encoding="utf-8")
    assert first.files == 3
    assert not first.skipped
    assert [line.split("  ", 1)[1] for line in text.splitlines()] == [
        "a.txt",
        "b.txt",
        "nested/c.txt",
    ]

    second = write_manifest(tmp_path)
    assert second.files == 3
    assert second.path.read_text(encoding="utf-8") == text


def test_manifest_lines_match_the_sha256sum_format(tmp_path: pathlib.Path) -> None:
    payload = tmp_path / "photo.bin"
    payload.write_bytes(b"synthetic bytes")
    result = write_manifest(tmp_path)
    digest, name = result.path.read_text(encoding="utf-8").rstrip("\n").split("  ", 1)
    assert digest == sha256(payload)
    assert name == "photo.bin"


@pytest.mark.skipif(os.name == "nt", reason="backslashes are separators on Windows")
def test_manifest_escapes_names_like_coreutils(tmp_path: pathlib.Path) -> None:
    (tmp_path / "odd\\name.txt").write_text("x", encoding="utf-8")
    result = write_manifest(tmp_path)
    line = result.path.read_text(encoding="utf-8").rstrip("\n")
    assert line.startswith("\\")
    assert line.endswith("  odd\\\\name.txt")


@requires_symlinks
def test_manifest_skips_symlinks(tmp_path: pathlib.Path) -> None:
    (tmp_path / "real.txt").write_text("real", encoding="utf-8")
    (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    outside = tmp_path.parent / "outside-target"
    outside.mkdir(exist_ok=True)
    (tmp_path / "link-dir").symlink_to(outside, target_is_directory=True)

    result = write_manifest(tmp_path)
    assert result.files == 1
    assert result.path.read_text(encoding="utf-8").endswith("  real.txt\n")


@requires_posix_permissions
def test_unreadable_files_are_reported_not_fatal(tmp_path: pathlib.Path) -> None:
    readable = tmp_path / "readable.txt"
    readable.write_text("ok", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("nope", encoding="utf-8")
    secret.chmod(0)
    try:
        result = write_manifest(tmp_path)
        assert result.files == 1
        assert len(result.skipped) == 1
        assert "secret.txt" in result.skipped[0]
    finally:
        secret.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_manifest_output_cannot_escape_root(tmp_path: pathlib.Path) -> None:
    for name in ("../outside.txt", "/absolute.txt", "sub/../../outside.txt"):
        with pytest.raises(ValueError, match="inside the root"):
            write_manifest(tmp_path, name)


def test_manifest_requires_a_directory(tmp_path: pathlib.Path) -> None:
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        write_manifest(file_path)


def test_manifest_can_be_written_into_a_subdirectory(tmp_path: pathlib.Path) -> None:
    (tmp_path / "data.txt").write_text("data", encoding="utf-8")
    result = write_manifest(tmp_path, "checksums/MANIFEST.txt")
    assert result.path == tmp_path / "checksums/MANIFEST.txt"
    assert result.files == 1
