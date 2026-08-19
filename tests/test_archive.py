from __future__ import annotations

import pathlib
import tarfile

from conftest import sqlite_payload, tar_bytes, tar_with_members

from hisuite_gcm.archive import extract_tar_safely, payload_kind


def write_tar(path: pathlib.Path, entries: dict[str, bytes]) -> pathlib.Path:
    path.write_bytes(tar_bytes(entries))
    return path


def test_regular_files_and_directories_are_extracted(tmp_path: pathlib.Path) -> None:
    archive = write_tar(
        tmp_path / "safe.tar",
        {"files/note.txt": b"memory", "files/nested/photo.bin": b"\x00\x01"},
    )
    report = extract_tar_safely(archive, tmp_path / "out")
    assert report.files == 2
    assert not report.problems
    assert (tmp_path / "out/files/note.txt").read_bytes() == b"memory"
    assert (tmp_path / "out/files/nested/photo.bin").read_bytes() == b"\x00\x01"


def test_traversal_members_are_refused_without_losing_the_rest(tmp_path: pathlib.Path) -> None:
    archive = write_tar(
        tmp_path / "mixed.tar",
        {"../escape.txt": b"nope", "files/keep.txt": b"kept", "/abs.txt": b"nope"},
    )
    report = extract_tar_safely(archive, tmp_path / "out")
    assert report.files == 1
    assert len(report.problems) == 2
    assert (tmp_path / "out/files/keep.txt").read_bytes() == b"kept"
    assert not (tmp_path / "escape.txt").exists()
    assert not (tmp_path.parent / "escape.txt").exists()


def test_windows_drive_relative_member_is_refused(tmp_path: pathlib.Path) -> None:
    archive = write_tar(tmp_path / "drive.tar", {"C:evil.txt": b"nope"})
    report = extract_tar_safely(archive, tmp_path / "out")
    assert report.files == 0
    assert "C:evil.txt" in report.problems[0]


def test_links_and_devices_are_never_materialised(tmp_path: pathlib.Path) -> None:
    archive = tmp_path / "links.tar"
    symlink = tarfile.TarInfo("evil-link")
    symlink.type = tarfile.SYMTYPE
    symlink.linkname = "/etc/passwd"
    hard = tarfile.TarInfo("evil-hardlink")
    hard.type = tarfile.LNKTYPE
    hard.linkname = "files/keep.txt"
    device = tarfile.TarInfo("evil-device")
    device.type = tarfile.CHRTYPE
    device.devmajor, device.devminor = 1, 3
    keep = tarfile.TarInfo("files/keep.txt")
    keep.size = 4
    tar_with_members(archive, [symlink, hard, device, keep])

    report = extract_tar_safely(archive, tmp_path / "out")
    assert report.files == 1
    assert report.skipped_special == 3
    assert not report.problems
    assert not (tmp_path / "out/evil-link").exists()
    assert not (tmp_path / "out/evil-hardlink").exists()
    assert not (tmp_path / "out/evil-device").exists()


def test_directory_members_are_created(tmp_path: pathlib.Path) -> None:
    archive = tmp_path / "dirs.tar"
    directory = tarfile.TarInfo("files/empty")
    directory.type = tarfile.DIRTYPE
    tar_with_members(archive, [directory])
    report = extract_tar_safely(archive, tmp_path / "out")
    assert report.directories == 1
    assert (tmp_path / "out/files/empty").is_dir()


def test_symlinked_destination_parent_cannot_be_used_to_escape(tmp_path: pathlib.Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    destination = tmp_path / "out"
    destination.mkdir()
    (destination / "link").symlink_to(outside, target_is_directory=True)
    archive = write_tar(tmp_path / "through-link.tar", {"link/planted.txt": b"nope"})
    report = extract_tar_safely(archive, destination)
    assert report.files == 0
    assert report.problems
    assert not (outside / "planted.txt").exists()


def test_payload_kind_identifies_formats(tmp_path: pathlib.Path) -> None:
    kinds = {
        "db": sqlite_payload(),
        "tar": tar_bytes(),
        "zip": b"PK\x03\x04" + bytes(100),
        "gz": b"\x1f\x8b" + bytes(100),
        "raw": b"nothing recognisable" * 10,
        "empty": b"",
    }
    for name, data in kinds.items():
        (tmp_path / name).write_bytes(data)
    assert payload_kind(tmp_path / "db") == "SQLite"
    assert payload_kind(tmp_path / "tar") == "TAR"
    assert payload_kind(tmp_path / "zip") == "ZIP"
    assert payload_kind(tmp_path / "gz") == "gzip"
    assert payload_kind(tmp_path / "raw") == "data"
    assert payload_kind(tmp_path / "empty") == "empty"
