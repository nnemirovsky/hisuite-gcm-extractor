"""Conservative TAR inspection and extraction."""

from __future__ import annotations

import dataclasses
import pathlib
import shutil
import tarfile

from .paths import is_safe_component, is_within

COPY_BUFFER = 1024 * 1024
MAX_MEMBER_PATH = 4096

_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"SQLite format 3\x00", "SQLite"),
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
)


@dataclasses.dataclass
class ExtractionReport:
    """What a single archive produced, including everything left behind."""

    files: int = 0
    directories: int = 0
    #: Hard links, symlinks, devices, and FIFOs, which are never materialised.
    skipped_special: int = 0
    #: Member names that could escape the destination, or that the filesystem
    #: refused. Each entry is safe to show a user.
    problems: list[str] = dataclasses.field(default_factory=list)


def payload_kind(path: pathlib.Path) -> str:
    """Identify a decrypted payload by magic bytes, without trusting names."""

    with path.open("rb") as handle:
        header = handle.read(512)
    if not header:
        return "empty"
    for signature, name in _SIGNATURES:
        if header.startswith(signature):
            return name
    if len(header) >= 263 and header[257:263] in (b"ustar\x00", b"ustar "):
        return "TAR"
    return "data"


def _member_target(
    member: tarfile.TarInfo,
    destination: pathlib.Path,
    root: pathlib.Path,
) -> pathlib.Path | None:
    """Resolve a member to a path inside ``root``, or ``None`` if it escapes."""

    name = member.name
    if not name or len(name) > MAX_MEMBER_PATH:
        return None
    relative = pathlib.PurePosixPath(name)
    if relative.is_absolute():
        return None
    parts = [part for part in relative.parts if part != "."]
    if not parts or not all(is_safe_component(part) for part in parts):
        return None
    target = destination.joinpath(*parts)
    try:
        resolved = target.resolve()
    except OSError:
        return None
    if not is_within(root, resolved):
        return None
    return target


def extract_tar_safely(archive: pathlib.Path, destination: pathlib.Path) -> ExtractionReport:
    """Extract regular files and directories, leaving anything unsafe behind.

    Links, devices, absolute paths, and traversal paths are never written.
    A single rejected member does not abandon the rest of the archive: it is
    reported so the caller can tell the user exactly what was not recovered.
    """

    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    report = ExtractionReport()
    with tarfile.open(archive, "r:") as opened:
        for member in opened:
            if not (member.isfile() or member.isdir()):
                report.skipped_special += 1
                continue
            target = _member_target(member, destination, root)
            if target is None:
                report.problems.append(f"{archive.name}: refused unsafe entry {member.name!r}")
                continue
            try:
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    report.directories += 1
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = opened.extractfile(member)
                if source is None:
                    report.skipped_special += 1
                    continue
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=COPY_BUFFER)
                report.files += 1
            except OSError as error:
                report.problems.append(f"{archive.name}: could not write {member.name!r}: {error}")
    return report
