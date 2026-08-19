"""Portable SHA-256 manifests for recovered data.

The output matches the ``sha256sum``/``shasum -a 256`` format, so a manifest
written today can be verified years later with tools that already exist on the
machine: ``sha256sum -c MANIFEST-SHA256.txt``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import pathlib

READ_BUFFER = 8 * 1024 * 1024
DEFAULT_MANIFEST_NAME = "MANIFEST-SHA256.txt"


@dataclasses.dataclass
class ManifestResult:
    """Where the manifest went, and what it could not cover."""

    path: pathlib.Path
    files: int = 0
    #: Human-readable reasons for files that could not be hashed.
    skipped: list[str] = dataclasses.field(default_factory=list)


def sha256(path: pathlib.Path) -> str:
    """Return the hexadecimal SHA-256 digest of a file, read in chunks."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(READ_BUFFER):
            digest.update(chunk)
    return digest.hexdigest()


def _format_line(digest: str, relative: str) -> str:
    """Escape exactly as coreutils does, so ``sha256sum -c`` stays usable."""

    if "\\" in relative or "\n" in relative or "\r" in relative:
        escaped = relative.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
        return f"\\{digest}  {escaped}\n"
    return f"{digest}  {relative}\n"


def _walk(root: pathlib.Path, excluded: set[pathlib.Path]) -> list[pathlib.Path]:
    """List regular files below ``root`` without following symlinked directories."""

    found: list[pathlib.Path] = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        here = pathlib.Path(current)
        directory_names[:] = sorted(
            name for name in directory_names if not (here / name).is_symlink()
        )
        for name in file_names:
            path = here / name
            if path in excluded or path.is_symlink() or not path.is_file():
                continue
            found.append(path)
    return sorted(found, key=lambda path: path.relative_to(root).as_posix())


def write_manifest(
    root: pathlib.Path,
    output_name: str = DEFAULT_MANIFEST_NAME,
) -> ManifestResult:
    """Write a SHA-256 manifest covering every regular file below ``root``."""

    root = root.expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    relative_output = pathlib.PurePath(output_name)
    if relative_output.is_absolute() or ".." in relative_output.parts:
        raise ValueError("manifest output must stay inside the root directory")
    output = (root / output_name).resolve()
    if output != root and root not in output.parents:
        raise ValueError("manifest output must stay inside the root directory")
    output.parent.mkdir(parents=True, exist_ok=True)

    temporary = output.with_name(f".{output.name}.tmp")
    result = ManifestResult(path=output)
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for path in _walk(root, {output, temporary}):
            relative = path.relative_to(root).as_posix()
            try:
                digest = sha256(path)
            except OSError as error:
                result.skipped.append(f"{relative}: {error.strerror or error}")
                continue
            handle.write(_format_line(digest, relative))
            result.files += 1
    temporary.replace(output)
    return result
