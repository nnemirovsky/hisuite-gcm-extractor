"""Path-component safety shared by metadata, discovery, and extraction.

Every name in a backup (module names in ``info.xml``, member names inside a
decrypted TAR) is untrusted input. Two questions are asked about such a name,
and they are deliberately kept separate:

``is_safe_component``
    May this name be joined onto a trusted directory at all? This is the
    security question. It must hold on every platform, including Windows,
    where ``Path("backup") / "C:evil"`` silently escapes to another drive.

``safe_component``
    What should the corresponding *output* name be? This is the portability
    question, answered by rewriting anything a filesystem may reject.
"""

from __future__ import annotations

import hashlib
import pathlib
import re

#: Names Windows reserves for devices, with or without an extension.
WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)

_UNSAFE_OUTPUT_CHARACTERS = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_COMPONENT_LENGTH = 255


def is_safe_component(name: str) -> bool:
    """Return whether ``name`` is a single, non-escaping path component.

    Rejects empty names, ``.``/``..``, embedded separators, control
    characters, and anything Windows would interpret as a drive-relative or
    root-relative path.
    """

    if not name or name in {".", ".."}:
        return False
    if len(name) > _MAX_COMPONENT_LENGTH:
        return False
    if any(character in name for character in ("/", "\\", "\x00")):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        return False
    windows = pathlib.PureWindowsPath(name)
    return not (windows.drive or windows.root or len(windows.parts) != 1)


def safe_component(name: str) -> str:
    """Return a portable output directory/file name derived from ``name``.

    The result stays recognisable when the input is already tame, and gains a
    short digest suffix whenever rewriting could otherwise merge two distinct
    inputs into one directory.
    """

    cleaned = _UNSAFE_OUTPUT_CHARACTERS.sub("_", name).strip("._ ")
    if cleaned.split(".")[0].upper() in WINDOWS_RESERVED:
        cleaned = f"_{cleaned}"
    if cleaned and cleaned == name and len(cleaned) <= 180:
        return cleaned
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]
    return f"{cleaned[:160] or 'unnamed'}--{digest}"


def is_within(root: pathlib.Path, target: pathlib.Path) -> bool:
    """Return whether ``target`` is ``root`` itself or lives below it."""

    return target == root or target.is_relative_to(root)
