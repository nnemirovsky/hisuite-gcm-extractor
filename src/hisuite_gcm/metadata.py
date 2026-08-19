"""Parse the subset of HiSuite ``info.xml`` needed for payload recovery."""

from __future__ import annotations

import dataclasses
import pathlib
import xml.etree.ElementTree as ET

from .crypto import is_valid_material

#: ``info.xml`` describes modules, not content; anything larger is refused
#: rather than parsed into memory.
MAX_INFO_XML_BYTES = 64 * 1024 * 1024

#: Depth searched below a directory when looking for a backup. Three levels
#: covers pointing the command at a HiSuite root, whose real backups live in
#: ``HiSuite/backupFiles/<backup name>/``.
MAX_SEARCH_DEPTH = 3

#: Upper bound on directories visited, so pointing the command at a home
#: directory by mistake stops quickly instead of walking a whole disk.
MAX_SEARCH_DIRECTORIES = 4000

#: Column names that have been observed to identify a module.
NAME_COLUMNS = ("packageName", "name", "appName")

_INFO_NAME = "info.xml"


@dataclasses.dataclass(frozen=True)
class Module:
    """Encryption metadata for one backed-up module or Android package.

    ``info.xml`` may list the same module more than once. Every distinct
    ``encMsgV3`` value is kept in document order; recovery tries them in turn
    and keeps only the one whose GCM tag verifies.
    """

    name: str
    materials: tuple[str, ...]

    @property
    def enc_msg_v3(self) -> str:
        """The first candidate key material for this module."""

        return self.materials[0]


def _value(column: ET.Element) -> str | None:
    value = column.find("value")
    if value is None:
        return None
    if "value" in value.attrib:
        return value.attrib["value"]
    if value.attrib:
        return next(iter(value.attrib.values()))
    if value.text:
        return value.text.strip()
    return None


def _reject_doctype(data: bytes) -> None:
    """Refuse documents carrying a DTD, which can drive entity expansion."""

    index = 0
    while index < len(data):
        if data.startswith(b"\xef\xbb\xbf", index):
            index += 3
        elif data[index : index + 1].isspace():
            index += 1
        elif data.startswith(b"<!--", index):
            end = data.find(b"-->", index + 4)
            if end < 0:
                return
            index = end + 3
        elif data.startswith(b"<?", index):
            end = data.find(b"?>", index + 2)
            if end < 0:
                return
            index = end + 2
        elif data[index : index + 9].upper() == b"<!DOCTYPE":
            raise ValueError(
                "info.xml declares a document type definition; refusing to parse it "
                "because entity expansion can exhaust memory"
            )
        else:
            return


def _parse(info_xml: pathlib.Path) -> ET.Element:
    size = info_xml.stat().st_size
    if size > MAX_INFO_XML_BYTES:
        raise ValueError(
            f"{info_xml} is {size} bytes, larger than the {MAX_INFO_XML_BYTES}-byte limit "
            "for backup metadata"
        )
    data = info_xml.read_bytes()
    _reject_doctype(data)
    try:
        return ET.fromstring(data)
    except ET.ParseError as error:
        raise ValueError(f"{info_xml} is not well-formed XML: {error}") from error


def modules_from_info(info_xml: pathlib.Path) -> list[Module]:
    """Return uniquely named modules that carry valid Security V3 material."""

    root = _parse(info_xml)
    materials: dict[str, list[str]] = {}
    for row_node in root.iter("row"):
        row: dict[str, str] = {}
        for column in row_node.findall("column"):
            name = column.get("name")
            value = _value(column)
            if name and value is not None:
                row[name] = value
        module_name = next((row[column] for column in NAME_COLUMNS if row.get(column)), None)
        material = row.get("encMsgV3", "")
        if not module_name or not is_valid_material(material):
            continue
        candidates = materials.setdefault(module_name, [])
        if material not in candidates:
            candidates.append(material)
    return sorted(
        (Module(name, tuple(values)) for name, values in materials.items()),
        key=lambda module: module.name,
    )


def _backup_directories(root: pathlib.Path) -> list[pathlib.Path]:
    """Return directories at or below ``root`` (bounded depth) holding info.xml."""

    found: list[pathlib.Path] = []
    level = [root]
    visited = 0
    for _depth in range(MAX_SEARCH_DEPTH + 1):
        if not level or visited >= MAX_SEARCH_DIRECTORIES:
            break
        children: list[pathlib.Path] = []
        for directory in level:
            visited += 1
            if visited > MAX_SEARCH_DIRECTORIES:
                break
            if (directory / _INFO_NAME).is_file():
                found.append(directory)
                continue
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            children.extend(
                entry
                for entry in entries
                if entry.is_dir() and not entry.is_symlink() and not entry.name.startswith(".")
            )
        level = children
    return found


def find_backup(path: pathlib.Path) -> pathlib.Path:
    """Resolve a backup directory from a directory, parent, or ``info.xml`` path."""

    candidate = path.expanduser().resolve()
    if candidate.is_file():
        if candidate.name == _INFO_NAME:
            return candidate.parent
        raise ValueError(f"expected a backup directory, got the file {candidate}")
    if not candidate.is_dir():
        raise FileNotFoundError(f"no such directory: {candidate}")
    if (candidate / _INFO_NAME).is_file():
        return candidate

    matches = _backup_directories(candidate)
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise FileNotFoundError(
            f"no {_INFO_NAME} found in {candidate} or up to {MAX_SEARCH_DEPTH} levels below it; "
            "point the command at the backup directory itself"
        )
    listed = "\n  ".join(str(match.relative_to(candidate)) for match in sorted(matches)[:10])
    extra = "" if len(matches) <= 10 else f"\n  ... and {len(matches) - 10} more"
    raise ValueError(
        f"{len(matches)} backups found below {candidate}; select exactly one:\n  {listed}{extra}"
    )
