"""Discover and recover encrypted payloads from a HiSuite backup.

Discovery is deliberately narrow: a module's key material is only ever applied
to files the backup itself attributes to that module. See
``docs/COMPATIBILITY.md`` for the reasoning behind those rules.
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import pathlib
import tarfile
from collections.abc import Callable, Iterable, Iterator

from .archive import ExtractionReport, extract_tar_safely, payload_kind
from .crypto import AuthenticationError, decrypt_file, derive_key_and_nonce, verify_file
from .metadata import Module, modules_from_info
from .paths import is_safe_component, is_within, safe_component

#: Suffix of the per-module directory holding encrypted application-data TARs.
APP_DATA_SUFFIX = "_appDataTar"
#: Suffix of an encrypted module database.
DATABASE_SUFFIX = ".db"

#: A payload larger than this is never used for the pre-flight password check,
#: so the check can never dominate the cost of the recovery itself.
PROBE_SIZE_LIMIT = 256 * 1024 * 1024
#: How many modules to sample when checking the password up front.
PROBE_MODULES = 3

DATABASE_KIND = "database"
APP_DATA_KIND = "app-data"


@dataclasses.dataclass(frozen=True)
class Payload:
    """One encrypted file, together with the module whose key unlocks it."""

    module: Module
    source: pathlib.Path
    kind: str
    relative: pathlib.PurePosixPath
    size: int


@dataclasses.dataclass
class RecoveryResult:
    """Everything a recovery run produced, including what it refused to do."""

    decrypted: int = 0
    extracted_files: int = 0
    extracted_directories: int = 0
    skipped_special: int = 0
    failures: list[str] = dataclasses.field(default_factory=list)
    notes: list[str] = dataclasses.field(default_factory=list)
    #: Set when every sampled payload failed authentication, which almost
    #: always means the password is wrong rather than the backup being damaged.
    password_failed: bool = False

    @property
    def succeeded(self) -> bool:
        return not self.failures and not self.password_failed


def _iter_module_tars(
    directory: pathlib.Path,
) -> Iterator[tuple[pathlib.Path, pathlib.PurePosixPath]]:
    """Yield ``*.tar`` files anywhere below a module's app-data directory."""

    root = directory.resolve()
    for current, directory_names, file_names in os.walk(directory, followlinks=False):
        here = pathlib.Path(current)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if is_safe_component(name) and not (here / name).is_symlink()
        )
        for name in sorted(file_names):
            if not name.endswith(".tar") or not is_safe_component(name):
                continue
            candidate = here / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            if not is_within(root, candidate.resolve()):
                continue
            yield candidate, pathlib.PurePosixPath(candidate.relative_to(directory).as_posix())


def discover(backup: pathlib.Path) -> list[Payload]:
    """List the encrypted payloads this backup attributes to known modules."""

    payloads: list[Payload] = []
    for module in modules_from_info(backup / "info.xml"):
        if not is_safe_component(module.name):
            continue
        database = backup / f"{module.name}{DATABASE_SUFFIX}"
        if database.is_file() and not database.is_symlink():
            payloads.append(
                Payload(
                    module,
                    database,
                    DATABASE_KIND,
                    pathlib.PurePosixPath(database.name),
                    database.stat().st_size,
                )
            )
        tar_directory = backup / f"{module.name}{APP_DATA_SUFFIX}"
        if tar_directory.is_dir() and not tar_directory.is_symlink():
            payloads.extend(
                Payload(module, archive, APP_DATA_KIND, relative, archive.stat().st_size)
                for archive, relative in _iter_module_tars(tar_directory)
            )
    return payloads


def _unique(candidate: pathlib.Path, claimed: set[pathlib.Path]) -> pathlib.Path:
    """Return an unclaimed output path, keeping distinct payloads distinct."""

    result = candidate
    counter = 2
    while result in claimed:
        result = candidate.with_name(f"{candidate.stem}-{counter}{candidate.suffix}")
        counter += 1
    claimed.add(result)
    return result


def _output_path(
    payload: Payload,
    destination: pathlib.Path,
    module_directory: str,
    claimed: set[pathlib.Path],
) -> pathlib.Path:
    if payload.kind == DATABASE_KIND:
        candidate = destination / "databases" / safe_component(payload.source.name)
    else:
        parts = [safe_component(part) for part in payload.relative.parts]
        candidate = destination.joinpath("decrypted_tars", module_directory, *parts)
    return _unique(candidate, claimed)


class _KeyCache:
    """Derive each module's key once; PBKDF2 is intentionally slow."""

    def __init__(self, password: bytes) -> None:
        self._password = password
        self._entries: dict[str, tuple[bytes, bytes]] = {}

    def get(self, material: str) -> tuple[bytes, bytes]:
        entry = self._entries.get(material)
        if entry is None:
            entry = derive_key_and_nonce(self._password, material)
            self._entries[material] = entry
        return entry


def _verified_material(payload: Payload, keys: _KeyCache) -> str | None:
    """Return the module material whose GCM tag verifies, without writing anything."""

    for material in payload.module.materials:
        key, nonce = keys.get(material)
        try:
            verify_file(payload.source, key, nonce)
        except AuthenticationError:
            continue
        return material
    return None


def _authenticating_material(payload: Payload, keys: _KeyCache) -> str:
    """Pick the material to decrypt this payload with.

    With a single candidate there is nothing to choose, and ``decrypt_file``
    authenticates anyway, so the file is read once. Only a module listed more
    than once in ``info.xml`` pays for a verification pass.
    """

    materials = payload.module.materials
    if len(materials) == 1:
        return materials[0]
    material = _verified_material(payload, keys)
    if material is None:
        raise AuthenticationError(f"authentication failed: {payload.source}")
    return material


def _probe_candidates(payloads: Iterable[Payload]) -> list[Payload]:
    seen: set[str] = set()
    candidates: list[Payload] = []
    for payload in sorted(payloads, key=lambda item: item.size):
        if payload.size > PROBE_SIZE_LIMIT or payload.module.name in seen:
            continue
        seen.add(payload.module.name)
        candidates.append(payload)
        if len(candidates) == PROBE_MODULES:
            break
    return candidates


def _password_rejected(payloads: list[Payload], keys: _KeyCache) -> bool:
    """Return whether every cheap sample failed authentication.

    A single damaged file must not be mistaken for a wrong password, so this
    only reports failure when no sampled module authenticates at all, and any
    error other than an authentication failure leaves the question open.
    """

    if len(payloads) < 2:
        return False
    candidates = _probe_candidates(payloads)
    if not candidates:
        return False
    for payload in candidates:
        try:
            verified = _verified_material(payload, keys)
        except (OSError, ValueError):
            return False
        if verified is not None:
            return False
    return True


def _prepare_destination(backup: pathlib.Path, destination: pathlib.Path) -> None:
    if is_within(backup, destination) or is_within(destination, backup):
        raise ValueError(
            "the destination must be outside the backup directory so the original "
            f"backup is never modified: {destination}"
        )
    try:
        destination.mkdir(parents=True)
    except FileExistsError as error:
        raise FileExistsError(
            f"destination already exists: {destination}; choose a new directory so a "
            "previous attempt is never mixed with this one"
        ) from error


def recover(
    backup: pathlib.Path,
    destination: pathlib.Path,
    password: bytes,
    *,
    expand_tars: bool = True,
    keep_tars: bool = True,
    progress: Callable[[str], None] | None = None,
) -> RecoveryResult:
    """Decrypt every discovered payload, expanding application-data archives.

    Plaintext reaches ``destination`` only after its AES-GCM tag verifies.
    """

    backup = backup.expanduser().resolve()
    destination = destination.expanduser().resolve()
    _prepare_destination(backup, destination)

    report = RecoveryResult()
    emit = progress or (lambda _message: None)
    payloads = discover(backup)
    keys = _KeyCache(password)

    if _password_rejected(payloads, keys):
        report.password_failed = True
        report.failures.append(
            "no sampled payload authenticated; the backup password appears to be wrong"
        )
        emit("Stopping before decryption: the password did not authenticate any sampled payload.")
        return report

    claimed: set[pathlib.Path] = set()
    for payload in payloads:
        module_directory = safe_component(payload.module.name)
        output = _output_path(payload, destination, module_directory, claimed)
        try:
            key, nonce = keys.get(_authenticating_material(payload, keys))
            decrypt_file(payload.source, output, key, nonce)
            kind = payload_kind(output)
            report.decrypted += 1
            emit(f"{payload.kind}: {payload.relative} -> {kind}")
            if payload.kind == APP_DATA_KIND and expand_tars and kind == "TAR":
                _expand(payload, output, destination / "app_data" / module_directory, report, emit)
                if not keep_tars:
                    _discard(output, destination / "decrypted_tars")
        except (OSError, ValueError, tarfile.TarError) as error:
            report.failures.append(str(error))
            emit(f"FAILED {payload.relative}: {error}")
    return report


def _expand(
    payload: Payload,
    archive: pathlib.Path,
    target: pathlib.Path,
    report: RecoveryResult,
    emit: Callable[[str], None],
) -> None:
    extraction: ExtractionReport = extract_tar_safely(archive, target)
    report.extracted_files += extraction.files
    report.extracted_directories += extraction.directories
    report.skipped_special += extraction.skipped_special
    for problem in extraction.problems:
        report.failures.append(problem)
        emit(f"REFUSED {payload.relative}: {problem}")


def _discard(archive: pathlib.Path, stop_at: pathlib.Path) -> None:
    """Remove an expanded archive, and any directory it leaves empty."""

    archive.unlink(missing_ok=True)
    parent = archive.parent
    while parent != stop_at and is_within(stop_at, parent):
        with contextlib.suppress(OSError):
            parent.rmdir()
        parent = parent.parent
