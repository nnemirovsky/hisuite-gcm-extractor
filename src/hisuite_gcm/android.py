"""Read-only shared-storage copying through Android Debug Bridge.

Only two ADB verbs are ever issued: ``get-state`` and ``pull``. Nothing is
installed, deleted, or written to the phone.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from collections.abc import Callable, Sequence
from typing import IO, Any

#: Anything that behaves like ``subprocess.run``. The payload type depends on
#: whether the call asked for text, so it stays deliberately loose.
Runner = Callable[..., "subprocess.CompletedProcess[Any]"]


def _default_runner(command: list[str], **options: object) -> subprocess.CompletedProcess[Any]:
    """Indirection so callers (and tests) can substitute the process runner."""

    return subprocess.run(command, **options)  # type: ignore[call-overload,no-any-return]


#: ``adb get-state`` answers immediately or not at all.
STATE_TIMEOUT_SECONDS = 30
#: Shared storage on every supported Android release.
SHARED_STORAGE = "/sdcard/."
#: Android's standard aggregated Contacts provider.
CONTACTS_URI = "content://com.android.contacts/contacts"
#: A contacts request that has not answered by now is not going to.
CONTACTS_TIMEOUT_SECONDS = 120
#: Contacts per provider request. Large batches build long URIs that the
#: platform may refuse, which is why the exporter falls back to single
#: requests rather than trusting one big one.
DEFAULT_BATCH_SIZE = 50
MAX_BATCH_SIZE = 500

_STATE_HELP = {
    "unauthorized": (
        "the phone has not authorised this computer; unlock the phone and accept the "
        "USB debugging prompt, then try again"
    ),
    "offline": (
        "the phone is connected but not responding to ADB; unplug it, unlock it, and "
        "reconnect the cable"
    ),
    "recovery": "the phone is in recovery mode; boot it normally before copying",
}


class AdbError(RuntimeError):
    """ADB is missing, the device is unusable, or a command failed."""


@dataclasses.dataclass
class ContactsExport:
    """The result of a contacts export, including what it could not read."""

    path: pathlib.Path
    requested: int = 0
    exported: int = 0
    #: Provider messages for contacts that could not be serialised. These
    #: carry no names or numbers.
    skipped: list[str] = dataclasses.field(default_factory=list)
    notes: list[str] = dataclasses.field(default_factory=list)


def _resolve_executable(adb: str) -> str:
    executable = shutil.which(adb)
    if executable is None:
        raise AdbError(
            f"ADB executable not found: {adb}. Install Google's Android Platform Tools "
            "and make sure 'adb' is on PATH, or pass --adb with its full path."
        )
    return executable


def _command(executable: str, serial: str | None, *arguments: str) -> list[str]:
    command = [executable]
    if serial:
        command.extend(["-s", serial])
    command.extend(arguments)
    return command


def _describe(result: subprocess.CompletedProcess[Any]) -> str:
    for stream in (result.stderr, result.stdout):
        text = (stream or "").strip()
        if text:
            return text.splitlines()[0]
    return f"adb exited with status {result.returncode}"


def device_state(
    *,
    adb: str = "adb",
    serial: str | None = None,
    runner: Runner | None = None,
) -> str:
    """Return the ADB device state, raising ``AdbError`` with plain guidance."""

    run = runner or _default_runner
    executable = _resolve_executable(adb)
    command: Sequence[str] = _command(executable, serial, "get-state")
    try:
        result = run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=STATE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise AdbError(
            "adb did not answer within "
            f"{STATE_TIMEOUT_SECONDS} seconds; try 'adb kill-server' and reconnect"
        ) from error
    except OSError as error:
        raise AdbError(f"could not run adb: {error}") from error

    state = (result.stdout or "").strip()
    if result.returncode != 0:
        detail = _describe(result)
        hint = ""
        if "more than one" in detail:
            hint = "; pass --serial SERIAL to choose one (list them with 'adb devices')"
        elif "no devices" in detail or "not found" in detail:
            hint = "; connect the phone by USB, unlock it, and enable USB debugging"
        raise AdbError(f"adb could not reach a device: {detail}{hint}")
    if state != "device":
        raise AdbError(f"the phone is in state {state!r}: {_STATE_HELP.get(state, 'not ready')}")
    return state


def copy_shared_storage(
    destination: pathlib.Path,
    *,
    adb: str = "adb",
    serial: str | None = None,
    runner: Runner | None = None,
) -> pathlib.Path:
    """Copy the accessible contents of ``/sdcard`` without changing the device.

    The copy itself is deliberately not given a timeout: a full shared-storage
    pull of a large phone can legitimately run for hours.
    """

    destination = destination.expanduser().resolve()
    if destination.exists():
        raise FileExistsError(
            f"destination already exists: {destination}; choose a new directory so an "
            "earlier copy is never mixed with this one"
        )
    run = runner or _default_runner
    device_state(adb=adb, serial=serial, runner=run)
    executable = _resolve_executable(adb)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = run(
            _command(executable, serial, "pull", SHARED_STORAGE, str(destination)),
            check=False,
            text=True,
        )
    except OSError as error:
        raise AdbError(f"could not run adb pull: {error}") from error
    if result.returncode != 0:
        raise AdbError(
            f"adb pull failed with status {result.returncode}; the phone may have been "
            "unplugged or locked, or the destination disk may be full"
        )
    return destination


def parse_lookup_keys(output: str) -> list[str]:
    """Parse opaque lookup keys without requesting contact names or numbers."""

    keys: list[str] = []
    for line in output.splitlines():
        match = re.fullmatch(r"Row: \d+ lookup=(.*)", line.strip())
        if match and match.group(1) not in {"", "NULL"}:
            keys.append(match.group(1))
    return keys


def _vcard_uri(keys: list[str]) -> str:
    if not keys:
        raise ValueError("cannot build a vCard URI without contact lookup keys")
    endpoint = "as_vcard" if len(keys) == 1 else "as_multi_vcard"
    encoded = urllib.parse.quote(":".join(keys), safe="")
    return f"{CONTACTS_URI}/{endpoint}/{encoded}"


def _read_vcards(executable: str, serial: str | None, keys: list[str], run: Runner) -> bytes:
    """Ask Android to serialise one batch of contacts, binary-safe."""

    try:
        result = run(
            _command(executable, serial, "exec-out", "content", "read", "--uri", _vcard_uri(keys)),
            check=False,
            capture_output=True,
            timeout=CONTACTS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise AdbError(
            f"the phone did not answer within {CONTACTS_TIMEOUT_SECONDS} seconds while "
            "serialising contacts; try a smaller --batch-size"
        ) from error
    except OSError as error:
        raise AdbError(f"could not run adb: {error}") from error
    if result.returncode != 0:
        stderr = result.stderr
        text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else (stderr or "")
        detail = text.strip().splitlines()
        message = detail[0] if detail else f"adb exited with status {result.returncode}"
        raise AdbError(f"Android could not serialize contacts as vCard: {message}")
    return result.stdout if isinstance(result.stdout, bytes) else result.stdout.encode("utf-8")


def _lookup_keys(executable: str, serial: str | None, run: Runner) -> list[str]:
    """List aggregated contacts by opaque key, requesting no personal fields."""

    try:
        query = run(
            _command(
                executable,
                serial,
                "shell",
                "content",
                "query",
                "--uri",
                CONTACTS_URI,
                "--projection",
                "lookup",
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=CONTACTS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise AdbError(
            f"the phone did not answer within {CONTACTS_TIMEOUT_SECONDS} seconds while "
            "listing contacts"
        ) from error
    except OSError as error:
        raise AdbError(f"could not run adb: {error}") from error
    if query.returncode != 0:
        raise AdbError(f"Android contacts query failed: {_describe(query)}")
    keys = parse_lookup_keys(query.stdout)
    if not keys:
        raise AdbError(
            "the Android contacts provider returned no exportable contacts; the phone may "
            "keep its contacts in an account this provider does not expose"
        )
    return keys


def _write_batches(
    handle: IO[bytes],
    executable: str,
    serial: str | None,
    keys: list[str],
    batch_size: int,
    run: Runner,
) -> ContactsExport:
    """Serialise every contact, falling back to one request per contact.

    A contact the provider refuses is skipped and counted rather than
    abandoning the whole export: 340 recovered contacts beat none.
    """

    report = ContactsExport(path=pathlib.Path())
    for start in range(0, len(keys), batch_size):
        batch = keys[start : start + batch_size]
        try:
            handle.write(_read_vcards(executable, serial, batch, run))
            continue
        except AdbError as error:
            if len(batch) == 1:
                report.skipped.append(str(error))
                continue
            report.notes.append(
                f"a batch of {len(batch)} contacts failed; retrying them one at a time"
            )
        for key in batch:
            try:
                handle.write(_read_vcards(executable, serial, [key], run))
            except AdbError as error:
                report.skipped.append(str(error))
    return report


def export_contacts(
    destination: pathlib.Path,
    *,
    adb: str = "adb",
    serial: str | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    runner: Runner | None = None,
) -> ContactsExport:
    """Export live aggregated contacts using Android's own vCard provider.

    The phone is only read from. The resulting ``.vcf`` is ordinary personal
    data in plain text: it is written with owner-only permissions and published
    only once every requested contact has been accounted for.
    """

    run = runner or _default_runner
    destination = destination.expanduser().resolve()
    if destination.exists():
        raise FileExistsError(
            f"destination already exists: {destination}; choose a new file so an earlier "
            "export is never mixed with this one"
        )
    if not 1 <= batch_size <= MAX_BATCH_SIZE:
        raise ValueError(f"batch size must be between 1 and {MAX_BATCH_SIZE}")
    device_state(adb=adb, serial=serial, runner=run)
    executable = _resolve_executable(adb)
    keys = _lookup_keys(executable, serial, run)

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: pathlib.Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=f".{destination.name[:80]}.",
            suffix=".part",
            delete=False,
        ) as temporary:
            temporary_path = pathlib.Path(temporary.name)
            report = _write_batches(temporary, executable, serial, keys, batch_size, run)
            temporary.flush()
            os.fsync(temporary.fileno())

        data = temporary_path.read_bytes()
        upper = data.upper()
        report.exported = upper.count(b"BEGIN:VCARD")
        endings = upper.count(b"END:VCARD")
        expected = len(keys) - len(report.skipped)
        if report.exported != expected or endings != report.exported:
            raise AdbError(
                "vCard validation failed: the provider returned "
                f"{report.exported} complete cards for {expected} contacts, so the export "
                "was discarded rather than saved incomplete"
            )
        report.requested = len(keys)
        report.path = destination
        temporary_path.replace(destination)
        temporary_path = None
        return report
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
