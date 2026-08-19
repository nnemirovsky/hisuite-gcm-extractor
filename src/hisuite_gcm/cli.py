"""Command-line interface.

Exit codes:

* ``0`` -- the command finished and every payload it touched succeeded.
* ``1`` -- the command ran, but something it tried to recover failed.
* ``2`` -- the command could not run: bad input, missing device, unsafe paths.
* ``130`` -- interrupted with Ctrl-C.
"""

from __future__ import annotations

import argparse
import getpass
import json
import pathlib
import sys

from . import __version__
from .adapters import Adapter, available_adapters, detect_adapters, find_adapter, open_readonly
from .android import DEFAULT_BATCH_SIZE, AdbError, copy_shared_storage, export_contacts
from .manifest import DEFAULT_MANIFEST_NAME, write_manifest
from .metadata import find_backup, modules_from_info
from .recovery import RecoveryResult, discover, recover

OK = 0
INCOMPLETE = 1
CANNOT_RUN = 2
INTERRUPTED = 130

GENERIC_ADAPTER = "sqlite-tables"

_WRONG_PASSWORD_HELP = """
The password did not authenticate the backup, so nothing was decrypted.

This is what to check, in order:
  1. The password is the one typed into HiSuite when this backup was made,
     not the phone's lock screen PIN and not a Huawei ID password.
  2. Capital letters, keyboard layout, and any leading or trailing space.
  3. That info.xml and the encrypted files come from the same backup folder.

Nothing was written, and the original backup was not modified.
""".strip()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hisuite-gcm",
        description="Recover recent Huawei HiSuite AES-GCM backups.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    inspect = commands.add_parser("inspect", help="list recoverable encrypted payloads")
    inspect.add_argument("backup", type=pathlib.Path)
    inspect.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    extract = commands.add_parser(
        "extract",
        help="authenticate, decrypt, and optionally expand payloads",
    )
    extract.add_argument("backup", type=pathlib.Path)
    extract.add_argument("destination", type=pathlib.Path)
    extract.add_argument(
        "--no-expand",
        action="store_true",
        help="keep decrypted TARs without expanding them",
    )
    extract.add_argument(
        "--no-keep-tars",
        action="store_true",
        help="delete each decrypted TAR once it has been expanded, to save disk space",
    )
    extract.add_argument(
        "--password-stdin",
        action="store_true",
        help="read one password line from standard input (for controlled automation)",
    )

    shared = commands.add_parser("copy-shared", help="copy accessible /sdcard data through ADB")
    shared.add_argument("destination", type=pathlib.Path)
    shared.add_argument("--adb", default="adb", help="ADB executable name or path")
    shared.add_argument("--serial", help="ADB device serial when multiple devices are connected")

    contacts = commands.add_parser(
        "export-contacts",
        help="export live aggregated contacts to vCard through ADB",
    )
    contacts.add_argument("destination", type=pathlib.Path)
    contacts.add_argument("--adb", default="adb", help="ADB executable name or path")
    contacts.add_argument("--serial", help="ADB device serial when multiple devices are connected")
    contacts.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"contacts per provider request (default: {DEFAULT_BATCH_SIZE})",
    )

    manifest = commands.add_parser("manifest", help="write a SHA-256 manifest for a directory tree")
    manifest.add_argument("root", type=pathlib.Path)
    manifest.add_argument("--output", default=DEFAULT_MANIFEST_NAME)

    adapters = commands.add_parser("adapters", help="list human-readable export adapters")
    adapters.add_argument(
        "database",
        nargs="?",
        type=pathlib.Path,
        help="optional database to test each adapter against",
    )
    adapters.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    export = commands.add_parser("export", help="write a readable export of a recovered database")
    export.add_argument("database", type=pathlib.Path)
    export.add_argument("destination", type=pathlib.Path)
    export.add_argument("--adapter", help="adapter name; omit to detect automatically")
    return parser


def _password(from_stdin: bool) -> bytes:
    if from_stdin:
        stream = getattr(sys.stdin, "buffer", None)
        line = stream.readline() if stream is not None else sys.stdin.readline().encode("utf-8")
        if not line:
            raise ValueError("no password received on standard input")
        if line.endswith(b"\n"):
            line = line[:-1]
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line:
            raise ValueError("the password read from standard input was empty")
        return line
    try:
        entered = getpass.getpass("HiSuite backup password (hidden): ")
    except EOFError as error:
        raise ValueError(
            "no terminal is available to read the password; use --password-stdin"
        ) from error
    if not entered:
        raise ValueError("no password entered")
    return entered.encode("utf-8")


def _adapter_rows(database: pathlib.Path | None) -> list[dict[str, str | bool | None]]:
    adapters = available_adapters()
    if database is None:
        return [
            {"name": item.name, "summary": item.summary, "supports": item.supports}
            for item in adapters
        ]
    return [
        {
            "name": adapter.name,
            "summary": adapter.summary,
            "supports": adapter.supports,
            "detected": bool(result),
            "reason": result.reason,
        }
        for adapter, result in detect_adapters(database, adapters=adapters)
    ]


def _choose_adapter(database: pathlib.Path) -> tuple[Adapter, str]:
    detected = [(adapter, result) for adapter, result in detect_adapters(database) if result]
    specific = [pair for pair in detected if pair[0].name != GENERIC_ADAPTER]
    for adapter, result in specific or detected:
        return adapter, result.reason
    raise ValueError(
        f"no adapter recognises {database}; run 'hisuite-gcm adapters {database}' to see why"
    )


def _report_recovery(result: RecoveryResult) -> int:
    if result.password_failed:
        sys.stdout.flush()
        print(_WRONG_PASSWORD_HELP, file=sys.stderr)
        return INCOMPLETE
    print(f"Authenticated payloads decrypted: {result.decrypted}")
    print(f"App-data files safely extracted:  {result.extracted_files}")
    if result.skipped_special:
        print(f"Links and devices not extracted:  {result.skipped_special}")
    for note in result.notes:
        print(f"note: {note}")
    if result.failures:
        sys.stdout.flush()
        print(f"\nFailures: {len(result.failures)}", file=sys.stderr)
        for failure in result.failures[:20]:
            print(f"  {failure}", file=sys.stderr)
        if len(result.failures) > 20:
            print(f"  ... and {len(result.failures) - 20} more", file=sys.stderr)
        return INCOMPLETE
    return OK


def _inspect(args: argparse.Namespace) -> int:
    backup = find_backup(args.backup)
    modules = modules_from_info(backup / "info.xml")
    payloads = discover(backup)
    result = {
        "tool_version": __version__,
        "backup": str(backup),
        "modules_with_crypto_metadata": len(modules),
        "encrypted_bytes": sum(payload.size for payload in payloads),
        "payloads": [
            {
                "module": payload.module.name,
                "kind": payload.kind,
                "path": payload.source.relative_to(backup).as_posix(),
                "bytes": payload.size,
            }
            for payload in payloads
        ],
    }
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return OK
    print(f"Backup: {backup}")
    print(f"Modules with encryption metadata: {len(modules)}")
    print(f"Recoverable payloads found: {len(payloads)}")
    for payload in payloads:
        relative = payload.source.relative_to(backup).as_posix()
        print(f"  {payload.kind:9} {payload.module.name}: {relative} ({payload.size} bytes)")
    if payloads:
        print("\nRun 'hisuite-gcm extract' with this backup to decrypt them.")
    else:
        print("\nNo encrypted payloads matched the modules listed in info.xml.")
    return OK


def _extract(args: argparse.Namespace) -> int:
    if args.no_expand and args.no_keep_tars:
        raise ValueError("--no-expand and --no-keep-tars together would discard everything")
    backup = find_backup(args.backup)
    result = recover(
        backup,
        args.destination,
        _password(args.password_stdin),
        expand_tars=not args.no_expand,
        keep_tars=not args.no_keep_tars,
        progress=print,
    )
    return _report_recovery(result)


def _export_contacts(args: argparse.Namespace) -> int:
    report = export_contacts(
        args.destination,
        adb=args.adb,
        serial=args.serial,
        batch_size=args.batch_size,
    )
    print(f"Contacts exported: {report.exported} of {report.requested}")
    print(f"vCard written: {report.path}")
    for note in report.notes:
        print(f"note: {note}")
    if report.skipped:
        sys.stdout.flush()
        print(f"{len(report.skipped)} contact(s) could not be exported:", file=sys.stderr)
        for message in report.skipped[:10]:
            print(f"  {message}", file=sys.stderr)
        if len(report.skipped) > 10:
            print(f"  ... and {len(report.skipped) - 10} more", file=sys.stderr)
        return INCOMPLETE
    return OK


def _adapters(args: argparse.Namespace) -> int:
    rows = _adapter_rows(args.database)
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return OK
    for row in rows:
        mark = "" if "detected" not in row else ("  [matches]" if row["detected"] else "")
        print(f"{row['name']}{mark}\n  {row['summary']}\n  supports: {row['supports']}")
        if "reason" in row:
            print(f"  detection: {row['reason']}")
    return OK


def _export(args: argparse.Namespace) -> int:
    destination = args.destination.expanduser().resolve()
    if destination.exists():
        raise FileExistsError(f"destination already exists: {destination}")
    if args.adapter:
        adapter = find_adapter(args.adapter)
        reason = "selected on the command line"
    else:
        adapter, reason = _choose_adapter(args.database)
    print(f"Adapter: {adapter.name} ({reason})")
    connection = open_readonly(args.database)
    try:
        result = adapter.export(connection, destination)
    finally:
        connection.close()
    print(f"Files written: {len(result.files)}")
    print(f"Rows exported: {result.rows}")
    if result.warnings:
        sys.stdout.flush()
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return INCOMPLETE if result.warnings else OK


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "inspect":
        return _inspect(args)
    if args.command == "extract":
        return _extract(args)
    if args.command == "copy-shared":
        destination = copy_shared_storage(args.destination, adb=args.adb, serial=args.serial)
        print(f"Shared storage copied to: {destination}")
        return OK
    if args.command == "export-contacts":
        return _export_contacts(args)
    if args.command == "manifest":
        result = write_manifest(args.root, args.output)
        print(f"Manifest written: {result.path} ({result.files} files)")
        if result.skipped:
            sys.stdout.flush()
        for skipped in result.skipped:
            print(f"skipped: {skipped}", file=sys.stderr)
        return INCOMPLETE if result.skipped else OK
    if args.command == "adapters":
        return _adapters(args)
    if args.command == "export":
        return _export(args)
    raise ValueError(f"unknown command: {args.command}")  # pragma: no cover - argparse guards this


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _dispatch(args)
    except KeyboardInterrupt:
        print("\ninterrupted; nothing further was written", file=sys.stderr)
        return INTERRUPTED
    except BrokenPipeError:  # pragma: no cover - depends on the reading process
        return OK
    except (AdbError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return CANNOT_RUN


if __name__ == "__main__":
    raise SystemExit(main())
