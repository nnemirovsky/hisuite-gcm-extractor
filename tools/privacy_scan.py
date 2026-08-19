#!/usr/bin/env python3
"""Scan repository files for private data before publishing.

This project is published from a machine that also holds real family backups,
so the release checklist runs a mechanical check for the categories of leak
that matter here: absolute home paths, contact details, device identifiers,
key material, and anything that looks like a real credential.

Usage::

    python3 tools/privacy_scan.py            # every tracked file
    python3 tools/privacy_scan.py PATH ...   # specific files

Exit status is 0 when nothing is found and 1 when something needs a human
decision. Findings are printed with the file, line number, and the matched
text truncated, never the whole line.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
from collections.abc import Iterable, Iterator

MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".pdf", ".whl", ".gz", ".tar", ".db"})

Finding = tuple[pathlib.Path, int, str, str]

#: (rule name, pattern). Patterns stay narrow so the check is worth running.
RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("absolute home path", re.compile(r"(?:/Users/|/home/|C:\\\\Users\\\\)[A-Za-z0-9._-]+")),
    ("temporary path", re.compile(r"/private/var/folders/[A-Za-z0-9._/-]+")),
    ("email address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("IMEI-like number", re.compile(r"\b\d{15}\b")),
    ("long hex blob", re.compile(r"\b[0-9a-fA-F]{64,}\b")),
    (
        "assigned password",
        re.compile(r"(?i)\b(?:password|passphrase|secret|token)\s*=\s*['\"][^'\"]{6,}"),
    ),
    ("device serial hint", re.compile(r"(?i)\b(?:serial|imei|udid)\s*[:=]\s*['\"]?[A-Z0-9]{8,}")),
    ("wifi or vpn config", re.compile(r"(?i)\b(?:wg0|openvpn|shadowsocks|psk)\b\s*[:=]")),
)

#: A line carrying this marker is skipped. Use it only for text that is
#: deliberately fake, and keep the marker on the same line as the text so a
#: reviewer sees both the claim and the evidence at once.
ALLOW_MARKER = "privacy-scan: allow"


def tracked_files() -> list[pathlib.Path]:
    output = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [pathlib.Path(name) for name in output.split("\0") if name]


def scan_text(path: pathlib.Path, text: str) -> Iterator[Finding]:
    for number, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        for name, pattern in RULES:
            match = pattern.search(line)
            if match:
                excerpt = match.group(0)
                yield path, number, name, excerpt[:60]


def scan(paths: Iterable[pathlib.Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        if path.suffix.lower() in SKIP_SUFFIXES or not path.is_file():
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        findings.extend(scan_text(path, text))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan files for private data.")
    parser.add_argument("paths", nargs="*", type=pathlib.Path)
    arguments = parser.parse_args(argv)
    paths = arguments.paths or tracked_files()
    findings = scan(paths)
    for path, number, name, excerpt in findings:
        print(f"{path}:{number}: {name}: {excerpt}")
    if findings:
        print(f"\n{len(findings)} item(s) need a human decision before publishing.")
        return 1
    print(f"No private data patterns found in {len(list(paths))} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
