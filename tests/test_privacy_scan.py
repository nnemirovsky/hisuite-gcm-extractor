"""The release-time privacy check must actually catch what it claims to."""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

SCANNER = pathlib.Path(__file__).resolve().parent.parent / "tools" / "privacy_scan.py"


def run_scanner(*paths: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCANNER), *(str(path) for path in paths)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("path = '/Users/someone/backups'", "absolute home path"),  # privacy-scan: allow
        ("contact: person@example.org", "email address"),  # privacy-scan: allow
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private key block"),  # privacy-scan: allow
        ("password = 'hunter2hunter2'", "assigned password"),  # privacy-scan: allow
        (f"material = '{'ab' * 48}'", "long hex blob"),  # privacy-scan: allow
        ("imei: 123456789012345", "IMEI-like number"),  # privacy-scan: allow
    ],
)
def test_planted_secrets_are_reported(tmp_path: pathlib.Path, content: str, expected: str) -> None:
    planted = tmp_path / "planted.txt"
    planted.write_text(content, encoding="utf-8")
    result = run_scanner(planted)
    assert result.returncode == 1
    assert expected in result.stdout


def test_clean_file_passes(tmp_path: pathlib.Path) -> None:
    clean = tmp_path / "clean.md"
    clean.write_text("Run `hisuite-gcm inspect ./backup` to list payloads.\n", encoding="utf-8")
    result = run_scanner(clean)
    assert result.returncode == 0
    assert "No private data patterns found" in result.stdout


def in_git_work_tree() -> bool:
    """The default scan asks git for tracked files, so it needs a checkout."""

    result = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
        cwd=SCANNER.parent.parent,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


@pytest.mark.skipif(not in_git_work_tree(), reason="not a git checkout (unpacked sdist)")
def test_the_repository_itself_is_clean() -> None:
    result = subprocess.run(
        [sys.executable, str(SCANNER)],
        capture_output=True,
        text=True,
        check=False,
        cwd=SCANNER.parent.parent,
    )
    assert result.returncode == 0, result.stdout
