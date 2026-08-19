from __future__ import annotations

import pathlib
import subprocess
import urllib.parse

import pytest

from hisuite_gcm import android
from hisuite_gcm.android import (
    CONTACTS_TIMEOUT_SECONDS,
    MAX_BATCH_SIZE,
    AdbError,
    _vcard_uri,
    copy_shared_storage,
    device_state,
    export_contacts,
    parse_lookup_keys,
)

#: An obviously synthetic device identifier.
DEVICE = "R58M12345"


class FakeAdb:
    """Records the argument arrays a caller would have handed to ADB."""

    def __init__(self, *, state: str = "device", state_code: int = 0, pull_code: int = 0) -> None:
        self.state = state
        self.state_code = state_code
        self.pull_code = pull_code
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        if "get-state" in command:
            stdout = self.state if self.state_code == 0 else ""
            stderr = "" if self.state_code == 0 else self.state
            return subprocess.CompletedProcess(command, self.state_code, stdout, stderr)
        return subprocess.CompletedProcess(command, self.pull_code, "", "")


@pytest.fixture
def fake_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend ADB is installed, without touching the machine's real PATH."""

    monkeypatch.setattr(android, "_resolve_executable", lambda name: f"/fake/bin/{name}")


def test_copy_uses_argument_arrays_and_never_a_shell(
    tmp_path: pathlib.Path, fake_executable: None
) -> None:
    runner = FakeAdb()
    destination = copy_shared_storage(tmp_path / "shared", runner=runner)
    assert runner.calls == [
        ["/fake/bin/adb", "get-state"],
        ["/fake/bin/adb", "pull", "/sdcard/.", str(destination)],
    ]
    assert destination == (tmp_path / "shared").resolve()


def test_serial_is_passed_through(tmp_path: pathlib.Path, fake_executable: None) -> None:
    runner = FakeAdb()
    copy_shared_storage(tmp_path / "shared", serial=DEVICE, runner=runner)
    assert runner.calls[0] == [
        "/fake/bin/adb",
        "-s",
        DEVICE,
        "get-state",
    ]
    assert runner.calls[1][:4] == [
        "/fake/bin/adb",
        "-s",
        DEVICE,
        "pull",
    ]


def test_existing_destination_is_refused(tmp_path: pathlib.Path, fake_executable: None) -> None:
    runner = FakeAdb()
    (tmp_path / "shared").mkdir()
    with pytest.raises(FileExistsError, match="already exists"):
        copy_shared_storage(tmp_path / "shared", runner=runner)
    assert runner.calls == []


def test_unauthorized_device_is_explained(tmp_path: pathlib.Path, fake_executable: None) -> None:
    runner = FakeAdb(state="unauthorized")
    with pytest.raises(AdbError, match="accept the USB debugging prompt"):
        copy_shared_storage(tmp_path / "shared", runner=runner)
    assert len(runner.calls) == 1


def test_multiple_devices_suggest_serial(tmp_path: pathlib.Path, fake_executable: None) -> None:
    runner = FakeAdb(state="adb: more than one device/emulator", state_code=1)
    with pytest.raises(AdbError, match="--serial"):
        copy_shared_storage(tmp_path / "shared", runner=runner)


def test_missing_device_is_explained(tmp_path: pathlib.Path, fake_executable: None) -> None:
    runner = FakeAdb(state="error: no devices/emulators found", state_code=1)
    with pytest.raises(AdbError, match="enable USB debugging"):
        copy_shared_storage(tmp_path / "shared", runner=runner)


def test_failed_pull_is_reported(tmp_path: pathlib.Path, fake_executable: None) -> None:
    runner = FakeAdb(pull_code=1)
    with pytest.raises(AdbError, match="adb pull failed"):
        copy_shared_storage(tmp_path / "shared", runner=runner)


def test_state_timeout_is_explained(fake_executable: None) -> None:
    def timeout(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, 30)

    with pytest.raises(AdbError, match="did not answer"):
        device_state(runner=timeout)


def test_missing_adb_executable_is_explained(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(AdbError, match="Android Platform Tools"):
        copy_shared_storage(tmp_path / "shared", runner=FakeAdb())


def test_parse_lookup_keys_ignores_noise_and_nulls() -> None:
    output = "\n".join(
        [
            "Row: 0 lookup=123i456",
            "Row: 1 lookup=encoded/value",
            "Row: 2 lookup=NULL",
            "unrelated diagnostic",
        ]
    )
    assert parse_lookup_keys(output) == ["123i456", "encoded/value"]


def test_vcard_uri_encodes_single_lookup_key() -> None:
    assert _vcard_uri(["a/b c"]) == ("content://com.android.contacts/contacts/as_vcard/a%2Fb%20c")


def test_vcard_uri_encodes_multi_contact_separator() -> None:
    assert _vcard_uri(["one", "two"]) == (
        "content://com.android.contacts/contacts/as_multi_vcard/one%3Atwo"
    )


def test_vcard_uri_requires_keys() -> None:
    with pytest.raises(ValueError, match="without contact lookup keys"):
        _vcard_uri([])


VCARD = b"BEGIN:VCARD\nVERSION:3.0\nFN:Synthetic Person\nEND:VCARD\n"


class FakeContactsAdb:
    """A phone whose contacts provider answers exactly as Android's does."""

    def __init__(self, keys: list[str], *, failing: set[str] | None = None) -> None:
        self.keys = keys
        self.failing = failing or set()
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[object]:
        self.commands.append(command)
        if "get-state" in command:
            return subprocess.CompletedProcess(command, 0, "device", "")
        if "query" in command:
            rows = "\n".join(f"Row: {index} lookup={key}" for index, key in enumerate(self.keys))
            return subprocess.CompletedProcess(command, 0, rows + "\n", "")
        requested = urllib.parse.unquote(command[-1].rsplit("/", 1)[-1]).split(":")
        if any(key in self.failing for key in requested):
            return subprocess.CompletedProcess(command, 1, b"", b"Error: no such contact\n")
        return subprocess.CompletedProcess(command, 0, VCARD * len(requested), b"")


def test_contacts_export_writes_one_card_per_contact(
    tmp_path: pathlib.Path, fake_executable: None
) -> None:
    runner = FakeContactsAdb(["a1", "b2", "c3"])
    report = export_contacts(tmp_path / "contacts.vcf", runner=runner)
    assert report.exported == 3
    assert report.requested == 3
    assert not report.skipped
    assert report.path.read_bytes().count(b"BEGIN:VCARD") == 3
    assert [command[1] for command in runner.commands] == ["get-state", "shell", "exec-out"]


def test_contacts_export_asks_only_for_opaque_keys(
    tmp_path: pathlib.Path, fake_executable: None
) -> None:
    runner = FakeContactsAdb(["a1"])
    export_contacts(tmp_path / "contacts.vcf", runner=runner)
    query = next(command for command in runner.commands if "query" in command)
    assert query[query.index("--projection") + 1] == "lookup"
    assert "display_name" not in query and "data1" not in query


def test_contacts_export_batches_and_falls_back_per_contact(
    tmp_path: pathlib.Path, fake_executable: None
) -> None:
    runner = FakeContactsAdb(["a1", "b2", "c3", "d4"], failing={"c3"})
    report = export_contacts(tmp_path / "contacts.vcf", batch_size=4, runner=runner)
    assert report.exported == 3
    assert report.requested == 4
    assert len(report.skipped) == 1
    assert report.notes
    assert report.path.read_bytes().count(b"BEGIN:VCARD") == 3


def test_contacts_export_refuses_an_existing_destination(
    tmp_path: pathlib.Path, fake_executable: None
) -> None:
    target = tmp_path / "contacts.vcf"
    target.write_bytes(b"earlier export")
    with pytest.raises(FileExistsError, match="already exists"):
        export_contacts(target, runner=FakeContactsAdb(["a1"]))
    assert target.read_bytes() == b"earlier export"


def test_contacts_export_rejects_an_impossible_batch_size(
    tmp_path: pathlib.Path, fake_executable: None
) -> None:
    for size in (0, MAX_BATCH_SIZE + 1):
        with pytest.raises(ValueError, match="batch size must be"):
            export_contacts(tmp_path / "contacts.vcf", batch_size=size, runner=FakeContactsAdb([]))


def test_contacts_export_explains_an_empty_provider(
    tmp_path: pathlib.Path, fake_executable: None
) -> None:
    with pytest.raises(AdbError, match="no exportable contacts"):
        export_contacts(tmp_path / "contacts.vcf", runner=FakeContactsAdb([]))


def test_contacts_export_discards_a_truncated_answer(
    tmp_path: pathlib.Path, fake_executable: None
) -> None:
    class Truncating(FakeContactsAdb):
        def __call__(
            self, command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[object]:
            result = super().__call__(command, **kwargs)
            if "exec-out" in command:
                return subprocess.CompletedProcess(command, 0, b"BEGIN:VCARD\nFN:cut off", b"")
            return result

    destination = tmp_path / "contacts.vcf"
    with pytest.raises(AdbError, match="vCard validation failed"):
        export_contacts(destination, runner=Truncating(["a1"]))
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_contacts_export_times_out_cleanly(tmp_path: pathlib.Path, fake_executable: None) -> None:
    def timeout(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[object]:
        if "get-state" in command:
            return subprocess.CompletedProcess(command, 0, "device", "")
        raise subprocess.TimeoutExpired(command, CONTACTS_TIMEOUT_SECONDS)

    with pytest.raises(AdbError, match="did not answer"):
        export_contacts(tmp_path / "contacts.vcf", runner=timeout)
