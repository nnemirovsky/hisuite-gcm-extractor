"""Synthetic fixtures.

Every byte used by the tests is generated here. No real backup, database,
password, or device identifier appears anywhere in this repository.
"""

from __future__ import annotations

import io
import pathlib
import tarfile
from collections.abc import Iterable, Mapping, Sequence

import pytest
from Crypto.Cipher import AES

from hisuite_gcm.crypto import TAG_SIZE, derive_key_and_nonce

PASSWORD = b"correct horse battery staple"
WRONG_PASSWORD = b"not the password"

#: Two distinct, obviously synthetic 48-byte key materials.
MATERIAL_A = bytes(range(48)).hex()
MATERIAL_B = bytes(range(48, 96)).hex()


def info_xml(rows: Sequence[Mapping[str, str]]) -> str:
    """Render an ``info.xml`` from plain column/value mappings."""

    body = []
    for row in rows:
        columns = "".join(
            f"<column name='{name}'><value value='{value}'/></column>"
            for name, value in row.items()
        )
        body.append(f"<row table='modules'>{columns}</row>")
    return f"<?xml version='1.0' encoding='utf-8'?><root>{''.join(body)}</root>"


def write_info(path: pathlib.Path, rows: Sequence[Mapping[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(info_xml(rows), encoding="utf-8")


def tar_bytes(entries: Mapping[str, bytes] | None = None) -> bytes:
    """Build an uncompressed TAR holding regular files."""

    entries = entries or {"files/hello.txt": b"hello from a synthetic backup\n"}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, content in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def tar_with_members(path: pathlib.Path, members: Iterable[tarfile.TarInfo]) -> None:
    """Write a TAR containing exactly the members given, links included."""

    with tarfile.open(path, "w") as archive:
        for member in members:
            if member.isreg():
                payload = b"x" * member.size
                archive.addfile(member, io.BytesIO(payload))
            else:
                archive.addfile(member)


def encrypt(
    path: pathlib.Path,
    plaintext: bytes,
    material: str = MATERIAL_A,
    password: bytes = PASSWORD,
) -> pathlib.Path:
    """Write ``ciphertext || tag`` exactly as an observed payload is laid out."""

    key, nonce = derive_key_and_nonce(password, material)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ciphertext + tag)
    return path


def sqlite_payload(extra: bytes = b"") -> bytes:
    """Plaintext that ``payload_kind`` should report as SQLite."""

    return b"SQLite format 3\x00" + bytes(256) + extra


@pytest.fixture
def backup(tmp_path: pathlib.Path) -> pathlib.Path:
    """A one-module backup with an encrypted database and one app-data TAR."""

    root = tmp_path / "HUAWEI Phone_2026-01-01"
    module = "com.example.memories"
    write_info(root / "info.xml", [{"packageName": module, "encMsgV3": MATERIAL_A}])
    encrypt(root / f"{module}.db", sqlite_payload())
    encrypt(root / f"{module}_appDataTar" / "data.tar", tar_bytes())
    return root
