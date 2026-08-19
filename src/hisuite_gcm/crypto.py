"""Streaming authenticated decryption for recent HiSuite payloads.

The observed Security V3 payload is ``ciphertext || 16-byte GCM tag`` with no
additional authenticated data. Nothing here ever falls back to an
unauthenticated cipher: a payload is either verified or it is discarded.
"""

from __future__ import annotations

import contextlib
import os
import pathlib
import string
import tempfile
from collections.abc import Callable

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2

#: Length of the trailing AES-GCM authentication tag, in bytes.
TAG_SIZE = 16
#: Bytes of ``encMsgV3`` used as the PBKDF2 salt.
SALT_SIZE = 32
#: Bytes of ``encMsgV3`` used as the AES-GCM nonce.
NONCE_SIZE = 16
#: Total decoded length of ``encMsgV3``.
MATERIAL_SIZE = SALT_SIZE + NONCE_SIZE
#: PBKDF2-HMAC-SHA256 iteration count observed in Security V3 metadata.
ITERATIONS = 5000
#: Derived AES key length, in bytes.
KEY_SIZE = 32

CHUNK_SIZE = 8 * 1024 * 1024

_HEX_DIGITS = frozenset(string.hexdigits)


class AuthenticationError(ValueError):
    """The password, metadata, or encrypted payload failed authentication."""


def _prf(password: bytes, salt: bytes) -> bytes:
    return HMAC.new(password, salt, SHA256).digest()


def is_valid_material(value: str) -> bool:
    """Return whether ``value`` looks like a 48-byte hexadecimal ``encMsgV3``."""

    return len(value) == MATERIAL_SIZE * 2 and all(character in _HEX_DIGITS for character in value)


def derive_key_and_nonce(password: bytes, enc_msg_v3: str) -> tuple[bytes, bytes]:
    """Derive the AES-GCM key and nonce from a password and ``encMsgV3``."""

    if not is_valid_material(enc_msg_v3):
        raise ValueError(
            f"encMsgV3 must be {MATERIAL_SIZE * 2} hexadecimal characters "
            f"({MATERIAL_SIZE} bytes), got {len(enc_msg_v3)} characters"
        )
    material = bytes.fromhex(enc_msg_v3)
    # PyCryptodome accepts a bytes password and a two-argument PRF at runtime;
    # its bundled stubs describe only the narrower str/one-argument form.
    key: bytes = PBKDF2(
        password,  # type: ignore[arg-type]
        material[:SALT_SIZE],
        KEY_SIZE,
        count=ITERATIONS,
        prf=_prf,  # type: ignore[arg-type]
    )
    return key, material[SALT_SIZE:]


def _stream(
    source: pathlib.Path,
    key: bytes,
    nonce: bytes,
    write: Callable[[bytes], object],
) -> None:
    """Decrypt ``source`` chunk by chunk and verify its trailing GCM tag."""

    size = source.stat().st_size
    if size < TAG_SIZE:
        raise ValueError(f"encrypted payload is too short to hold a GCM tag: {source}")
    with source.open("rb") as encrypted:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
        remaining = size - TAG_SIZE
        while remaining:
            chunk = encrypted.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise OSError(f"unexpected end of encrypted file: {source}")
            write(cipher.decrypt(chunk))
            remaining -= len(chunk)
        tag = encrypted.read(TAG_SIZE)
        if len(tag) != TAG_SIZE:
            raise OSError(f"missing GCM authentication tag: {source}")
        try:
            cipher.verify(tag)
        except ValueError as error:
            raise AuthenticationError(f"authentication failed: {source}") from error


def verify_file(source: pathlib.Path, key: bytes, nonce: bytes) -> None:
    """Authenticate ``source`` without writing any plaintext to disk."""

    _stream(source, key, nonce, lambda _plaintext: None)


def _sync_directory(directory: pathlib.Path) -> None:
    """Best-effort durability for the rename itself; unsupported on Windows."""

    with contextlib.suppress(OSError, AttributeError):
        handle = os.open(directory, getattr(os, "O_DIRECTORY", os.O_RDONLY))
        try:
            os.fsync(handle)
        finally:
            os.close(handle)


def decrypt_file(
    source: pathlib.Path,
    destination: pathlib.Path,
    key: bytes,
    nonce: bytes,
) -> None:
    """Decrypt to a temporary file and publish it only after GCM verification.

    The temporary file is created in the destination directory with
    owner-only permissions, so a failed or interrupted run never leaves
    unauthenticated plaintext at the final path.
    """

    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path: pathlib.Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=f".{destination.name[:80]}.",
            suffix=".part",
            delete=False,
        ) as temporary:
            temp_path = pathlib.Path(temporary.name)
            _stream(source, key, nonce, temporary.write)
            temporary.flush()
            os.fsync(temporary.fileno())
        temp_path.replace(destination)
        _sync_directory(destination.parent)
        temp_path = None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
