from __future__ import annotations

import pathlib

import pytest
from conftest import MATERIAL_A, PASSWORD, WRONG_PASSWORD, encrypt

from hisuite_gcm.crypto import (
    ITERATIONS,
    TAG_SIZE,
    AuthenticationError,
    decrypt_file,
    derive_key_and_nonce,
    is_valid_material,
    verify_file,
)


def test_material_validation_rejects_wrong_length_and_characters() -> None:
    assert is_valid_material(MATERIAL_A)
    assert not is_valid_material(MATERIAL_A[:-1])
    assert not is_valid_material("z" * 96)
    assert not is_valid_material("")


def test_derive_key_and_nonce_shape_and_determinism() -> None:
    key, nonce = derive_key_and_nonce(PASSWORD, MATERIAL_A)
    again, _ = derive_key_and_nonce(PASSWORD, MATERIAL_A)
    assert len(key) == 32
    assert len(nonce) == 16
    assert nonce == bytes.fromhex(MATERIAL_A)[32:]
    assert key == again
    assert derive_key_and_nonce(WRONG_PASSWORD, MATERIAL_A)[0] != key
    assert ITERATIONS == 5000


def test_derive_key_rejects_malformed_material() -> None:
    with pytest.raises(ValueError, match="hexadecimal"):
        derive_key_and_nonce(PASSWORD, "00" * 47)


def test_round_trip_publishes_plaintext(tmp_path: pathlib.Path) -> None:
    source = encrypt(tmp_path / "payload.enc", b"private but synthetic")
    key, nonce = derive_key_and_nonce(PASSWORD, MATERIAL_A)
    destination = tmp_path / "out" / "payload"
    decrypt_file(source, destination, key, nonce)
    assert destination.read_bytes() == b"private but synthetic"
    assert not list(destination.parent.glob(".*"))


def test_empty_payload_is_still_authenticated(tmp_path: pathlib.Path) -> None:
    source = encrypt(tmp_path / "empty.enc", b"")
    key, nonce = derive_key_and_nonce(PASSWORD, MATERIAL_A)
    destination = tmp_path / "empty"
    decrypt_file(source, destination, key, nonce)
    assert destination.read_bytes() == b""


def test_corrupted_tag_never_publishes_plaintext(tmp_path: pathlib.Path) -> None:
    source = encrypt(tmp_path / "payload.enc", b"a" * 4096)
    data = bytearray(source.read_bytes())
    data[-1] ^= 0xFF
    source.write_bytes(bytes(data))
    key, nonce = derive_key_and_nonce(PASSWORD, MATERIAL_A)
    destination = tmp_path / "out" / "payload"
    with pytest.raises(AuthenticationError, match="authentication failed"):
        decrypt_file(source, destination, key, nonce)
    assert not destination.exists()
    assert list(destination.parent.iterdir()) == []


def test_corrupted_ciphertext_never_publishes_plaintext(tmp_path: pathlib.Path) -> None:
    source = encrypt(tmp_path / "payload.enc", b"b" * 4096)
    data = bytearray(source.read_bytes())
    data[0] ^= 0xFF
    source.write_bytes(bytes(data))
    key, nonce = derive_key_and_nonce(PASSWORD, MATERIAL_A)
    destination = tmp_path / "out" / "payload"
    with pytest.raises(AuthenticationError):
        decrypt_file(source, destination, key, nonce)
    assert not destination.exists()


def test_truncated_payload_is_rejected(tmp_path: pathlib.Path) -> None:
    source = encrypt(tmp_path / "payload.enc", b"c" * 4096)
    source.write_bytes(source.read_bytes()[:-4])
    key, nonce = derive_key_and_nonce(PASSWORD, MATERIAL_A)
    destination = tmp_path / "out" / "payload"
    with pytest.raises(AuthenticationError):
        decrypt_file(source, destination, key, nonce)
    assert not destination.exists()


def test_payload_shorter_than_the_tag_is_rejected(tmp_path: pathlib.Path) -> None:
    source = tmp_path / "stub.enc"
    source.write_bytes(bytes(TAG_SIZE - 1))
    key, nonce = derive_key_and_nonce(PASSWORD, MATERIAL_A)
    with pytest.raises(ValueError, match="too short"):
        decrypt_file(source, tmp_path / "out" / "stub", key, nonce)


def test_wrong_password_leaves_no_temporary_files(tmp_path: pathlib.Path) -> None:
    source = encrypt(tmp_path / "payload.enc", b"d" * 100_000)
    key, nonce = derive_key_and_nonce(WRONG_PASSWORD, MATERIAL_A)
    destination = tmp_path / "out" / "payload"
    with pytest.raises(AuthenticationError):
        decrypt_file(source, destination, key, nonce)
    assert list(destination.parent.iterdir()) == []


def test_verify_file_authenticates_without_writing(tmp_path: pathlib.Path) -> None:
    source = encrypt(tmp_path / "payload.enc", b"e" * 1000)
    good = derive_key_and_nonce(PASSWORD, MATERIAL_A)
    bad = derive_key_and_nonce(WRONG_PASSWORD, MATERIAL_A)
    verify_file(source, *good)
    with pytest.raises(AuthenticationError):
        verify_file(source, *bad)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["payload.enc"]


def test_decrypt_overwrites_only_after_authentication(tmp_path: pathlib.Path) -> None:
    source = encrypt(tmp_path / "payload.enc", b"fresh plaintext")
    destination = tmp_path / "existing"
    destination.write_bytes(b"earlier contents")
    key, nonce = derive_key_and_nonce(WRONG_PASSWORD, MATERIAL_A)
    with pytest.raises(AuthenticationError):
        decrypt_file(source, destination, key, nonce)
    assert destination.read_bytes() == b"earlier contents"
