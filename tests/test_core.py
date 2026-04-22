from __future__ import annotations

import os
from pathlib import Path

import pytest

from dotenv_encrypt import (
    DecryptionError,
    ScryptParams,
    decrypt_bytes,
    encrypt_bytes,
    load_enc_env,
    read_encrypted_env,
    render_env,
    unload_enc_env,
    write_encrypted_env,
)

FAST_KDF = ScryptParams(n=2**10, r=8, p=1)
PASSPHRASE = "correct horse battery staple"  # noqa: S105


def test_encrypted_env_roundtrip_does_not_store_plaintext(tmp_path: Path) -> None:
    path = tmp_path / ".env.enc"
    env = {
        "API_KEY": "super-secret",
        "QUOTED": 'hello "there" \\ friend',
        "MULTILINE": "line one\nline two",
    }

    write_encrypted_env(env, path, PASSPHRASE, kdf_params=FAST_KDF)

    encrypted = path.read_bytes()
    assert b"super-secret" not in encrypted
    assert b"API_KEY" not in encrypted
    assert read_encrypted_env(path, PASSPHRASE) == env


def test_wrong_passphrase_fails_authentication(tmp_path: Path) -> None:
    path = tmp_path / ".env.enc"
    write_encrypted_env({"TOKEN": "abc"}, path, PASSPHRASE, kdf_params=FAST_KDF)

    with pytest.raises(DecryptionError):
        read_encrypted_env(path, "wrong passphrase")


def test_tampered_ciphertext_fails_authentication(tmp_path: Path) -> None:
    path = tmp_path / ".env.enc"
    write_encrypted_env({"TOKEN": "abc"}, path, PASSPHRASE, kdf_params=FAST_KDF)

    encrypted = bytearray(path.read_bytes())
    encrypted[-1] ^= 1
    path.write_bytes(bytes(encrypted))

    with pytest.raises(DecryptionError):
        read_encrypted_env(path, PASSPHRASE)


def test_tampered_authenticated_header_fails_authentication() -> None:
    encrypted = bytearray(
        encrypt_bytes(b"TOKEN=abc\n", PASSPHRASE, kdf_params=FAST_KDF)
    )
    header_len = int.from_bytes(encrypted[8:10], "big")
    header_start = 10
    header_end = header_start + header_len
    encrypted[header_start:header_end] = encrypted[header_start:header_end].replace(
        b'"p":1',
        b'"p":2',
        1,
    )

    with pytest.raises(DecryptionError):
        decrypt_bytes(bytes(encrypted), PASSPHRASE)


def test_load_and_unload_respect_override_flag(tmp_path: Path) -> None:
    path = tmp_path / ".env.enc"
    write_encrypted_env(
        {"EXISTING": "new", "ADDED": "value"},
        path,
        PASSPHRASE,
        kdf_params=FAST_KDF,
    )
    environ = {"EXISTING": "kept"}

    loaded = load_enc_env(path, PASSPHRASE, environ=environ, override=False)

    assert loaded == {"EXISTING": "new", "ADDED": "value"}
    assert environ == {"EXISTING": "kept", "ADDED": "value"}

    unload_enc_env(environ=environ)

    assert environ == {"EXISTING": "kept"}


def test_render_env_rejects_invalid_names() -> None:
    with pytest.raises(ValueError):
        render_env({"1BAD": "value"})


def test_kdf_parameters_are_bounded() -> None:
    with pytest.raises(ValueError, match="no greater"):
        ScryptParams(n=2**21).validate()


def test_file_permissions_are_private_on_posix(tmp_path: Path) -> None:
    path = tmp_path / ".env.enc"
    write_encrypted_env({"TOKEN": "abc"}, path, PASSPHRASE, kdf_params=FAST_KDF)

    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
