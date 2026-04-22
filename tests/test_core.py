from __future__ import annotations

import hashlib
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dotenv_encrypt import (
    PASSPHRASE_ENV,
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
from dotenv_encrypt.cli import main as cli_main

FAST_KDF = ScryptParams(n=2**10, r=8, p=1)
PASSPHRASE = "correct horse battery staple"  # noqa: S105
LEGACY_SALT = b"C9A73747FDAC9945E2ADC3"


def test_encrypted_env_roundtrip_does_not_store_plaintext(tmp_path):
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


def test_wrong_passphrase_fails_authentication(tmp_path):
    path = tmp_path / ".env.enc"
    write_encrypted_env({"TOKEN": "abc"}, path, PASSPHRASE, kdf_params=FAST_KDF)

    with pytest.raises(DecryptionError):
        read_encrypted_env(path, "wrong passphrase")


def test_tampered_ciphertext_fails_authentication(tmp_path):
    path = tmp_path / ".env.enc"
    write_encrypted_env({"TOKEN": "abc"}, path, PASSPHRASE, kdf_params=FAST_KDF)

    encrypted = bytearray(path.read_bytes())
    encrypted[-1] ^= 1
    path.write_bytes(bytes(encrypted))

    with pytest.raises(DecryptionError):
        read_encrypted_env(path, PASSPHRASE)


def test_tampered_authenticated_header_fails_authentication():
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


def test_load_and_unload_respect_override_flag(tmp_path):
    path = tmp_path / ".env.enc"
    write_encrypted_env(
        {"EXISTING": "new", "ADDED": "value"},
        path,
        PASSPHRASE,
        kdf_params=FAST_KDF,
    )
    environ = {"EXISTING": "old"}

    loaded = load_enc_env(path, PASSPHRASE, environ=environ, override=False)

    assert loaded == {"EXISTING": "new", "ADDED": "value"}
    assert environ == {"EXISTING": "old", "ADDED": "value"}

    unload_enc_env(environ=environ)

    assert environ == {"EXISTING": "old"}


def test_render_env_rejects_invalid_names():
    with pytest.raises(ValueError):
        render_env({"1BAD": "value"})


def test_kdf_parameters_are_bounded():
    with pytest.raises(ValueError, match="no greater"):
        ScryptParams(n=2**21).validate()


def test_file_permissions_are_private_on_posix(tmp_path):
    path = tmp_path / ".env.enc"
    write_encrypted_env({"TOKEN": "abc"}, path, PASSPHRASE, kdf_params=FAST_KDF)

    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_legacy_original_script_format_can_be_read(tmp_path):
    key = hashlib.scrypt(
        PASSPHRASE.encode("utf-8"),
        salt=LEGACY_SALT,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    nonce = b"1" * 12
    ciphertext = AESGCM(key).encrypt(nonce, b"LEGACY=yes\n", None)
    path = tmp_path / ".env.enc"
    path.write_bytes(nonce + ciphertext)

    assert read_encrypted_env(path, PASSPHRASE) == {"LEGACY": "yes"}


def test_cli_encrypt_show_set_and_unset(tmp_path, monkeypatch, capsys):
    plaintext = tmp_path / ".env"
    encrypted = tmp_path / ".env.enc"
    plaintext.write_text("ALPHA=one\n", encoding="utf-8")
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)

    assert cli_main(["encrypt", str(plaintext), "-o", str(encrypted)]) == 0
    assert cli_main(["show", str(encrypted)]) == 0
    output = capsys.readouterr().out
    assert "ALPHA\n" in output
    assert "one" not in output

    assert cli_main(["set", "BRAVO", "two", str(encrypted)]) == 0
    assert read_encrypted_env(encrypted, PASSPHRASE) == {
        "ALPHA": "one",
        "BRAVO": "two",
    }

    assert cli_main(["unset", "ALPHA", str(encrypted)]) == 0
    assert read_encrypted_env(encrypted, PASSPHRASE) == {"BRAVO": "two"}
