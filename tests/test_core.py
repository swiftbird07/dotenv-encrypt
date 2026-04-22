from __future__ import annotations

import os
from pathlib import Path

import pytest

import dotenv_encrypt.core as core
from dotenv_encrypt import (
    DecryptionError,
    InvalidEncryptedFile,
    ScryptParams,
    decrypt_bytes,
    encrypt_bytes,
    encrypt_text,
    load_enc_env,
    read_encrypted_env,
    render_env,
    unload_enc_env,
    write_encrypted_env,
)

FAST_KDF = ScryptParams(n=2**14, r=8, p=1)
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


def test_unversioned_data_is_rejected() -> None:
    with pytest.raises(InvalidEncryptedFile):
        decrypt_bytes(b"not a dotenv-encrypt file", PASSPHRASE)


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


def test_load_rolls_back_values_if_environment_write_fails(tmp_path: Path) -> None:
    class FailingEnvironment(dict[str, str]):
        def __setitem__(self, key: str, value: str) -> None:
            if key == "BAD":
                raise RuntimeError("injected failure")
            super().__setitem__(key, value)

    path = tmp_path / ".env.enc"
    write_encrypted_env(
        {"GOOD": "loaded", "BAD": "boom"},
        path,
        PASSPHRASE,
        kdf_params=FAST_KDF,
    )
    environ = FailingEnvironment({"EXISTING": "kept"})

    with pytest.raises(RuntimeError, match="injected failure"):
        load_enc_env(path, PASSPHRASE, environ=environ)

    assert environ == {"EXISTING": "kept"}


def test_dotenv_interpolation_is_not_expanded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / ".env.enc"
    monkeypatch.setenv("AMBIENT_FOR_TEST", "ambient-value")
    write_encrypted_env(
        {
            "EXPANDS": "${AMBIENT_FOR_TEST}",
            "LITERAL": "x${AMBIENT_FOR_TEST}y",
        },
        path,
        PASSPHRASE,
        kdf_params=FAST_KDF,
    )

    assert read_encrypted_env(path, PASSPHRASE) == {
        "EXPANDS": "${AMBIENT_FOR_TEST}",
        "LITERAL": "x${AMBIENT_FOR_TEST}y",
    }


def test_render_env_rejects_invalid_names() -> None:
    with pytest.raises(ValueError):
        render_env({"1BAD": "value"})


def test_render_env_rejects_nul_values() -> None:
    with pytest.raises(ValueError, match="contains NUL"):
        render_env({"BAD": "contains\x00nul"})


def test_kdf_parameters_reject_weak_and_excessive_values() -> None:
    with pytest.raises(ValueError, match="at least"):
        ScryptParams(n=2**10).validate()
    with pytest.raises(ValueError, match="no greater"):
        ScryptParams(n=2**21).validate()
    with pytest.raises(ValueError, match="no greater"):
        ScryptParams(n=2**14, r=16).validate()


def test_file_write_failure_preserves_existing_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / ".env.enc"
    original = encrypt_text("ORIGINAL=yes\n", PASSPHRASE, kdf_params=FAST_KDF)
    path.write_bytes(original)

    def fail_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(core.os, "replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        write_encrypted_env({"NEW": "value"}, path, PASSPHRASE, kdf_params=FAST_KDF)

    assert path.read_bytes() == original


def test_file_permissions_are_private_on_posix(tmp_path: Path) -> None:
    path = tmp_path / ".env.enc"
    write_encrypted_env({"TOKEN": "abc"}, path, PASSPHRASE, kdf_params=FAST_KDF)

    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_file_write_replaces_symlink_instead_of_following_it(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("symlink replacement semantics are POSIX-specific")

    target = tmp_path / "target.txt"
    link = tmp_path / ".env.enc"
    target.write_text("do-not-clobber", encoding="utf-8")
    link.symlink_to(target)

    write_encrypted_env({"TOKEN": "abc"}, link, PASSPHRASE, kdf_params=FAST_KDF)

    assert not link.is_symlink()
    assert target.read_text(encoding="utf-8") == "do-not-clobber"
    assert read_encrypted_env(link, PASSPHRASE) == {"TOKEN": "abc"}
