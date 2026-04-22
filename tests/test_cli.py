from __future__ import annotations

import os
from pathlib import Path

from pytest import CaptureFixture, MonkeyPatch

from dotenv_encrypt import (
    PASSPHRASE_ENV,
    load_enc_env,
    read_encrypted_env,
    unload_enc_env,
)
from dotenv_encrypt.cli import main as cli_main

PASSPHRASE = "correct horse battery staple"  # noqa: S105


def test_cli_encrypt_show_set_and_unset(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
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


def test_e2e_encrypt_delete_plaintext_and_load_env(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    plaintext = tmp_path / ".env"
    encrypted = tmp_path / ".env.enc"
    plaintext_content = (
        "DOTENV_ENCRYPT_E2E_VALUE=usable-value\n"
        "DOTENV_ENCRYPT_E2E_FLAG=yes\n"
    )
    plaintext.write_text(plaintext_content, encoding="utf-8")
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    monkeypatch.delenv("DOTENV_ENCRYPT_E2E_VALUE", raising=False)
    monkeypatch.delenv("DOTENV_ENCRYPT_E2E_FLAG", raising=False)

    assert (
        cli_main(
            [
                "encrypt",
                str(plaintext),
                "-o",
                str(encrypted),
                "--delete-plaintext",
            ]
        )
        == 0
    )

    assert not plaintext.exists()
    assert encrypted.exists()
    encrypted_bytes = encrypted.read_bytes()
    assert encrypted_bytes != plaintext_content.encode("utf-8")
    assert b"DOTENV_ENCRYPT_E2E_VALUE" not in encrypted_bytes
    assert b"usable-value" not in encrypted_bytes

    plaintext.write_text(plaintext_content, encoding="utf-8")
    second_encrypted = tmp_path / ".env.second.enc"
    assert (
        cli_main(
            [
                "encrypt",
                str(plaintext),
                "-o",
                str(second_encrypted),
                "--delete-plaintext",
            ]
        )
        == 0
    )
    assert second_encrypted.read_bytes() != encrypted_bytes

    loaded = load_enc_env(encrypted, PASSPHRASE)

    assert loaded["DOTENV_ENCRYPT_E2E_VALUE"] == "usable-value"
    assert os.environ["DOTENV_ENCRYPT_E2E_VALUE"] == "usable-value"
    assert os.getenv("DOTENV_ENCRYPT_E2E_FLAG") == "yes"

    unload_enc_env()
    assert "DOTENV_ENCRYPT_E2E_VALUE" not in os.environ
    assert "DOTENV_ENCRYPT_E2E_FLAG" not in os.environ
