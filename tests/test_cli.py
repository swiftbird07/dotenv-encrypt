from __future__ import annotations

import builtins
import os
from pathlib import Path

import pytest
from pytest import CaptureFixture, MonkeyPatch

from dotenv_encrypt import (
    PASSPHRASE_ENV,
    load_enc_env,
    read_encrypted_env,
    unload_enc_env,
)
from dotenv_encrypt.cli import main as cli_main

PASSPHRASE = "correct horse battery staple"  # noqa: S105


def _answer_no(_prompt: str) -> str:
    print(_prompt, end="")
    return "n"


def _answer_yes(_prompt: str) -> str:
    print(_prompt, end="")
    return "yes"


def _raise_keyboard_interrupt(_prompt: str) -> str:
    raise KeyboardInterrupt


def _return_passphrase(_prompt: str) -> str:
    print(_prompt, end="")
    return PASSPHRASE


def test_cli_without_args_prints_help(capsys: CaptureFixture[str]) -> None:
    assert cli_main([]) == 0

    output = capsys.readouterr().out
    assert "Encrypt, inspect, and update .env.enc files." in output
    assert "encrypt" in output
    assert "show" in output


def test_cli_help_can_show_subcommand_help(capsys: CaptureFixture[str]) -> None:
    assert cli_main(["help", "show"]) == 0

    output = capsys.readouterr().out
    assert "--full" in output
    assert "print full secret values" in output


def test_cli_unknown_subcommand_argument_prints_subcommand_help(
    capsys: CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli_main(["decrypt", "--unknown"])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "usage: dotenv-encrypt decrypt" in error
    assert "{encrypt,decrypt,show,set,unset,merge}" not in error
    assert "unrecognized arguments: --unknown" in error


def test_cli_help_explains_merge_defaults(capsys: CaptureFixture[str]) -> None:
    assert cli_main(["help", "merge"]) == 0

    output = capsys.readouterr().out
    assert "PLAIN_ENV" in output
    assert "plaintext dotenv file with new or updated variables" in output
    assert "ENV_ENC_FILE" in output
    assert "Example: dotenv-encrypt merge .env .env.enc" in output


def test_cli_argument_error_prints_full_subcommand_help(
    capsys: CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli_main(["set"])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "usage: dotenv-encrypt set" in error
    assert "positional arguments:" in error
    assert "KEY" in error
    assert "VALUE" in error
    assert "ENV_ENC_FILE" in error
    assert "options:" in error
    assert "the following arguments are required: KEY, VALUE" in error


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
    assert "ALPHA=...\n" in output
    assert "one" not in output

    assert cli_main(["show", str(encrypted), "--full"]) == 0
    output = capsys.readouterr().out
    assert "ALPHA=one\n" in output

    assert cli_main(["set", "BRAVO", "two", str(encrypted)]) == 0
    assert read_encrypted_env(encrypted, PASSPHRASE) == {
        "ALPHA": "one",
        "BRAVO": "two",
    }

    assert cli_main(["unset", "ALPHA", str(encrypted)]) == 0
    assert read_encrypted_env(encrypted, PASSPHRASE) == {"BRAVO": "two"}


def test_cli_encrypt_refuses_existing_output_without_confirmation(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    plaintext = tmp_path / ".env"
    encrypted = tmp_path / ".env.enc"
    plaintext.write_text("TOKEN=new\n", encoding="utf-8")
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)

    assert cli_main(["set", "TOKEN", "existing", str(encrypted)]) == 0
    monkeypatch.setattr(builtins, "input", _answer_no)

    assert cli_main(["encrypt", str(plaintext), "-o", str(encrypted)]) == 1

    assert read_encrypted_env(encrypted, PASSPHRASE) == {"TOKEN": "existing"}
    output = capsys.readouterr().out
    assert "already exists" in output
    assert "dotenv-encrypt merge" in output


def test_cli_encrypt_can_replace_existing_output_with_confirmation_or_force(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    plaintext = tmp_path / ".env"
    encrypted = tmp_path / ".env.enc"
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)

    plaintext.write_text("TOKEN=first\n", encoding="utf-8")
    assert cli_main(["encrypt", str(plaintext), "-o", str(encrypted)]) == 0

    plaintext.write_text("TOKEN=second\n", encoding="utf-8")
    monkeypatch.setattr(builtins, "input", _answer_yes)
    assert cli_main(["encrypt", str(plaintext), "-o", str(encrypted)]) == 0
    assert read_encrypted_env(encrypted, PASSPHRASE) == {"TOKEN": "second"}

    plaintext.write_text("TOKEN=third\n", encoding="utf-8")
    monkeypatch.setattr(builtins, "input", _answer_no)
    assert cli_main(["encrypt", str(plaintext), "-o", str(encrypted), "--force"]) == 0
    assert read_encrypted_env(encrypted, PASSPHRASE) == {"TOKEN": "third"}


def test_cli_decrypt_accepts_overwrite_alias(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    Path(".env").write_text("TOKEN=secret\n", encoding="utf-8")

    assert cli_main(["encrypt"]) == 0
    Path(".env").write_text("TOKEN=stale\n", encoding="utf-8")

    assert cli_main(["decrypt", "--overwrite"]) == 0

    assert "TOKEN=secret" in Path(".env").read_text(encoding="utf-8")


def test_cli_handles_keyboard_interrupt_during_confirmation(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    plaintext = tmp_path / ".env"
    encrypted = tmp_path / ".env.enc"
    plaintext.write_text("TOKEN=new\n", encoding="utf-8")
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)

    assert cli_main(["set", "TOKEN", "existing", str(encrypted)]) == 0
    monkeypatch.setattr(builtins, "input", _raise_keyboard_interrupt)

    with pytest.raises(SystemExit) as exc_info:
        cli_main(["encrypt", str(plaintext), "-o", str(encrypted)])

    assert exc_info.value.code == 130
    assert capsys.readouterr().err == "dotenv-encrypt: cancelled\n"
    assert read_encrypted_env(encrypted, PASSPHRASE) == {"TOKEN": "existing"}


def test_cli_show_masks_long_values(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    plaintext = tmp_path / ".env"
    encrypted = tmp_path / ".env.enc"
    plaintext.write_text("LONG=abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8")
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)

    assert cli_main(["encrypt", str(plaintext), "-o", str(encrypted)]) == 0
    assert cli_main(["show", str(encrypted)]) == 0

    output = capsys.readouterr().out
    assert "LONG=abc...xyz\n" in output
    assert "abcdefghijklmnopqrstuvwxyz" not in output


def test_cli_merge_does_not_expand_ambient_environment(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    encrypted = tmp_path / ".env.enc"
    additions = tmp_path / ".env.add"
    additions.write_text("MERGED=${AMBIENT_FOR_TEST}\n", encoding="utf-8")
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    monkeypatch.setenv("AMBIENT_FOR_TEST", "ambient-value")

    assert cli_main(["merge", str(additions), str(encrypted)]) == 0

    assert read_encrypted_env(encrypted, PASSPHRASE) == {
        "MERGED": "${AMBIENT_FOR_TEST}"
    }


def test_cli_merge_defaults_to_dotenv_and_default_encrypted_file(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    Path(".env").write_text("DEFAULT_MERGE=yes\n", encoding="utf-8")

    assert cli_main(["merge"]) == 0

    assert read_encrypted_env(".env.enc", PASSPHRASE) == {"DEFAULT_MERGE": "yes"}


def test_cli_merge_previews_plan_before_passphrase_prompt(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    monkeypatch.setattr("dotenv_encrypt.cli.getpass", _return_passphrase)
    Path(".env").write_text("ALPHA=one\nBRAVO=two\n", encoding="utf-8")

    assert cli_main(["merge"]) == 0

    output = capsys.readouterr().out
    preview = "Will merge/update 2 variable(s) from .env to .env.enc."
    prompt = f"Passphrase ({PASSPHRASE_ENV}): "
    assert preview in output
    assert "To continue, enter the passphrase." in output
    assert output.index(preview) < output.index(prompt)
    assert read_encrypted_env(".env.enc", PASSPHRASE) == {
        "ALPHA": "one",
        "BRAVO": "two",
    }


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
