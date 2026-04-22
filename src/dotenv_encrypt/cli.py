"""Command line interface for dotenv-encrypt."""

from __future__ import annotations

import argparse
import os
import sys
from getpass import getpass
from pathlib import Path
from typing import NoReturn

from dotenv import dotenv_values

from .core import (
    PASSPHRASE_ENV,
    DecryptionError,
    DotenvEncryptError,
    decrypt_file,
    encrypt_file,
    read_encrypted_env,
    write_encrypted_env,
)


class HelpOnErrorParser(argparse.ArgumentParser):
    """Argument parser that shows full help when parsing fails."""

    error_help_parser: argparse.ArgumentParser | None = None

    def error(self, message: str) -> NoReturn:
        help_parser = self._help_parser_for_error(message)
        help_parser.print_help(sys.stderr)
        self.exit(2, f"{help_parser.prog}: error: {message}\n")

    def _help_parser_for_error(self, message: str) -> argparse.ArgumentParser:
        if (
            message.startswith("unrecognized arguments:")
            and self.error_help_parser is not None
        ):
            return self.error_help_parser
        return self


def main(argv: list[str] | None = None) -> int:
    parser, command_parsers = _build_parser()
    args_list = sys.argv[1:] if argv is None else argv
    if not args_list:
        parser.print_help()
        return 0
    if args_list[0] == "help":
        return _cmd_help(parser, command_parsers, args_list[1:])

    parser.error_help_parser = _selected_command_parser(args_list, command_parsers)
    args = parser.parse_args(args_list)

    try:
        return args.func(args)
    except KeyboardInterrupt:
        parser.exit(130, "dotenv-encrypt: cancelled\n")
    except (DotenvEncryptError, OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"dotenv-encrypt: error: {exc}\n")


def _build_parser() -> tuple[
    HelpOnErrorParser,
    dict[str, argparse.ArgumentParser],
]:
    parser = HelpOnErrorParser(
        prog="dotenv-encrypt",
        description="Encrypt, inspect, and update .env.enc files.",
    )
    parser.add_argument(
        "--passphrase-env",
        default=PASSPHRASE_ENV,
        help=(
            "environment variable containing the passphrase "
            f"(default: {PASSPHRASE_ENV})"
        ),
    )

    subparsers = parser.add_subparsers(
        required=True,
        parser_class=HelpOnErrorParser,
    )
    command_parsers: dict[str, argparse.ArgumentParser] = {}

    encrypt = subparsers.add_parser(
        "encrypt",
        help="encrypt a plaintext .env file",
    )
    command_parsers["encrypt"] = encrypt
    encrypt.add_argument(
        "src",
        nargs="?",
        default=".env",
        metavar="ENV_FILE",
        help="plaintext dotenv file to encrypt (default: .env)",
    )
    encrypt.add_argument("-o", "--output", default=".env.enc", metavar="ENV_ENC_FILE")
    encrypt.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="replace output without asking when it already exists",
    )
    encrypt.add_argument(
        "--delete-plaintext",
        action="store_true",
        help="unlink the plaintext source after successful encryption",
    )
    encrypt.set_defaults(func=_cmd_encrypt)

    decrypt = subparsers.add_parser(
        "decrypt",
        help="decrypt to a plaintext file",
    )
    command_parsers["decrypt"] = decrypt
    decrypt.add_argument(
        "src",
        nargs="?",
        default=".env.enc",
        metavar="ENV_ENC_FILE",
        help="encrypted dotenv file to decrypt (default: .env.enc)",
    )
    decrypt.add_argument("-o", "--output", default=".env", metavar="ENV_FILE")
    decrypt.add_argument(
        "-f",
        "--force",
        "--overwrite",
        action="store_true",
        help="overwrite output if it already exists",
    )
    decrypt.set_defaults(func=_cmd_decrypt)

    show = subparsers.add_parser(
        "show",
        help="list variables in an encrypted file",
    )
    command_parsers["show"] = show
    show.add_argument(
        "src",
        nargs="?",
        default=".env.enc",
        metavar="ENV_ENC_FILE",
        help="encrypted dotenv file to inspect (default: .env.enc)",
    )
    show.add_argument(
        "--full",
        action="store_true",
        help="print full secret values instead of masked values",
    )
    show.set_defaults(func=_cmd_show)

    set_cmd = subparsers.add_parser(
        "set",
        help="add or update one variable",
    )
    command_parsers["set"] = set_cmd
    set_cmd.add_argument("key", metavar="KEY", help="environment variable name")
    set_cmd.add_argument("value", metavar="VALUE", help="environment variable value")
    set_cmd.add_argument(
        "src",
        nargs="?",
        default=".env.enc",
        metavar="ENV_ENC_FILE",
        help="encrypted dotenv file to update (default: .env.enc)",
    )
    set_cmd.set_defaults(func=_cmd_set)

    unset_cmd = subparsers.add_parser(
        "unset",
        help="remove one variable",
    )
    command_parsers["unset"] = unset_cmd
    unset_cmd.add_argument("key", metavar="KEY", help="environment variable name")
    unset_cmd.add_argument(
        "src",
        nargs="?",
        default=".env.enc",
        metavar="ENV_ENC_FILE",
        help="encrypted dotenv file to update (default: .env.enc)",
    )
    unset_cmd.set_defaults(func=_cmd_unset)

    merge = subparsers.add_parser(
        "merge",
        description=(
            "Read variables from a plaintext dotenv file such as .env, "
            "merge them into an encrypted dotenv file, then rewrite the "
            "encrypted file."
        ),
        epilog="Example: dotenv-encrypt merge .env .env.enc",
        help="merge variables from a plaintext file",
    )
    command_parsers["merge"] = merge
    merge.add_argument(
        "plain_env",
        nargs="?",
        default=".env",
        metavar="PLAIN_ENV",
        help="plaintext dotenv file with new or updated variables (default: .env)",
    )
    merge.add_argument(
        "src",
        nargs="?",
        default=".env.enc",
        metavar="ENV_ENC_FILE",
        help="encrypted dotenv file to update (default: .env.enc)",
    )
    merge.add_argument(
        "--delete-plaintext",
        action="store_true",
        help="unlink the plaintext input file after successful merge",
    )
    merge.set_defaults(func=_cmd_merge)

    return parser, command_parsers


def _selected_command_parser(
    args: list[str],
    command_parsers: dict[str, argparse.ArgumentParser],
) -> argparse.ArgumentParser | None:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--passphrase-env":
            skip_next = True
            continue
        if arg.startswith("--passphrase-env="):
            continue
        if arg in command_parsers:
            return command_parsers[arg]
    return None


def _cmd_help(
    parser: argparse.ArgumentParser,
    command_parsers: dict[str, argparse.ArgumentParser],
    args: list[str],
) -> int:
    if not args:
        parser.print_help()
        return 0

    command = args[0]
    subparser = command_parsers.get(command)
    if subparser is None:
        parser.exit(2, f"dotenv-encrypt: error: unknown command: {command}\n")
    subparser.print_help()
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.exists() and not args.force and not _confirm_replace(output):
        print(f"Skipped: {output} already exists")
        return 1

    passphrase = _read_passphrase(args.passphrase_env, confirm=True)
    output = encrypt_file(args.src, args.output, passphrase=passphrase)
    if args.delete_plaintext:
        Path(args.src).unlink()
    print(f"Encrypted {args.src} -> {output}")
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    passphrase = _read_passphrase(args.passphrase_env)
    output = decrypt_file(
        args.src,
        args.output,
        passphrase=passphrase,
        overwrite=args.force,
    )
    print(f"Decrypted {args.src} -> {output}")
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    passphrase = _read_passphrase(args.passphrase_env)
    env = read_encrypted_env(args.src, passphrase=passphrase)
    for key, value in env.items():
        visible_value = value if args.full else _mask_value(value)
        print(f"{key}={visible_value}")
    return 0


def _cmd_set(args: argparse.Namespace) -> int:
    passphrase = _read_passphrase(args.passphrase_env)
    env = _read_or_empty(args.src, passphrase)
    env[args.key] = args.value
    write_encrypted_env(env, args.src, passphrase=passphrase)
    print(f"Set {args.key} in {args.src}")
    return 0


def _cmd_unset(args: argparse.Namespace) -> int:
    passphrase = _read_passphrase(args.passphrase_env)
    env = read_encrypted_env(args.src, passphrase=passphrase)
    env.pop(args.key, None)
    write_encrypted_env(env, args.src, passphrase=passphrase)
    print(f"Removed {args.key} from {args.src}")
    return 0


def _cmd_merge(args: argparse.Namespace) -> int:
    additions = {
        key: value
        for key, value in dotenv_values(
            args.plain_env,
            interpolate=False,
        ).items()
        if value is not None
    }
    print(
        f"Will merge/update {len(additions)} variable(s) "
        f"from {args.plain_env} to {args.src}."
    )
    if not os.environ.get(args.passphrase_env):
        print("To continue, enter the passphrase.")

    passphrase = _read_passphrase(args.passphrase_env)
    env = _read_or_empty(args.src, passphrase)
    env.update(additions)
    write_encrypted_env(env, args.src, passphrase=passphrase)
    if args.delete_plaintext:
        Path(args.plain_env).unlink()
    print(f"Merged {len(additions)} variable(s) into {args.src}")
    return 0


def _read_or_empty(path: str, passphrase: str) -> dict[str, str]:
    try:
        return read_encrypted_env(path, passphrase=passphrase)
    except FileNotFoundError:
        return {}
    except DecryptionError:
        raise


def _read_passphrase(env_name: str, *, confirm: bool = False) -> str:
    value = os.environ.get(env_name)
    if value:
        return value

    first = getpass(f"Passphrase ({env_name}): ")
    if confirm:
        second = getpass("Confirm passphrase: ")
        if first != second:
            raise ValueError("Passphrases do not match.")
    if not first:
        raise ValueError("Passphrase cannot be empty.")
    return first


def _confirm_replace(path: Path) -> bool:
    answer = input(
        f"{path} already exists. Replace it? [y/N]:\n"
        "Tip: use `dotenv-encrypt merge` to add/update variables instead.\n"
        "> "
    ).strip().lower()
    return answer in {"y", "yes"}


def _mask_value(value: str) -> str:
    """Return a short abc...xyz-style preview without exposing full secrets."""
    if len(value) <= 6:
        return "..." if value else ""
    return f"{value[:3]}...{value[-3:]}"


if __name__ == "__main__":
    raise SystemExit(main())
