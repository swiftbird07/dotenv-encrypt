"""Command line interface for dotenv-encrypt."""

from __future__ import annotations

import argparse
import os
from getpass import getpass
from pathlib import Path

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


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except (DotenvEncryptError, OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"dotenv-encrypt: error: {exc}\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
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

    subparsers = parser.add_subparsers(required=True)

    encrypt = subparsers.add_parser("encrypt", help="encrypt a plaintext .env file")
    encrypt.add_argument("src", nargs="?", default=".env")
    encrypt.add_argument("-o", "--output", default=".env.enc")
    encrypt.add_argument(
        "--delete-plaintext",
        action="store_true",
        help="delete the plaintext source after successful encryption",
    )
    encrypt.set_defaults(func=_cmd_encrypt)

    decrypt = subparsers.add_parser("decrypt", help="decrypt to a plaintext file")
    decrypt.add_argument("src", nargs="?", default=".env.enc")
    decrypt.add_argument("-o", "--output", default=".env")
    decrypt.add_argument("-f", "--force", action="store_true", help="overwrite output")
    decrypt.set_defaults(func=_cmd_decrypt)

    show = subparsers.add_parser("show", help="list variables in an encrypted file")
    show.add_argument("src", nargs="?", default=".env.enc")
    show.add_argument(
        "--values",
        action="store_true",
        help="print secret values as well as names",
    )
    show.set_defaults(func=_cmd_show)

    set_cmd = subparsers.add_parser("set", help="add or update one variable")
    set_cmd.add_argument("key")
    set_cmd.add_argument("value")
    set_cmd.add_argument("src", nargs="?", default=".env.enc")
    set_cmd.set_defaults(func=_cmd_set)

    unset_cmd = subparsers.add_parser("unset", help="remove one variable")
    unset_cmd.add_argument("key")
    unset_cmd.add_argument("src", nargs="?", default=".env.enc")
    unset_cmd.set_defaults(func=_cmd_unset)

    merge = subparsers.add_parser("merge", help="merge variables from a plaintext file")
    merge.add_argument("add_file")
    merge.add_argument("src", nargs="?", default=".env.enc")
    merge.add_argument(
        "--delete-plaintext",
        action="store_true",
        help="delete the plaintext add file after successful merge",
    )
    merge.set_defaults(func=_cmd_merge)

    return parser


def _cmd_encrypt(args: argparse.Namespace) -> int:
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
        print(f"{key}={value}" if args.values else key)
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
    passphrase = _read_passphrase(args.passphrase_env)
    additions = {
        key: value
        for key, value in dotenv_values(args.add_file).items()
        if value is not None
    }
    env = _read_or_empty(args.src, passphrase)
    env.update(additions)
    write_encrypted_env(env, args.src, passphrase=passphrase)
    if args.delete_plaintext:
        Path(args.add_file).unlink()
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


if __name__ == "__main__":
    raise SystemExit(main())
