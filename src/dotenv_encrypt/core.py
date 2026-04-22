"""Core encryption and .env loading helpers for dotenv-encrypt."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from getpass import getpass
from io import StringIO
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import dotenv_values

PASSPHRASE_ENV: Final = "DOTENV_ENCRYPT_KEY"  # noqa: S105
"""Environment variable read for non-interactive passphrases."""

LEGACY_PASSPHRASE_ENV: Final = "ENC_DOTENV_KEY"  # noqa: S105
"""Legacy environment variable used by the original script."""

_MAGIC: Final = b"DENVENC1"
_HEADER_LEN: Final = 2
_NONCE_SIZE: Final = 12
_SALT_SIZE: Final = 16
_AES_GCM_TAG_SIZE: Final = 16
_LEGACY_PASSPHRASE_SALT: Final = b"C9A73747FDAC9945E2ADC3"
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_SCRYPT_N: Final = 2**20
_MAX_SCRYPT_R: Final = 16
_MAX_SCRYPT_P: Final = 4

_loaded_keys: set[str] = set()


class DotenvEncryptError(Exception):
    """Base exception for dotenv-encrypt failures."""


class InvalidEncryptedFile(DotenvEncryptError):
    """Raised when encrypted input is malformed or unsupported."""


class DecryptionError(DotenvEncryptError):
    """Raised when decryption fails authentication."""


@dataclass(frozen=True)
class ScryptParams:
    """Parameters for passphrase-based key derivation."""

    n: int = 2**14
    r: int = 8
    p: int = 1
    dklen: int = 32

    def validate(self) -> None:
        """Validate parameters before handing them to OpenSSL."""
        if self.n < 2 or self.n & (self.n - 1):
            raise ValueError("scrypt n must be a power of two greater than 1.")
        if self.n > _MAX_SCRYPT_N:
            raise ValueError(f"scrypt n must be no greater than {_MAX_SCRYPT_N}.")
        if self.r < 1:
            raise ValueError("scrypt r must be at least 1.")
        if self.r > _MAX_SCRYPT_R:
            raise ValueError(f"scrypt r must be no greater than {_MAX_SCRYPT_R}.")
        if self.p < 1:
            raise ValueError("scrypt p must be at least 1.")
        if self.p > _MAX_SCRYPT_P:
            raise ValueError(f"scrypt p must be no greater than {_MAX_SCRYPT_P}.")
        if self.dklen != 32:
            raise ValueError("AES-256-GCM requires a 32-byte derived key.")

    def to_header(self) -> dict[str, int]:
        """Serialize KDF parameters into encrypted file metadata."""
        self.validate()
        return {"n": self.n, "r": self.r, "p": self.p, "dklen": self.dklen}

    @classmethod
    def from_header(cls, data: Mapping[str, Any]) -> ScryptParams:
        """Load KDF parameters from encrypted file metadata."""
        try:
            params = cls(
                n=int(data["n"]),
                r=int(data["r"]),
                p=int(data["p"]),
                dklen=int(data["dklen"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidEncryptedFile("Invalid scrypt parameters.") from exc
        params.validate()
        return params


DEFAULT_SCRYPT_PARAMS: Final = ScryptParams()


def resolve_env_path(path: str | os.PathLike[str]) -> Path:
    """Resolve an env file path from the current directory or its parents."""
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate

    cwd = Path.cwd().resolve()
    search_paths = [cwd / candidate]
    search_paths.extend(parent / candidate for parent in cwd.parents)
    for search_path in search_paths:
        if search_path.exists():
            return search_path
    return candidate


def encrypt_bytes(
    plaintext: bytes,
    passphrase: str,
    *,
    kdf_params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
) -> bytes:
    """Encrypt bytes with AES-256-GCM using a passphrase-derived key.

    The output format stores a random salt and KDF parameters in authenticated
    metadata, followed by a random 96-bit nonce and ciphertext.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes.")
    _validate_passphrase(passphrase)

    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    header = _make_header(salt, kdf_params)
    prefix = _encode_header(header)
    key = _derive_key(passphrase, salt, kdf_params)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, prefix)
    return prefix + nonce + ciphertext


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    """Decrypt bytes produced by :func:`encrypt_bytes`.

    Files created by the original one-off script are also accepted as a legacy
    format: ``nonce || ciphertext || tag`` with its static scrypt salt.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes.")
    _validate_passphrase(passphrase)

    if blob.startswith(_MAGIC):
        return _decrypt_current_format(blob, passphrase)
    return _decrypt_legacy_format(blob, passphrase)


def encrypt_text(
    plaintext: str,
    passphrase: str,
    *,
    kdf_params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
) -> bytes:
    """Encrypt UTF-8 text and return encrypted bytes."""
    return encrypt_bytes(
        plaintext.encode("utf-8"),
        passphrase,
        kdf_params=kdf_params,
    )


def decrypt_text(blob: bytes, passphrase: str) -> str:
    """Decrypt encrypted bytes and decode the plaintext as UTF-8."""
    try:
        return decrypt_bytes(blob, passphrase).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidEncryptedFile("Decrypted data is not valid UTF-8.") from exc


def encrypt_file(
    src: str | os.PathLike[str],
    dst: str | os.PathLike[str] = ".env.enc",
    passphrase: str | None = None,
    *,
    kdf_params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
) -> Path:
    """Encrypt a plaintext file to ``dst`` and return the destination path."""
    secret = _resolve_passphrase(passphrase, prompt=True, confirm=True)
    plaintext = Path(src).read_bytes()
    encrypted = encrypt_bytes(plaintext, secret, kdf_params=kdf_params)
    return _write_private_file(dst, encrypted)


def decrypt_file(
    src: str | os.PathLike[str],
    dst: str | os.PathLike[str],
    passphrase: str | None = None,
    *,
    overwrite: bool = False,
) -> Path:
    """Decrypt ``src`` to ``dst``.

    ``overwrite`` defaults to ``False`` because the destination is plaintext.
    """
    target = Path(dst)
    if target.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite plaintext file: {target}")

    secret = _resolve_passphrase(passphrase, prompt=True)
    plaintext = decrypt_bytes(resolve_env_path(src).read_bytes(), secret)
    return _write_private_file(target, plaintext)


def read_encrypted_env(
    path: str | os.PathLike[str] = ".env.enc",
    passphrase: str | None = None,
) -> dict[str, str]:
    """Read an encrypted ``.env`` file and return parsed key/value pairs."""
    secret = _resolve_passphrase(passphrase, prompt=True)
    plaintext = decrypt_text(resolve_env_path(path).read_bytes(), secret)
    return _parse_env(plaintext)


def write_encrypted_env(
    env: Mapping[str, str],
    path: str | os.PathLike[str] = ".env.enc",
    passphrase: str | None = None,
    *,
    kdf_params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
) -> Path:
    """Serialize and encrypt environment variables to ``path``."""
    _validate_env_mapping(env)
    secret = _resolve_passphrase(passphrase, prompt=True, confirm=True)
    encrypted = encrypt_text(render_env(env), secret, kdf_params=kdf_params)
    return _write_private_file(path, encrypted)


def load_enc_env(
    src: str | os.PathLike[str] = ".env.enc",
    passphrase: str | None = None,
    *,
    environ: MutableMapping[str, str] | None = None,
    override: bool = True,
) -> dict[str, str]:
    """Decrypt ``src`` and load variables into an environment mapping.

    Returns the parsed variables. Only variables written by this call are later
    removed by :func:`unload_enc_env`.
    """
    global _loaded_keys

    target_environ = os.environ if environ is None else environ
    env = read_encrypted_env(src, passphrase)

    written: set[str] = set()
    for key, value in env.items():
        if override or key not in target_environ:
            target_environ[key] = value
            written.add(key)

    _loaded_keys = written
    return env


def unload_enc_env(*, environ: MutableMapping[str, str] | None = None) -> None:
    """Remove variables injected by the last :func:`load_enc_env` call."""
    global _loaded_keys

    target_environ = os.environ if environ is None else environ
    for key in _loaded_keys:
        target_environ.pop(key, None)
    _loaded_keys = set()


def render_env(env: Mapping[str, str]) -> str:
    """Serialize a mapping in dotenv syntax with safely escaped values."""
    _validate_env_mapping(env)
    lines = []
    for key, value in env.items():
        escaped = (
            value.replace("\\", "\\\\")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace('"', '\\"')
        )
        lines.append(f'{key}="{escaped}"')
    return "\n".join(lines) + ("\n" if lines else "")


def _decrypt_current_format(blob: bytes, passphrase: str) -> bytes:
    try:
        header, header_end = _decode_header(blob)
    except InvalidEncryptedFile:
        raise
    except Exception as exc:
        raise InvalidEncryptedFile("Malformed encrypted file header.") from exc

    salt = _decode_b64(header.get("salt"), "salt")
    params = ScryptParams.from_header(_expect_mapping(header.get("scrypt"), "scrypt"))
    nonce_start = header_end
    nonce_end = nonce_start + _NONCE_SIZE
    nonce = blob[nonce_start:nonce_end]
    ciphertext = blob[nonce_end:]

    if len(salt) != _SALT_SIZE:
        raise InvalidEncryptedFile("Invalid salt length.")
    if len(nonce) != _NONCE_SIZE or len(ciphertext) < _AES_GCM_TAG_SIZE:
        raise InvalidEncryptedFile("Encrypted file is truncated.")

    aad = blob[:header_end]
    key = _derive_key(passphrase, salt, params)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed: wrong passphrase or file has been tampered with."
        ) from exc


def _decrypt_legacy_format(blob: bytes, passphrase: str) -> bytes:
    if len(blob) < _NONCE_SIZE + _AES_GCM_TAG_SIZE:
        raise InvalidEncryptedFile("Encrypted file is too short.")

    nonce = blob[:_NONCE_SIZE]
    ciphertext = blob[_NONCE_SIZE:]
    keys = [_derive_key(passphrase, _LEGACY_PASSPHRASE_SALT, DEFAULT_SCRYPT_PARAMS)]
    direct_key = _maybe_urlsafe_b64_key(passphrase)
    if direct_key is not None:
        keys.append(direct_key)

    for key in keys:
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            continue
    raise DecryptionError(
        "Decryption failed: wrong passphrase or file has been tampered with."
    )


def _make_header(salt: bytes, params: ScryptParams) -> dict[str, Any]:
    return {
        "version": 1,
        "cipher": "AES-256-GCM",
        "kdf": "scrypt",
        "scrypt": params.to_header(),
        "salt": _urlsafe_b64(salt),
    }


def _encode_header(header: Mapping[str, Any]) -> bytes:
    header_bytes = json.dumps(
        header,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(header_bytes) > 65535:
        raise ValueError("Encrypted file header is too large.")
    return _MAGIC + struct.pack(">H", len(header_bytes)) + header_bytes


def _decode_header(blob: bytes) -> tuple[dict[str, Any], int]:
    if len(blob) < len(_MAGIC) + _HEADER_LEN:
        raise InvalidEncryptedFile("Encrypted file is too short.")
    if not blob.startswith(_MAGIC):
        raise InvalidEncryptedFile("Unsupported encrypted file format.")

    header_len_start = len(_MAGIC)
    header_len_end = header_len_start + _HEADER_LEN
    header_len = struct.unpack(">H", blob[header_len_start:header_len_end])[0]
    header_start = header_len_end
    header_end = header_start + header_len
    if len(blob) < header_end + _NONCE_SIZE + _AES_GCM_TAG_SIZE:
        raise InvalidEncryptedFile("Encrypted file is truncated.")

    try:
        header = json.loads(blob[header_start:header_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidEncryptedFile(
            "Encrypted file metadata is not valid JSON."
        ) from exc
    if not isinstance(header, dict):
        raise InvalidEncryptedFile("Encrypted file metadata must be an object.")
    if header.get("version") != 1:
        raise InvalidEncryptedFile("Unsupported encrypted file version.")
    if header.get("cipher") != "AES-256-GCM" or header.get("kdf") != "scrypt":
        raise InvalidEncryptedFile("Unsupported encrypted file metadata.")
    return header, header_end


def _derive_key(passphrase: str, salt: bytes, params: ScryptParams) -> bytes:
    _validate_passphrase(passphrase)
    params.validate()
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=params.n,
        r=params.r,
        p=params.p,
        dklen=params.dklen,
    )


def _parse_env(text: str) -> dict[str, str]:
    return {
        key: value
        for key, value in dotenv_values(stream=StringIO(text)).items()
        if value is not None
    }


def _validate_env_mapping(env: Mapping[str, str]) -> None:
    for key, value in env.items():
        if not isinstance(key, str) or not _ENV_NAME.fullmatch(key):
            raise ValueError(f"Invalid environment variable name: {key!r}")
        if not isinstance(value, str):
            raise TypeError(f"Environment variable {key!r} must be a string.")


def _resolve_passphrase(
    passphrase: str | None,
    *,
    prompt: bool,
    confirm: bool = False,
) -> str:
    if passphrase is None:
        passphrase = os.environ.get(PASSPHRASE_ENV) or os.environ.get(
            LEGACY_PASSPHRASE_ENV
        )
    if passphrase is None and prompt:
        passphrase = _prompt_passphrase(confirm=confirm)
    if passphrase is None:
        raise ValueError(
            f"Passphrase required. Pass one explicitly or set {PASSPHRASE_ENV}."
        )
    _validate_passphrase(passphrase)
    return passphrase


def _prompt_passphrase(*, confirm: bool) -> str:
    first = getpass("dotenv-encrypt passphrase: ")
    if confirm:
        second = getpass("Confirm passphrase: ")
        if first != second:
            raise ValueError("Passphrases do not match.")
    return first


def _validate_passphrase(passphrase: str) -> None:
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a string.")
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")


def _write_private_file(path: str | os.PathLike[str], data: bytes) -> Path:
    target = Path(path)
    if target.parent != Path("."):
        target.parent.mkdir(parents=True, exist_ok=True)

    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)

    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target


def _urlsafe_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _decode_b64(value: Any, name: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidEncryptedFile(f"Missing encrypted file {name}.")
    try:
        return base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise InvalidEncryptedFile(f"Invalid encrypted file {name}.") from exc


def _expect_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidEncryptedFile(f"Missing encrypted file {name}.")
    return value


def _maybe_urlsafe_b64_key(value: str) -> bytes | None:
    try:
        decoded = base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return None
    return decoded if len(decoded) == 32 else None
