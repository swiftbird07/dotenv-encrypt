"""Core encryption and .env loading helpers for dotenv-encrypt.

The current encrypted file format is:

```
DENVENC1 || header_len_u16_be || header_json || nonce || ciphertext_and_tag
```

The JSON header contains non-secret metadata such as the format version, KDF
parameters, and random salt. The exact encoded header bytes are passed to
AES-GCM as additional authenticated data (AAD), so metadata changes are caught
by authentication even though the metadata itself is not encrypted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import tempfile
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from getpass import getpass
from io import StringIO
from pathlib import Path
from typing import Final, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import dotenv_values

PASSPHRASE_ENV: Final = "DOTENV_ENCRYPT_KEY"  # noqa: S105
"""Environment variable read for non-interactive passphrases."""
_MAGIC: Final = b"DENVENC1"
_HEADER_LEN: Final = 2
_NONCE_SIZE: Final = 12
_SALT_SIZE: Final = 16
_AES_GCM_TAG_SIZE: Final = 16
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# KDF parameters are read from the encrypted file header before authentication
# can complete. These caps prevent a malicious file from requesting excessive
# memory or CPU during key derivation.
_MIN_SCRYPT_N: Final = 2**14
_MAX_SCRYPT_N: Final = 2**16
_MIN_SCRYPT_R: Final = 8
_MAX_SCRYPT_R: Final = 8
_MIN_SCRYPT_P: Final = 1
_MAX_SCRYPT_P: Final = 2

# Tracks names written by load_enc_env so unload_enc_env removes only values
# injected by this package, rather than deleting unrelated process environment.
_loaded_keys: set[str] = set()


class DotenvEncryptError(Exception):
    """Base exception for dotenv-encrypt failures."""


class InvalidEncryptedFile(DotenvEncryptError):
    """Raised when encrypted input is malformed or unsupported."""


class DecryptionError(DotenvEncryptError):
    """Raised when decryption fails authentication."""


@dataclass(frozen=True)
class ScryptParams:
    """Parameters for passphrase-based key derivation.

    ``n``, ``r``, and ``p`` are the standard scrypt work-factor parameters.
    ``dklen`` is fixed at 32 bytes because the package uses AES-256-GCM.
    """

    n: int = 2**14
    r: int = 8
    p: int = 1
    dklen: int = 32

    def validate(self) -> None:
        """Validate parameters before handing them to OpenSSL.

        The upper bounds are deliberately part of validation because these
        values may come from untrusted file metadata during decryption.
        """
        if self.n < 2 or self.n & (self.n - 1):
            raise ValueError("scrypt n must be a power of two greater than 1.")
        if self.n < _MIN_SCRYPT_N:
            raise ValueError(f"scrypt n must be at least {_MIN_SCRYPT_N}.")
        if self.n > _MAX_SCRYPT_N:
            raise ValueError(f"scrypt n must be no greater than {_MAX_SCRYPT_N}.")
        if self.r < _MIN_SCRYPT_R:
            raise ValueError(f"scrypt r must be at least {_MIN_SCRYPT_R}.")
        if self.r > _MAX_SCRYPT_R:
            raise ValueError(f"scrypt r must be no greater than {_MAX_SCRYPT_R}.")
        if self.p < _MIN_SCRYPT_P:
            raise ValueError(f"scrypt p must be at least {_MIN_SCRYPT_P}.")
        if self.p > _MAX_SCRYPT_P:
            raise ValueError(f"scrypt p must be no greater than {_MAX_SCRYPT_P}.")
        if self.dklen != 32:
            raise ValueError("AES-256-GCM requires a 32-byte derived key.")

    def to_header(self) -> dict[str, int]:
        """Serialize KDF parameters into encrypted file metadata.

        The returned values are not secret, but they are authenticated as part
        of the encrypted file header.
        """
        self.validate()
        return {"n": self.n, "r": self.r, "p": self.p, "dklen": self.dklen}

    @classmethod
    def from_header(cls, data: Mapping[str, object]) -> ScryptParams:
        """Load KDF parameters from encrypted file metadata.

        A dedicated parser keeps untrusted JSON values as ``object`` until each
        expected integer field has been type-checked.
        """
        try:
            params = cls(
                n=_expect_int(data["n"], "n"),
                r=_expect_int(data["r"], "r"),
                p=_expect_int(data["p"], "p"),
                dklen=_expect_int(data["dklen"], "dklen"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidEncryptedFile("Invalid scrypt parameters.") from exc
        params.validate()
        return params


DEFAULT_SCRYPT_PARAMS: Final = ScryptParams()


def resolve_env_path(path: str | os.PathLike[str]) -> Path:
    """Resolve an env file path from the current directory or its parents.

    Relative paths are searched from the current working directory upward. This
    supports common application layouts where code runs from a subdirectory but
    the encrypted env file lives at the repository root.
    """
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
    _validate_passphrase(passphrase)

    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    header = _make_header(salt, kdf_params)
    prefix = _encode_header(header)
    key = _derive_key(passphrase, salt, kdf_params)

    # Authenticate the serialized header as AAD so changes to KDF metadata,
    # cipher name, salt, or version fail decryption instead of being trusted.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, prefix)
    return prefix + nonce + ciphertext


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    """Decrypt bytes produced by :func:`encrypt_bytes`."""
    _validate_passphrase(passphrase)

    if blob.startswith(_MAGIC):
        return _decrypt_current_format(blob, passphrase)

    raise InvalidEncryptedFile("Unsupported encrypted file format.")


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
    """Encrypt a plaintext file to ``dst`` and return the destination path.

    The source file is left untouched. The CLI handles optional deletion so the
    library API does not surprise callers by removing plaintext input.
    """
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
    The plaintext file is still written with private permissions where the
    platform supports them.
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
    """Read an encrypted ``.env`` file and return parsed key/value pairs.

    Parsing is delegated to ``python-dotenv`` so quoting and escaping match the
    familiar dotenv format.
    """
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
    """Serialize and encrypt environment variables to ``path``.

    Keys are validated before rendering to avoid writing malformed dotenv lines
    that could parse differently later.
    """
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

    This is the main runtime API. By default, variables are injected into
    ``os.environ`` so existing application code can read them with
    ``os.getenv`` or ``os.environ``. Tests and integrations can pass a custom
    mutable mapping through ``environ`` to avoid mutating the process-wide
    environment.

    Passphrase resolution is intentionally ordered for safer local use:

    1. an explicit ``passphrase`` argument, when provided;
    2. ``DOTENV_ENCRYPT_KEY``, when set;
    3. an interactive ``getpass`` prompt.

    ``override`` controls collision handling. When ``True`` (the default),
    encrypted values replace existing environment values. When ``False``,
    existing values are preserved and only missing keys are written.

    Returns:
        The complete set of variables parsed from the encrypted file,
        including variables that were not written because ``override=False``.

    Raises:
        FileNotFoundError: If ``src`` cannot be found.
        ValueError: If no passphrase is available or an empty passphrase is
            supplied.
        DecryptionError: If authentication fails because the passphrase is
            wrong or the encrypted file was modified.
        InvalidEncryptedFile: If the encrypted file is malformed or unsupported.

    Security:
        After loading, plaintext values live in the target environment mapping.
        Code running in the same process can read them. Call
        :func:`unload_enc_env` when the values are no longer needed by a
        long-running process.

    Only variables written by the most recent call are tracked for later
    removal by :func:`unload_enc_env`.
    """
    global _loaded_keys

    target_environ = os.environ if environ is None else environ
    env = read_encrypted_env(src, passphrase)
    _validate_env_mapping(env)

    written: set[str] = set()
    previous_values: dict[str, str | None] = {}
    try:
        for key, value in env.items():
            if override or key not in target_environ:
                previous_values[key] = target_environ.get(key)
                target_environ[key] = value
                written.add(key)
    except Exception:
        for key in reversed(tuple(written)):
            previous = previous_values[key]
            if previous is None:
                target_environ.pop(key, None)
            else:
                target_environ[key] = previous
        raise

    _loaded_keys = written
    return env


def unload_enc_env(*, environ: MutableMapping[str, str] | None = None) -> None:
    """Remove variables injected by the last :func:`load_enc_env` call.

    By default, variables are removed from ``os.environ``. Pass the same custom
    mapping used with :func:`load_enc_env` through ``environ`` when loading into
    a test mapping or another process-local store.

    Only keys that were actually written by the most recent ``load_enc_env``
    call are removed. Existing values preserved by ``override=False`` are left
    alone, and keys removed by other code before this call are ignored.

    This function resets the internal tracking set after cleanup, so repeated
    calls are safe and become no-ops until another load occurs.

    Security:
        This removes the package's tracked environment entries from the target
        mapping. It cannot erase copies already read by application code,
        libraries, logs, crash dumps, child processes, or other runtime state.
    """
    global _loaded_keys

    target_environ = os.environ if environ is None else environ
    for key in _loaded_keys:
        target_environ.pop(key, None)
    _loaded_keys = set()


def render_env(env: Mapping[str, str]) -> str:
    """Serialize a mapping in dotenv syntax with safely escaped values.

    Values are double-quoted and escaped so round trips through
    ``python-dotenv`` preserve backslashes, quotes, and newlines.
    """
    _validate_env_mapping(env)
    lines: list[str] = []
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
    """Decrypt the versioned format written by current package releases."""
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

    # The authenticated data must be the exact bytes used during encryption.
    # Re-serializing JSON would be unsafe because key order and whitespace could
    # differ while representing the same object.
    aad = blob[:header_end]
    key = _derive_key(passphrase, salt, params)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed: wrong passphrase or file has been tampered with."
        ) from exc


def _make_header(salt: bytes, params: ScryptParams) -> dict[str, object]:
    """Build non-secret metadata for the versioned encrypted file header."""
    return {
        "version": 1,
        "cipher": "AES-256-GCM",
        "kdf": "scrypt",
        "scrypt": params.to_header(),
        "salt": _urlsafe_b64(salt),
    }


def _encode_header(header: Mapping[str, object]) -> bytes:
    """Encode header metadata into the authenticated byte prefix."""
    header_bytes = json.dumps(
        header,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(header_bytes) > 65535:
        raise ValueError("Encrypted file header is too large.")
    return _MAGIC + struct.pack(">H", len(header_bytes)) + header_bytes


def _decode_header(blob: bytes) -> tuple[dict[str, object], int]:
    """Parse and validate the versioned file header.

    The returned index points to the first nonce byte. Authentication is handled
    later by AES-GCM once the key can be derived.
    """
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
        raw_header = json.loads(blob[header_start:header_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidEncryptedFile(
            "Encrypted file metadata is not valid JSON."
        ) from exc
    if not isinstance(raw_header, dict):
        raise InvalidEncryptedFile("Encrypted file metadata must be an object.")
    header = cast(dict[str, object], raw_header)
    if header.get("version") != 1:
        raise InvalidEncryptedFile("Unsupported encrypted file version.")
    if header.get("cipher") != "AES-256-GCM" or header.get("kdf") != "scrypt":
        raise InvalidEncryptedFile("Unsupported encrypted file metadata.")
    return header, header_end


def _derive_key(passphrase: str, salt: bytes, params: ScryptParams) -> bytes:
    """Derive a 32-byte AES key from a passphrase and salt."""
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
    """Parse dotenv text, dropping entries without values."""
    return {
        key: value
        for key, value in dotenv_values(
            stream=StringIO(text),
            interpolate=False,
        ).items()
        if value is not None
    }


def _validate_env_mapping(env: Mapping[str, str]) -> None:
    """Validate env names before rendering dotenv text."""
    for key, value in env.items():
        if not _ENV_NAME.fullmatch(key):
            raise ValueError(f"Invalid environment variable name: {key!r}")
        if "\x00" in key:
            raise ValueError(f"Environment variable name contains NUL: {key!r}")
        if "\x00" in value:
            raise ValueError(f"Environment variable {key!r} contains NUL.")


def _resolve_passphrase(
    passphrase: str | None,
    *,
    prompt: bool,
    confirm: bool = False,
) -> str:
    """Return an explicit, environment, or prompted passphrase."""
    if passphrase is None:
        passphrase = os.environ.get(PASSPHRASE_ENV)
    if passphrase is None and prompt:
        passphrase = _prompt_passphrase(confirm=confirm)
    if passphrase is None:
        raise ValueError(
            f"Passphrase required. Pass one explicitly or set {PASSPHRASE_ENV}."
        )
    _validate_passphrase(passphrase)
    return passphrase


def _prompt_passphrase(*, confirm: bool) -> str:
    """Read a passphrase without echoing it to the terminal."""
    first = getpass("dotenv-encrypt passphrase: ")
    if confirm:
        second = getpass("Confirm passphrase: ")
        if first != second:
            raise ValueError("Passphrases do not match.")
    return first


def _validate_passphrase(passphrase: str) -> None:
    """Reject empty passphrases before key derivation."""
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")


def _write_private_file(path: str | os.PathLike[str], data: bytes) -> Path:
    """Atomically write bytes with owner-only permissions where possible."""
    target = Path(path)
    if target.parent != Path("."):
        target.parent.mkdir(parents=True, exist_ok=True)

    directory = target.parent if target.parent != Path("") else Path(".")
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=directory,
    )
    tmp_path = Path(tmp_name)
    try:
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass

        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_path, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        _fsync_directory(directory)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return target


def _fsync_directory(directory: Path) -> None:
    """Best-effort fsync for the containing directory after atomic replace."""
    if os.name != "posix":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _urlsafe_b64(data: bytes) -> str:
    """Encode binary metadata as URL-safe base64 text."""
    return base64.urlsafe_b64encode(data).decode("ascii")


def _decode_b64(value: object, name: str) -> bytes:
    """Decode a base64 metadata field from untrusted JSON."""
    if not isinstance(value, str):
        raise InvalidEncryptedFile(f"Missing encrypted file {name}.")
    try:
        return base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise InvalidEncryptedFile(f"Invalid encrypted file {name}.") from exc


def _expect_mapping(value: object, name: str) -> Mapping[str, object]:
    """Require a JSON metadata field to be an object."""
    if not isinstance(value, Mapping):
        raise InvalidEncryptedFile(f"Missing encrypted file {name}.")
    return cast(Mapping[str, object], value)


def _expect_int(value: object, name: str) -> int:
    """Require a JSON metadata field to be an integer."""
    if not isinstance(value, int):
        raise InvalidEncryptedFile(f"Invalid integer field in encrypted file: {name}.")
    return value
