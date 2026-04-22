# dotenv-encrypt

Encrypt, decrypt, edit, and load `.env` files from Python without committing
plaintext secrets.

`dotenv-encrypt` uses AES-256-GCM for authenticated encryption and derives keys
from a passphrase with scrypt. New files include a random salt, a random nonce,
and authenticated encryption metadata.

## Install

```bash
pip install dotenv-encrypt
```

For local development:

```bash
python -m pip install -e ".[dev]"
pytest
```

## Python Usage

```python
from dotenv_encrypt import load_enc_env, unload_enc_env

load_enc_env(".env.enc", passphrase="your passphrase")

# os.environ now contains the variables from .env.enc

unload_enc_env()
```

Read and write encrypted dotenv files directly:

```python
from dotenv_encrypt import read_encrypted_env, write_encrypted_env

write_encrypted_env(
    {"API_KEY": "secret", "DEBUG": "false"},
    ".env.enc",
    passphrase="your passphrase",
)

env = read_encrypted_env(".env.enc", passphrase="your passphrase")
```

## CLI Usage

The CLI intentionally avoids passphrase command-line flags, because command-line
arguments can leak through shell history and process listings. Set
`DOTENV_ENCRYPT_KEY` for automation, or let the CLI prompt securely.

```bash
dotenv-encrypt encrypt .env -o .env.enc
dotenv-encrypt show .env.enc
dotenv-encrypt show .env.enc --values
dotenv-encrypt set API_KEY "secret" .env.enc
dotenv-encrypt unset API_KEY .env.enc
dotenv-encrypt merge .env.add .env.enc
dotenv-encrypt decrypt .env.enc -o .env.local
```

## Security Notes

- Encryption is AES-256-GCM with a fresh 96-bit nonce for every write.
- Passphrases are stretched with scrypt and a fresh 128-bit salt per file.
- File metadata is authenticated with AES-GCM additional authenticated data.
- Output files are written with `0600` permissions where the platform supports
  POSIX modes.
- Secret values are not printed by default. Use `show --values` only when you
  explicitly need plaintext output.
- The original script format is supported for decryption so existing
  `nonce || ciphertext || tag` files can be migrated.

## Publishing

Update the version in `pyproject.toml`, then build and check the package:

```bash
python -m build
python -m twine check dist/*
```

Upload with:

```bash
python -m twine upload dist/*
```
