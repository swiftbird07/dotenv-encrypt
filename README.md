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

load_enc_env(".env.enc")

# os.environ now contains the variables from .env.enc

unload_enc_env()
```

When no passphrase is supplied and `DOTENV_ENCRYPT_KEY` is unset,
`dotenv-encrypt` prompts securely with `getpass`. This is the recommended local
usage because the passphrase is not stored in source code.

Read and write encrypted dotenv files directly:

```python
from dotenv_encrypt import read_encrypted_env, write_encrypted_env

write_encrypted_env(
    {"API_KEY": "secret", "DEBUG": "false"},
    ".env.enc",
)

env = read_encrypted_env(".env.enc")
```

An explicit `passphrase=` argument is available for controlled integrations and
tests. For automation, prefer a protected `DOTENV_ENCRYPT_KEY` environment
variable over hard-coded source values.

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
- Secret values are not printed by default. `show --values` should be used only
  when plaintext output is required.

## Threat Model

`dotenv-encrypt` protects the contents of an encrypted `.env.enc` file only
while the attacker does not also have the passphrase or the decrypted
environment values. It is a file-at-rest protection tool, not a runtime
sandbox or secret manager.

### Protects Against

- **Offline file reads:** an attacker gets a copy of a repository, laptop
  backup, deployment bundle, container image, or disk contents and can read
  `.env.enc`, but cannot access the passphrase.
- **Accidental secret commits:** `.env.enc` can be committed without exposing
  the plaintext values that would have appeared in `.env`.
- **Simple online file stealers:** malware or an intrusion grabs project files
  from disk but does not read process memory, process environments, shell
  history, terminal input, CI logs, or password manager contents.
- **Stopped or unloaded apps:** an online attacker gets file access after the
  application has stopped, before the application has started, or after
  `unload_enc_env()` has been called and no other copy of the plaintext values
  remains in the process.
- **Tampering with encrypted files:** AES-GCM authentication detects wrong
  passphrases and modified ciphertext or authenticated metadata.

### Does NOT Protect Against

- **Attackers with the passphrase:** anyone who knows `DOTENV_ENCRYPT_KEY`, saw
  the passphrase being typed, read it from a password manager, or found it in CI
  configuration can decrypt the file.
- **Runtime memory or environment theft:** if an application has already loaded
  the variables, an attacker who can read process memory, `/proc` environment
  data, crash dumps, debugger output, or equivalent OS/runtime state can obtain
  the plaintext values.
- **Malicious code running in the same process:** dependencies, plugins, or app
  code can read `os.environ` after `load_enc_env()` has populated it.
- **Shell, log, and history leaks:** decrypted values printed by an application,
  `dotenv-encrypt show --values`, debug logs, traces, shell history, copied
  plaintext `.env` files, and CI output are outside the encryption boundary.
- **Compromised hosts:** if an attacker controls the machine while secrets are
  being decrypted or used, encryption at rest cannot keep those runtime secrets
  private.
- **Weak passphrases:** scrypt slows guessing, but it cannot save a short,
  reused, or leaked passphrase from offline brute force.

### Operational Guidance

- Keep the passphrase out of source control, logs, command-line arguments, and
  issue trackers.
- Prefer interactive prompts locally and protected CI secrets or GitHub
  environment secrets in automation.
- `unload_enc_env()` should be called when a long-running process no longer
  needs the values. Decrypted values should not be copied into other long-lived
  globals.
- Treat `show --values` and `decrypt` as sensitive operations. Plaintext output
  and plaintext files should be short-lived and handled like any other secret.
