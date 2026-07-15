# vault-plugin-secrets-gpg

A HashiCorp Vault / OpenBao secrets engine that manages **GPG / OpenPGP keys**
and performs **signing, verification, encryption and decryption** with them —
the transit engine, but the key material is OpenPGP.

Keys are generated and stored inside Vault's own barrier storage (seal-wrapped
under `key/`) and the private key never leaves Vault unless a key is explicitly
marked `exportable`. Each named key is **versioned**: rotating adds a new
OpenPGP entity, while older versions are retained so archived signatures still
verify and old ciphertext still decrypts.

The armored public key the engine hands back is a standard, importable OpenPGP
key, so `gpg`, [`pass`](https://www.passwordstore.org/) and friends can encrypt
to it while the private key stays in Vault and decryption is delegated back to
`decrypt/<name>`.

```
gpg / pass  ──encrypt to public key──▶  binary .gpg
    │                                       │
    │ import public key                     │ decrypt/<name>
    ▼                                       ▼
export/public-key/<name>  ◀── Vault ──▶  private key (never leaves the barrier)
```

## Paths

| Path | Purpose |
|------|---------|
| `keys/<name>` (write/read/delete, list `keys/`) | generate a key (`rsa-2048`, `rsa-3072`, `rsa-4096`, `ed25519`); read metadata + armored public key |
| `keys/<name>/config` | set `min_decryption_version`, `deletion_allowed`, `exportable` |
| `keys/<name>/rotate` | add a new version (older versions kept for decrypt/verify) |
| `keys/<name>/import` | import an existing armored private key |
| `export/<public-key\|private-key>/<name>[/<version>]` | export armored key material |
| `sign/<name>` / `verify/<name>` | detached OpenPGP signature over base64 input |
| `encrypt/<name>` / `decrypt/<name>` | OpenPGP encrypt to / decrypt with the key |

Creating a key is **idempotent** — writing `keys/<name>` again returns the
existing key rather than regenerating it. Deletion is refused unless
`deletion_allowed=true` is set via `keys/<name>/config`.

## Usage

```sh
# register + enable (the plugin_directory must contain the binary)
sha=$(sha256sum /opt/vault-plugins/vault-plugin-secrets-gpg | cut -d' ' -f1)
vault plugin register -sha256=$sha secret vault-plugin-secrets-gpg
vault secrets enable -path=gpg vault-plugin-secrets-gpg

# generate a key
vault write gpg/keys/app algorithm=rsa-4096 identity="App <app@unkin.net>"
vault read  gpg/keys/app                       # metadata + armored public key

# sign / verify (input and output are base64 / armored)
sig=$(vault write -field=signature gpg/sign/app input=$(base64 <<<"ship it"))
vault write -field=valid gpg/verify/app input=$(base64 <<<"ship it") signature="$sig"

# encrypt / decrypt
ct=$(vault write -field=ciphertext gpg/encrypt/app plaintext=$(base64 <<<"secret"))
vault write -field=plaintext gpg/decrypt/app ciphertext="$ct" | base64 -d

# rotate; old ciphertext still decrypts
vault write gpg/keys/app/rotate
```

## Using it with `pass`

The engine holds the private key; `pass`/`gpg` only need the **public** key to
encrypt, and delegate decryption back to Vault.

```sh
# import the engine's public key into your gpg keyring
vault read -field=public_key gpg/keys/app | gpg --import
fpr=$(vault read -field=fingerprint gpg/keys/app)

# initialise a password store against it
pass init "$fpr"
pass insert email/example          # writes ~/.password-store/email/example.gpg (binary OpenPGP)

# decrypt an entry through Vault (decrypt accepts binary ciphertext directly)
vault write -field=plaintext gpg/decrypt/app \
  ciphertext=$(base64 -w0 ~/.password-store/email/example.gpg) | base64 -d
```

`decrypt/<name>` auto-detects ASCII-armored vs raw-binary input, so the binary
`.gpg` files `pass` writes work without conversion. A thin `gpg`/`pass`
wrapper that routes decryption to Vault automatically can be layered on top.

## Build

```sh
make build      # -> dist/vault-plugin-secrets-gpg
make test lint  # go test -race / go vet
make e2e        # full lifecycle against Vault + OpenBao in Docker
make rpm        # vault + openbao RPM flavours
```

CI (Woodpecker) runs pre-commit/build/lint/test on PRs and builds+publishes the
RPMs on a `v*` tag. The unit tests include real-`gpg` and real-`pass` interop
checks (skipped automatically when those binaries are absent).
