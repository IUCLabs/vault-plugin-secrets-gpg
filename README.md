# vault-plugin-secrets-gpg

A secrets engine for HashiCorp Vault and OpenBao that manages OpenPGP (GPG)
keys and signs, verifies, encrypts and decrypts with them. Think of it as the
transit engine, but the keys are OpenPGP keys.

### Why use this plugin?

Private keys are generated and stored in Vault's barrier storage. They never
leave Vault unless you mark a key `exportable`. The engine hands out a
standard armored public key, so `gpg`, [`pass`](https://www.passwordstore.org/)
and other OpenPGP tools can encrypt to the key. Decryption goes back through
Vault. Keys are versioned: when you rotate a key, older versions stay
available, so old signatures still verify and old ciphertext still decrypts.

To manage the engine's mounts and keys from Terraform or OpenTofu, use
[terraform-provider-vault-secrets-gpg](https://github.com/IUCLabs/terraform-provider-vault-secrets-gpg).

## Requirements

- HashiCorp Vault or OpenBao. The same binary works on both. The end-to-end
  tests run against Vault 1.18 and the latest OpenBao release.
- Go 1.25+ (only if you build from source)

## Installation

Download a binary from the
[releases page](https://github.com/IUCLabs/vault-plugin-secrets-gpg/releases),
or build one:

```sh
make build   # -> dist/vault-plugin-secrets-gpg
```

Copy the binary into the server's `plugin_directory`, then register it in the
plugin catalog and enable the engine. On OpenBao, run the same commands with
`bao` in place of `vault`.
The example assumes `plugin_directory = "/etc/vault/plugins"`; use the
directory set in your server config.

```sh
SHA256=$(sha256sum /etc/vault/plugins/vault-plugin-secrets-gpg | cut -d' ' -f1)
vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-gpg
vault secrets enable -path=gpg vault-plugin-secrets-gpg
```

## Usage

The engine has no mount-level configuration. Each key holds its own settings
(see [keys](docs/keys.md)).

All binary input and output is base64-encoded.

```sh
# create a key (repeating the write returns the existing key)
vault write gpg/keys/app algorithm=rsa-4096 identity="App <app@example.com>"
vault read gpg/keys/app

# sign / verify
sig=$(vault write -field=signature gpg/sign/app input=$(base64 <<<"ship it"))
vault write -field=valid gpg/verify/app input=$(base64 <<<"ship it") signature="$sig"

# encrypt / decrypt
ct=$(vault write -field=ciphertext gpg/encrypt/app plaintext=$(base64 <<<"secret"))
vault write -field=plaintext gpg/decrypt/app ciphertext="$ct" | base64 -d

# rotate; ciphertext from older versions still decrypts
vault write gpg/keys/app/rotate
```

### With `pass`

`pass` needs only the public key to encrypt. Decryption goes through Vault.

```sh
vault read -field=public_key gpg/keys/app | gpg --import
pass init "$(vault read -field=fingerprint gpg/keys/app)"
pass insert email/example

vault write -field=plaintext gpg/decrypt/app \
  ciphertext=$(base64 -w0 ~/.password-store/email/example.gpg) | base64 -d
```

## Documentation

Full path reference:

- [Keys](docs/keys.md): `keys/`, `keys/:name`, `keys/:name/config`, `keys/:name/rotate`, `keys/:name/import`
- [Export](docs/export.md): `export/:type/:name(/:version)`
- [Sign and verify](docs/sign-verify.md): `sign/:name`, `verify/:name`
- [Encrypt and decrypt](docs/encrypt-decrypt.md): `encrypt/:name`, `decrypt/:name`

## Development

```sh
make test   # unit tests, including gpg/pass interop when those binaries exist
make lint
make e2e    # full lifecycle against Vault and OpenBao in Docker
```

## License

[MIT](LICENSE)
