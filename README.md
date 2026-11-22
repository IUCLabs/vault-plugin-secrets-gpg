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

Release assets download through artifactapi's GitHub proxy, which serves
`https://artifactapi.k8s.syd1.au.unkin.net/api/v1/remote/github/IUCLabs/vault-plugin-secrets-gpg/releases/download/<tag>/<file>`.
Each method below ends with `SHA256` set for [registration](#register-and-enable).
With OpenBao, use `bao` in place of `vault`.

```sh
TAG=vX.Y.Z  # the release to install
V=${TAG#v}
BASE=https://artifactapi.k8s.syd1.au.unkin.net/api/v1/remote/github/IUCLabs/vault-plugin-secrets-gpg/releases/download/$TAG
```

### RPM

Install the Vault RPM or the OpenBao RPM, not both. Set the server's
`plugin_directory` to the directory the RPM installs into.

Vault: installs `/usr/libexec/vault-plugins/vault-plugin-secrets-gpg`.

```sh
dnf install vault-plugin-secrets-gpg  # from a yum repo carrying it, or from the release:
dnf install "$BASE/vault-plugin-secrets-gpg-$V-1.x86_64.rpm"

SHA256=$(sha256sum /usr/libexec/vault-plugins/vault-plugin-secrets-gpg | cut -d' ' -f1)
```

OpenBao: installs `/usr/libexec/openbao-plugins/vault-plugin-secrets-gpg`.

```sh
dnf install openbao-plugin-secrets-gpg  # from a yum repo carrying it, or from the release:
dnf install "$BASE/openbao-plugin-secrets-gpg-$V-1.x86_64.rpm"

SHA256=$(sha256sum /usr/libexec/openbao-plugins/vault-plugin-secrets-gpg | cut -d' ' -f1)
```

### Released binary

`vault-plugin-secrets-gpg_<version>_SHA256SUMS` lists the binary and the RPMs.

```sh
curl -fLO "$BASE/vault-plugin-secrets-gpg_${V}_linux_amd64"
curl -fLO "$BASE/vault-plugin-secrets-gpg_${V}_SHA256SUMS"
sha256sum --check --ignore-missing "vault-plugin-secrets-gpg_${V}_SHA256SUMS"

install -m 0755 "vault-plugin-secrets-gpg_${V}_linux_amd64" <plugin_directory>/vault-plugin-secrets-gpg
SHA256=$(sha256sum <plugin_directory>/vault-plugin-secrets-gpg | cut -d' ' -f1)
```

### Kubernetes image volume

`ghcr.io/iuclabs/vault-plugin-secrets-gpg:<tag>` is a `FROM scratch` image holding only
`/vault-plugin-secrets-gpg`. Mount it read-only into the Vault/OpenBao container with an
[image volume](https://kubernetes.io/docs/concepts/storage/volumes/#image):
Image volumes are beta from Kubernetes 1.33 but off by default (enable the
`ImageVolume` feature gate), on by default from 1.35, and GA in 1.36. Vault and OpenBao only run a binary that sits directly in
`plugin_directory`, not in a subdirectory, so mount the file itself with
`subPath`, which on image volumes needs 1.33+.

```yaml
spec:
  containers:
    - name: vault
      volumeMounts:
        - name: plugin-gpg
          mountPath: /vault/plugins/vault-plugin-secrets-gpg  # <plugin_directory>/vault-plugin-secrets-gpg
          subPath: vault-plugin-secrets-gpg
          readOnly: true
  volumes:
    - name: plugin-gpg
      image:
        reference: ghcr.io/iuclabs/vault-plugin-secrets-gpg:vX.Y.Z
        pullPolicy: IfNotPresent
```

The image holds the released binary, so its sha256 is the `linux_amd64` line
of `SHA256SUMS`:

```sh
SHA256=$(curl -fsSL "$BASE/vault-plugin-secrets-gpg_${V}_SHA256SUMS" | awk '/_linux_amd64$/ {print $1}')
```

### From source

```sh
make build  # writes ./dist/vault-plugin-secrets-gpg
```

Copy it into `plugin_directory` and take `SHA256` from `sha256sum` as above.

### Register and enable

```sh
vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-gpg
vault secrets enable -path=gpg vault-plugin-secrets-gpg
```

After replacing the binary, register the new sha256 and reload the plugin:

```sh
vault write sys/plugins/reload/backend plugin=vault-plugin-secrets-gpg
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
