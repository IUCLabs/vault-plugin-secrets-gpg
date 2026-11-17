# Keys

These paths create, read, configure, rotate, import, list and delete named
OpenPGP keys. All examples assume the engine is mounted at `gpg/`.

Every key is versioned. Each version is a separate OpenPGP entity with its own
fingerprint. Private keys are stored seal-wrapped.

## Create key

`POST /gpg/keys/:name`

Generates a new key. Creating a key is idempotent: if the key already exists,
the request returns it unchanged and does not regenerate it.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | string | required | Name of the key (in the URL). |
| `algorithm` | string | `rsa-3072` | One of `rsa-2048`, `rsa-3072`, `rsa-4096`, `ed25519`. |
| `identity` | string | key name | OpenPGP User ID, e.g. `Jane Doe <jane@example.com>`. |
| `exportable` | bool | `false` | Allow the private key to be exported. Once enabled, this cannot be disabled. |

```sh
vault write gpg/keys/app algorithm=ed25519 identity="App <app@example.com>"
```

## Read key

`GET /gpg/keys/:name`

Returns key metadata and the armored public key of every version.

```sh
vault read gpg/keys/app
```

| Field | Description |
|-------|-------------|
| `name`, `algorithm`, `identity` | As set at creation. |
| `latest_version` | Highest key version. |
| `min_decryption_version` | Lowest version used for decryption. |
| `deletion_allowed`, `exportable` | Key policy. |
| `imported` | `true` if the key was imported, not generated. |
| `creation_time` | RFC 3339 timestamp. |
| `fingerprint`, `public_key` | Fingerprint and armored public key of the latest version. |
| `keys` | Map of version to `creation_time`, `fingerprint`, `key_id`, `public_key`. |

The create, config, rotate and import endpoints return the same response.

## List keys

`LIST /gpg/keys`

```sh
vault list gpg/keys
```

## Delete key

`DELETE /gpg/keys/:name`

Deletes the key and all of its versions. This fails unless `deletion_allowed`
has been set to `true` through the config endpoint.

```sh
vault write gpg/keys/app/config deletion_allowed=true
vault delete gpg/keys/app
```

## Configure key

`POST /gpg/keys/:name/config`

Changes key policy. The key material is not touched. Only the parameters you
send are changed.

| Parameter | Type | Description |
|-----------|------|-------------|
| `min_decryption_version` | int | Lowest version usable for decryption. Must be between 1 and `latest_version`. |
| `deletion_allowed` | bool | Whether the key may be deleted. |
| `exportable` | bool | Allow private key export. Once enabled, this cannot be disabled. |

```sh
vault write gpg/keys/app/config min_decryption_version=2
```

## Rotate key

`POST /gpg/keys/:name/rotate`

Generates a new version with the same algorithm and identity, and makes it the
latest version. Older versions are kept, so older ciphertext still decrypts and
older signatures still verify. Decryption is limited to versions at or above
`min_decryption_version`.

Imported keys cannot be rotated; the request fails with
`cannot rotate an imported key`.

```sh
vault write -field=latest_version gpg/keys/app/rotate
```

## Import key

`POST /gpg/keys/:name/import`

Imports an existing armored OpenPGP private key as version 1 of a new key.
This fails if the name is already in use.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `private_key` | string | required | ASCII-armored private key. It must not be passphrase-protected. |
| `exportable` | bool | `false` | Allow the private key to be exported again later. |

```sh
gpg --export-secret-keys --armor app@example.com > app.asc
vault write gpg/keys/app/import private_key=@app.asc
```
