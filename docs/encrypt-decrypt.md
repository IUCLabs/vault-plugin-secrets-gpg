# Encrypt and decrypt

Messages are standard OpenPGP messages. Anything encrypted to the key's public
key, whether by this engine, `gpg` or `pass`, can be decrypted here.

## Encrypt

`POST /gpg/encrypt/:name`

Encrypts to the latest key version.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `plaintext` | string | required | Base64-encoded plaintext. |
| `format` | string | `base64` | `base64` (base64-encoded binary OpenPGP), or `ascii-armor`. |

The response has `ciphertext` and `key_version`.

```sh
vault write -field=ciphertext gpg/encrypt/app plaintext=$(base64 <<<"secret")
vault write -field=ciphertext gpg/encrypt/app plaintext=$(base64 <<<"secret") format=ascii-armor
```

## Decrypt

`POST /gpg/decrypt/:name`

Tries every key version at or above `min_decryption_version`. The engine
detects whether the input is armored or binary.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ciphertext` | string | ASCII-armored message, or base64-encoded binary (the format `gpg`/`pass` write by default). |

The response has `plaintext` (base64).

```sh
vault write -field=plaintext gpg/decrypt/app ciphertext="$ct" | base64 -d

# decrypt a file written by gpg or pass
vault write -field=plaintext gpg/decrypt/app \
  ciphertext=$(base64 -w0 ~/.password-store/email/example.gpg) | base64 -d
```
