# Sign and verify

These paths create and check detached OpenPGP signatures. The input message is
always base64-encoded.

## Sign

`POST /gpg/sign/:name`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input` | string | required | Base64-encoded message to sign. |
| `key_version` | int | `0` (latest) | Key version to sign with. |
| `format` | string | `ascii-armor` | `ascii-armor`, or `base64` for a raw binary signature. |

The response has `signature`.

```sh
vault write -field=signature gpg/sign/app input=$(base64 -w0 release.tar.gz) > release.tar.gz.asc

# check it with gpg, using the exported public key
vault read -field=public_key gpg/keys/app | gpg --import
gpg --verify release.tar.gz.asc release.tar.gz
```

## Verify

`POST /gpg/verify/:name`

Checks the signature against every key version.

| Parameter | Type | Description |
|-----------|------|-------------|
| `input` | string | Base64-encoded message that was signed. |
| `signature` | string | Detached signature, either ASCII-armored or base64-encoded binary. |

The response has `valid` (`true` or `false`). A malformed signature returns
`valid=false`, not an error.

```sh
vault write -field=valid gpg/verify/app \
  input=$(base64 -w0 release.tar.gz) signature=@release.tar.gz.asc
```
