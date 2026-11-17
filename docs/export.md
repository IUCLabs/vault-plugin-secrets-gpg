# Export

`GET /gpg/export/:type/:name(/:version)`

Returns armored key material. `public-key` can always be exported, and is what
`gpg` or `pass` imports to encrypt to the key. `private-key` works only if the
key is `exportable`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | `public-key` or `private-key`. |
| `name` | string | Name of the key. |
| `version` | int | Version to export. `0` means the latest version. Leave it out to export every version. |

The response has `name`, `type` and `keys`. `keys` maps each version number to
its armored key.

```sh
# all public versions
vault read gpg/export/public-key/app

# latest public key, ready for gpg
vault read -format=json gpg/export/public-key/app/0 \
  | jq -r '.data.keys | to_entries[0].value' | gpg --import

# private key of version 1 (key must be exportable)
vault read gpg/export/private-key/app/1
```
