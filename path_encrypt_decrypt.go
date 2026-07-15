package gpg

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathEncrypt(b *gpgBackend) *framework.Path {
	return &framework.Path{
		Pattern: "encrypt/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "gpg",
			OperationSuffix: "encrypt",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key to encrypt to.",
				Required:    true,
			},
			"plaintext": {
				Type:        framework.TypeString,
				Description: "Base64-encoded plaintext to encrypt.",
			},
			"format": {
				Type:        framework.TypeString,
				Description: "Ciphertext encoding: base64 (default, raw binary OpenPGP) or ascii-armor.",
				Default:     "base64",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathEncryptWrite},
		},
		HelpSynopsis:    "Encrypt plaintext to the key's latest public version.",
		HelpDescription: "Produces an OpenPGP message decryptable via decrypt/<name> or with the exported private key.",
	}
}

func (b *gpgBackend) pathEncryptWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	plaintext, err := base64.StdEncoding.DecodeString(data.Get("plaintext").(string))
	if err != nil {
		return logical.ErrorResponse("plaintext must be valid base64: %s", err), logical.ErrInvalidRequest
	}

	asciiArmor, errResp := parseEncFormat(data.Get("format").(string))
	if errResp != nil {
		return errResp, logical.ErrInvalidRequest
	}

	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return logical.ErrorResponse("key %q not found", name), logical.ErrInvalidRequest
	}

	ciphertext, err := key.encrypt(plaintext, asciiArmor)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	out := base64.StdEncoding.EncodeToString(ciphertext)
	if asciiArmor {
		out = string(ciphertext)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext":  out,
			"key_version": key.LatestVersion,
		},
	}, nil
}

func pathDecrypt(b *gpgBackend) *framework.Path {
	return &framework.Path{
		Pattern: "decrypt/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "gpg",
			OperationSuffix: "decrypt",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key to decrypt with.",
				Required:    true,
			},
			"ciphertext": {
				Type:        framework.TypeString,
				Description: "The OpenPGP message: ASCII-armored, or base64-encoded raw binary (as `pass`/`gpg` write by default).",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathDecryptWrite},
		},
		HelpSynopsis:    "Decrypt an OpenPGP message with the key's private material.",
		HelpDescription: "Tries every key version at or above min_decryption_version. Accepts armored or binary ciphertext.",
	}
}

func (b *gpgBackend) pathDecryptWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	ciphertext := decodeCiphertext(data.Get("ciphertext").(string))

	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return logical.ErrorResponse("key %q not found", name), logical.ErrInvalidRequest
	}

	plaintext, err := key.decrypt(ciphertext)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		},
	}, nil
}

// decodeCiphertext passes armored input through untouched and base64-decodes
// everything else back to raw binary OpenPGP.
func decodeCiphertext(ciphertext string) []byte {
	if len(ciphertext) > len(armorPrefix) && ciphertext[:len(armorPrefix)] == armorPrefix {
		return []byte(ciphertext)
	}
	if raw, err := base64.StdEncoding.DecodeString(ciphertext); err == nil {
		return raw
	}
	return []byte(ciphertext)
}

// parseEncFormat resolves the base64 / ascii-armor selector for ciphertext.
func parseEncFormat(format string) (asciiArmor bool, errResp *logical.Response) {
	switch format {
	case "", "base64":
		return false, nil
	case "ascii-armor":
		return true, nil
	default:
		return false, logical.ErrorResponse("invalid format %q (must be base64 or ascii-armor)", format)
	}
}
