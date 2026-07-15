package gpg

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathSign(b *gpgBackend) *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "gpg",
			OperationSuffix: "sign",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key to sign with.",
				Required:    true,
			},
			"input": {
				Type:        framework.TypeString,
				Description: "Base64-encoded message to sign.",
			},
			"key_version": {
				Type:        framework.TypeInt,
				Description: "Key version to sign with (0 or omitted = latest).",
				Default:     0,
			},
			"format": {
				Type:        framework.TypeString,
				Description: "Signature encoding: ascii-armor (default) or base64 (raw binary detached signature).",
				Default:     "ascii-armor",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathSignWrite},
		},
		HelpSynopsis:    "Produce a detached OpenPGP signature over the input.",
		HelpDescription: "Signs with the key's primary signing key. Verify elsewhere with gpg or the verify/<name> path.",
	}
}

func (b *gpgBackend) pathSignWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	message, err := base64.StdEncoding.DecodeString(data.Get("input").(string))
	if err != nil {
		return logical.ErrorResponse("input must be valid base64: %s", err), logical.ErrInvalidRequest
	}

	asciiArmor, errResp := parseFormat(data.Get("format").(string))
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

	sig, err := key.sign(message, data.Get("key_version").(int), asciiArmor)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	signature := string(sig)
	if !asciiArmor {
		signature = base64.StdEncoding.EncodeToString(sig)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"signature": signature,
		},
	}, nil
}

func pathVerify(b *gpgBackend) *framework.Path {
	return &framework.Path{
		Pattern: "verify/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "gpg",
			OperationSuffix: "verify",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key to verify against.",
				Required:    true,
			},
			"input": {
				Type:        framework.TypeString,
				Description: "Base64-encoded message that was signed.",
			},
			"signature": {
				Type:        framework.TypeString,
				Description: "The detached signature: ASCII-armored, or base64-encoded raw binary.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathVerifyWrite},
		},
		HelpSynopsis:    "Verify a detached OpenPGP signature over the input.",
		HelpDescription: "Checks the signature against every version of the key; returns valid=true/false.",
	}
}

func (b *gpgBackend) pathVerifyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	message, err := base64.StdEncoding.DecodeString(data.Get("input").(string))
	if err != nil {
		return logical.ErrorResponse("input must be valid base64: %s", err), logical.ErrInvalidRequest
	}

	signature := decodeSignature(data.Get("signature").(string))

	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return logical.ErrorResponse("key %q not found", name), logical.ErrInvalidRequest
	}

	valid, err := key.verify(message, signature)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"valid": valid,
		},
	}, nil
}

// decodeSignature accepts an armored signature verbatim, or decodes a base64
// raw-binary one. If it is neither, the original bytes are returned and
// verification will simply fail.
func decodeSignature(sig string) []byte {
	if len(sig) > len(armorPrefix) && sig[:len(armorPrefix)] == armorPrefix {
		return []byte(sig)
	}
	if raw, err := base64.StdEncoding.DecodeString(sig); err == nil {
		return raw
	}
	return []byte(sig)
}

// parseFormat resolves the ascii-armor / base64 format selector.
func parseFormat(format string) (asciiArmor bool, errResp *logical.Response) {
	switch format {
	case "", "ascii-armor":
		return true, nil
	case "base64":
		return false, nil
	default:
		return false, logical.ErrorResponse("invalid format %q (must be ascii-armor or base64)", format)
	}
}
