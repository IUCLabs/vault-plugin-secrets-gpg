package gpg

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotate(b *gpgBackend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/rotate",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "gpg",
			OperationSuffix: "key-rotate",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotateWrite},
		},
		HelpSynopsis:    "Add a new version to a key.",
		HelpDescription: "Generate a fresh OpenPGP entity as the new latest version. Older versions are retained for decryption and verification.",
	}
}

func (b *gpgBackend) pathRotateWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	lock := b.lockForKey(name)
	lock.Lock()
	defer lock.Unlock()

	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return logical.ErrorResponse("key %q not found", name), logical.ErrInvalidRequest
	}
	if err := key.rotate(time.Now()); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if err := b.putKey(ctx, req.Storage, key); err != nil {
		return nil, err
	}
	return b.keyResponse(key)
}
