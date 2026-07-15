package gpg

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathKeyConfig(b *gpgBackend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "gpg",
			OperationSuffix: "key-config",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key.",
				Required:    true,
			},
			"min_decryption_version": {
				Type:        framework.TypeInt,
				Description: "Minimum key version usable for decryption and verification. Versions below this can no longer open data.",
			},
			"deletion_allowed": {
				Type:        framework.TypeBool,
				Description: "Whether the key may be deleted.",
			},
			"exportable": {
				Type:        framework.TypeBool,
				Description: "Enable export of the private key. Once enabled it cannot be disabled.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathKeyConfigWrite},
		},
		HelpSynopsis:    "Tune deletion, exportability and the minimum decryption version of a key.",
		HelpDescription: "Update mutable policy on a key without touching its material.",
	}
}

func (b *gpgBackend) pathKeyConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	lock := b.lockForKey(name)
	lock.Lock()
	defer lock.Unlock()

	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, nil
	}

	if v, ok := data.GetOk("min_decryption_version"); ok {
		mdv := v.(int)
		if mdv < 1 || mdv > key.LatestVersion {
			return logical.ErrorResponse("min_decryption_version must be between 1 and the latest version (%d)", key.LatestVersion), logical.ErrInvalidRequest
		}
		key.MinDecryptionVersion = mdv
	}
	if v, ok := data.GetOk("deletion_allowed"); ok {
		key.DeletionAllowed = v.(bool)
	}
	if v, ok := data.GetOk("exportable"); ok {
		exportable := v.(bool)
		if key.Exportable && !exportable {
			return logical.ErrorResponse("exportable cannot be disabled once enabled"), logical.ErrInvalidRequest
		}
		key.Exportable = exportable
	}

	if err := b.putKey(ctx, req.Storage, key); err != nil {
		return nil, err
	}
	return b.keyResponse(key)
}
