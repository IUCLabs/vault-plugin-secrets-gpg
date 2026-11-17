package gpg

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathKeys(b *gpgBackend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "gpg",
			OperationSuffix: "key",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key.",
				Required:    true,
			},
			"algorithm": {
				Type:        framework.TypeString,
				Description: "Key algorithm: rsa-2048, rsa-3072 (default), rsa-4096 or ed25519.",
				Default:     "rsa-3072",
			},
			"identity": {
				Type:        framework.TypeString,
				Description: `OpenPGP User ID for the key, e.g. "Jane Doe <jane@example.com>". Defaults to the key name.`,
			},
			"exportable": {
				Type:        framework.TypeBool,
				Description: "Whether the private key may be exported via export/private-key. Cannot be unset once enabled.",
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathKeysWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathKeysWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathKeysRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathKeysDelete},
		},
		ExistenceCheck:  b.pathKeysExistenceCheck,
		HelpSynopsis:    "Generate and manage a named GPG key.",
		HelpDescription: "Create a versioned OpenPGP key, read its metadata and armored public key, or delete it.",
	}
}

func pathKeysList(b *gpgBackend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "gpg",
			OperationSuffix: "keys",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathKeysList},
		},
		HelpSynopsis: "List named GPG keys.",
	}
}

func (b *gpgBackend) pathKeysExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	key, err := b.getKey(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return key != nil, nil
}

func (b *gpgBackend) pathKeysWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing key name"), nil
	}

	lock := b.lockForKey(name)
	lock.Lock()
	defer lock.Unlock()

	existing, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		// Creation is idempotent: return the existing key rather than
		// regenerating and destroying its material.
		return b.keyResponse(existing)
	}

	algorithm := data.Get("algorithm").(string)
	identity := data.Get("identity").(string)
	if identity == "" {
		identity = name
	}
	exportable := data.Get("exportable").(bool)

	key, err := newKey(name, algorithm, identity, exportable, time.Now())
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := b.putKey(ctx, req.Storage, key); err != nil {
		return nil, err
	}
	return b.keyResponse(key)
}

func (b *gpgBackend) pathKeysRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	key, err := b.getKey(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, nil
	}
	return b.keyResponse(key)
}

func (b *gpgBackend) pathKeysDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	if !key.DeletionAllowed {
		return logical.ErrorResponse("deletion is not allowed for this key; enable it via keys/%s/config deletion_allowed=true", name), logical.ErrInvalidRequest
	}
	if err := req.Storage.Delete(ctx, keyPrefix+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *gpgBackend) pathKeysList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

// keyResponse renders a key's metadata plus the armored public key of every
// version. The top-level public_key is the latest version, for convenience.
func (b *gpgBackend) keyResponse(key *gpgKey) (*logical.Response, error) {
	versions := map[string]interface{}{}
	for v, kv := range key.Versions {
		pub, err := key.publicKeyArmored(v)
		if err != nil {
			return nil, fmt.Errorf("rendering public key for version %d: %w", v, err)
		}
		versions[fmt.Sprintf("%d", v)] = map[string]interface{}{
			"creation_time": kv.CreationTime.Format(time.RFC3339),
			"fingerprint":   kv.Fingerprint,
			"key_id":        kv.KeyID,
			"public_key":    pub,
		}
	}

	latestPub, err := key.publicKeyArmored(key.LatestVersion)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":                   key.Name,
			"algorithm":              key.Algorithm,
			"identity":               key.Identity,
			"latest_version":         key.LatestVersion,
			"min_decryption_version": key.MinDecryptionVersion,
			"deletion_allowed":       key.DeletionAllowed,
			"exportable":             key.Exportable,
			"imported":               key.Imported,
			"creation_time":          key.CreationTime.Format(time.RFC3339),
			"fingerprint":            key.Versions[key.LatestVersion].Fingerprint,
			"public_key":             latestPub,
			"keys":                   versions,
		},
	}, nil
}
