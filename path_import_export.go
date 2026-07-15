package gpg

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathImport(b *gpgBackend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/import",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "gpg",
			OperationSuffix: "key-import",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key.",
				Required:    true,
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: "ASCII-armored OpenPGP private key to import.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"exportable": {
				Type:        framework.TypeBool,
				Description: "Whether the imported private key may later be exported.",
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathImportWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathImportWrite},
		},
		ExistenceCheck:  b.pathKeysExistenceCheck,
		HelpSynopsis:    "Import an existing armored OpenPGP private key.",
		HelpDescription: "Register an externally-generated private key as version 1 of a new named key.",
	}
}

func (b *gpgBackend) pathImportWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	armored := data.Get("private_key").(string)
	if armored == "" {
		return logical.ErrorResponse("private_key is required"), logical.ErrInvalidRequest
	}

	lock := b.lockForKey(name)
	lock.Lock()
	defer lock.Unlock()

	existing, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("key %q already exists", name), logical.ErrInvalidRequest
	}

	key, err := newImportedKey(name, armored, data.Get("exportable").(bool), time.Now())
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if err := b.putKey(ctx, req.Storage, key); err != nil {
		return nil, err
	}
	return b.keyResponse(key)
}

func pathExport(b *gpgBackend) *framework.Path {
	return &framework.Path{
		Pattern: "export/" + framework.GenericNameRegex("type") + "/" + framework.GenericNameRegex("name") + "(/" + framework.GenericNameRegex("version") + ")?",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "gpg",
			OperationSuffix: "export",
		},
		Fields: map[string]*framework.FieldSchema{
			"type": {
				Type:        framework.TypeString,
				Description: "Material to export: public-key or private-key.",
				Required:    true,
			},
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key.",
				Required:    true,
			},
			"version": {
				Type:        framework.TypeString,
				Description: "Specific version to export. Omit to export all versions.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathExportRead},
		},
		HelpSynopsis:    "Export the public (or, if exportable, private) armored key.",
		HelpDescription: "public-key is always exportable and is what gpg/pass import to encrypt to this key. private-key requires the key to be marked exportable.",
	}
}

func (b *gpgBackend) pathExportRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	exportType := data.Get("type").(string)
	name := data.Get("name").(string)
	versionArg := data.Get("version").(string)

	switch exportType {
	case "public-key", "private-key":
	default:
		return logical.ErrorResponse("invalid export type %q (must be public-key or private-key)", exportType), logical.ErrInvalidRequest
	}

	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, nil
	}
	if exportType == "private-key" && !key.Exportable {
		return logical.ErrorResponse("key %q is not exportable", name), logical.ErrInvalidRequest
	}

	render := func(v int) (string, error) {
		if exportType == "public-key" {
			return key.publicKeyArmored(v)
		}
		kv, ok := key.Versions[v]
		if !ok {
			return "", fmt.Errorf("version %d does not exist", v)
		}
		return kv.PrivateKey, nil
	}

	keys := map[string]interface{}{}
	if versionArg != "" {
		v, err := strconv.Atoi(versionArg)
		if err != nil {
			return logical.ErrorResponse("invalid version %q", versionArg), logical.ErrInvalidRequest
		}
		if v == 0 {
			v = key.LatestVersion
		}
		material, err := render(v)
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		keys[strconv.Itoa(v)] = material
	} else {
		for v := range key.Versions {
			material, err := render(v)
			if err != nil {
				return nil, err
			}
			keys[strconv.Itoa(v)] = material
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name": key.Name,
			"type": exportType,
			"keys": keys,
		},
	}, nil
}
