// Package gpg implements a Vault / OpenBao secrets engine that manages GPG /
// OpenPGP keys and performs signing, verification, encryption and decryption
// with them — a transit-style engine whose key material happens to be OpenPGP.
//
// Keys are generated and stored inside Vault's own barrier storage (seal-wrapped
// under key/) and never leave it unless explicitly marked exportable. Each named
// key is versioned: rotating adds a new OpenPGP entity while older versions are
// retained so archived signatures still verify and old ciphertext still decrypts.
//
// The exported public key is a standard, importable OpenPGP key, so tools like
// `gpg` and `pass` can encrypt to it while the private key stays in Vault and
// decryption is delegated back to the decrypt/<name> path.
package gpg

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const keyPrefix = "key/"

type gpgBackend struct {
	*framework.Backend

	// locks serializes read-modify-write cycles per key name (rotate, config,
	// delete), following the transit engine's pattern.
	locks []*locksutil.LockEntry
}

// Factory returns a configured gpg secrets backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *gpgBackend {
	b := &gpgBackend{
		locks: locksutil.CreateLocks(),
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{keyPrefix},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathKeys(b),
				pathKeysList(b),
				pathKeyConfig(b),
				pathRotate(b),
				pathImport(b),
				pathExport(b),
				pathSign(b),
				pathVerify(b),
				pathEncrypt(b),
				pathDecrypt(b),
			},
		),
	}

	return b
}

func (b *gpgBackend) lockForKey(name string) *locksutil.LockEntry {
	return locksutil.LockForKey(b.locks, name)
}

// getKey loads a named key from storage, returning (nil, nil) when absent.
func (b *gpgBackend) getKey(ctx context.Context, s logical.Storage, name string) (*gpgKey, error) {
	entry, err := s.Get(ctx, keyPrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	key := &gpgKey{}
	if err := entry.DecodeJSON(key); err != nil {
		return nil, err
	}
	if key.Versions == nil {
		key.Versions = map[int]keyVersion{}
	}
	return key, nil
}

func (b *gpgBackend) putKey(ctx context.Context, s logical.Storage, key *gpgKey) error {
	entry, err := logical.StorageEntryJSON(keyPrefix+key.Name, key)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

const backendHelp = `
The gpg secrets engine manages OpenPGP keys and performs cryptographic
operations with them without the private key ever leaving Vault.

Generate or import a key under keys/<name>, then use sign, verify, encrypt and
decrypt just as you would with transit. Keys are versioned: keys/<name>/rotate
adds a new generation while older versions keep working for decrypt and verify.

The armored public key returned by keys/<name> (or export/public-key/<name>) is
a standard OpenPGP key that gpg, pass and other tooling can import and encrypt
to; decryption is delegated back to decrypt/<name>.
`
