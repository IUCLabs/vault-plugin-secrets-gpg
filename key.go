package gpg

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	pgpMessageType = "PGP MESSAGE"
	armorPrefix    = "-----BEGIN PGP"
)

// keyVersion is one generation of a named GPG key. Each version is a complete,
// self-contained OpenPGP entity (its own fingerprint), so rotating a key never
// invalidates data that was signed or encrypted against an earlier version.
type keyVersion struct {
	Version      int       `json:"version"`
	CreationTime time.Time `json:"creation_time"`
	Fingerprint  string    `json:"fingerprint"`
	KeyID        string    `json:"key_id"`
	// PrivateKey is the ASCII-armored OpenPGP private key for this version.
	PrivateKey string `json:"private_key"`
}

// gpgKey is the transit-style, versioned key stored (barrier-encrypted and
// seal-wrapped) under key/<name>.
type gpgKey struct {
	Name                 string             `json:"name"`
	Algorithm            string             `json:"algorithm"`
	Identity             string             `json:"identity"`
	Versions             map[int]keyVersion `json:"versions"`
	LatestVersion        int                `json:"latest_version"`
	MinDecryptionVersion int                `json:"min_decryption_version"`
	DeletionAllowed      bool               `json:"deletion_allowed"`
	Exportable           bool               `json:"exportable"`
	Imported             bool               `json:"imported"`
	CreationTime         time.Time          `json:"creation_time"`
}

// packetConfig maps our algorithm labels onto an OpenPGP generation config.
func packetConfig(algorithm string) (*packet.Config, error) {
	cfg := &packet.Config{DefaultHash: crypto.SHA256}
	switch algorithm {
	case "rsa-2048":
		cfg.Algorithm = packet.PubKeyAlgoRSA
		cfg.RSABits = 2048
	case "", "rsa-3072":
		cfg.Algorithm = packet.PubKeyAlgoRSA
		cfg.RSABits = 3072
	case "rsa-4096":
		cfg.Algorithm = packet.PubKeyAlgoRSA
		cfg.RSABits = 4096
	case "ed25519":
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
	default:
		return nil, fmt.Errorf("unsupported algorithm %q (supported: rsa-2048, rsa-3072, rsa-4096, ed25519)", algorithm)
	}
	return cfg, nil
}

// parseIdentity splits "Name (comment) <email>" into its parts. Any part may be
// absent; a bare string is treated as the name.
func parseIdentity(identity string) (name, comment, email string) {
	s := strings.TrimSpace(identity)
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j > 0 {
			email = strings.TrimSpace(s[i+1 : i+j])
			s = strings.TrimSpace(s[:i])
		}
	}
	if i := strings.LastIndex(s, "("); i >= 0 {
		if j := strings.Index(s[i:], ")"); j > 0 {
			comment = strings.TrimSpace(s[i+1 : i+j])
			s = strings.TrimSpace(s[:i])
		}
	}
	name = strings.TrimSpace(s)
	return name, comment, email
}

// newKey generates version 1 of a fresh named key.
func newKey(name, algorithm, identity string, exportable bool, now time.Time) (*gpgKey, error) {
	kv, err := generateVersion(algorithm, identity, 1, now)
	if err != nil {
		return nil, err
	}
	return &gpgKey{
		Name:                 name,
		Algorithm:            algorithm,
		Identity:             identity,
		Versions:             map[int]keyVersion{1: kv},
		LatestVersion:        1,
		MinDecryptionVersion: 1,
		Exportable:           exportable,
		CreationTime:         now,
	}, nil
}

// newImportedKey wraps an externally-generated armored private key as version 1.
func newImportedKey(name, armoredPrivate string, exportable bool, now time.Time) (*gpgKey, error) {
	e, err := readArmoredEntity(armoredPrivate)
	if err != nil {
		return nil, fmt.Errorf("parsing imported key: %w", err)
	}
	if e.PrivateKey == nil {
		return nil, errors.New("imported material contains no private key")
	}
	kv := keyVersion{
		Version:      1,
		CreationTime: now,
		Fingerprint:  fmt.Sprintf("%X", e.PrimaryKey.Fingerprint),
		KeyID:        e.PrimaryKey.KeyIdString(),
		PrivateKey:   armoredPrivate,
	}
	return &gpgKey{
		Name:                 name,
		Algorithm:            algoLabel(e),
		Identity:             entityIdentity(e),
		Versions:             map[int]keyVersion{1: kv},
		LatestVersion:        1,
		MinDecryptionVersion: 1,
		Exportable:           exportable,
		Imported:             true,
		CreationTime:         now,
	}, nil
}

// rotate appends a new key version and makes it the latest.
func (k *gpgKey) rotate(now time.Time) error {
	if k.Imported {
		return errors.New("cannot rotate an imported key")
	}
	v := k.LatestVersion + 1
	kv, err := generateVersion(k.Algorithm, k.Identity, v, now)
	if err != nil {
		return err
	}
	k.Versions[v] = kv
	k.LatestVersion = v
	return nil
}

func generateVersion(algorithm, identity string, version int, now time.Time) (keyVersion, error) {
	name, comment, email := parseIdentity(identity)
	cfg, err := packetConfig(algorithm)
	if err != nil {
		return keyVersion{}, err
	}
	cfg.Time = func() time.Time { return now }

	e, err := openpgp.NewEntity(name, comment, email, cfg)
	if err != nil {
		return keyVersion{}, fmt.Errorf("generating openpgp entity: %w", err)
	}
	armored, err := armorPrivateKey(e)
	if err != nil {
		return keyVersion{}, err
	}
	return keyVersion{
		Version:      version,
		CreationTime: now,
		Fingerprint:  fmt.Sprintf("%X", e.PrimaryKey.Fingerprint),
		KeyID:        e.PrimaryKey.KeyIdString(),
		PrivateKey:   armored,
	}, nil
}

// entityForVersion re-parses the stored armored private key for a version.
func (k *gpgKey) entityForVersion(v int) (*openpgp.Entity, error) {
	kv, ok := k.Versions[v]
	if !ok {
		return nil, fmt.Errorf("key version %d does not exist", v)
	}
	return readArmoredEntity(kv.PrivateKey)
}

// verifyKeyring returns the public keys of every version (for verifying
// signatures made under any generation of the key).
func (k *gpgKey) verifyKeyring() (openpgp.EntityList, error) {
	var list openpgp.EntityList
	for v := 1; v <= k.LatestVersion; v++ {
		if _, ok := k.Versions[v]; !ok {
			continue
		}
		e, err := k.entityForVersion(v)
		if err != nil {
			return nil, err
		}
		list = append(list, e)
	}
	return list, nil
}

// decryptionKeyring returns the private keys of every version at or above
// min_decryption_version, so archived ciphertext still opens after rotation.
func (k *gpgKey) decryptionKeyring() (openpgp.EntityList, error) {
	var list openpgp.EntityList
	for v := k.MinDecryptionVersion; v <= k.LatestVersion; v++ {
		if _, ok := k.Versions[v]; !ok {
			continue
		}
		e, err := k.entityForVersion(v)
		if err != nil {
			return nil, err
		}
		list = append(list, e)
	}
	if len(list) == 0 {
		return nil, errors.New("no decryption-eligible key versions")
	}
	return list, nil
}

// publicKeyArmored returns the ASCII-armored public key for a version. This is
// the value you feed to `gpg --import` / `pass init <fingerprint>`.
func (k *gpgKey) publicKeyArmored(v int) (string, error) {
	e, err := k.entityForVersion(v)
	if err != nil {
		return "", err
	}
	return armorPublicKey(e)
}

// encrypt OpenPGP-encrypts plaintext to the latest version's public key.
func (k *gpgKey) encrypt(plaintext []byte, asciiArmor bool) ([]byte, error) {
	e, err := k.entityForVersion(k.LatestVersion)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	var sink io.Writer = &buf
	var armorWriter io.WriteCloser
	if asciiArmor {
		armorWriter, err = armor.Encode(&buf, pgpMessageType, nil)
		if err != nil {
			return nil, err
		}
		sink = armorWriter
	}

	w, err := openpgp.Encrypt(sink, []*openpgp.Entity{e}, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if armorWriter != nil {
		if err := armorWriter.Close(); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// decrypt opens ciphertext with any eligible private version. It accepts both
// ASCII-armored input and raw binary OpenPGP messages (what `pass`/`gpg` write
// by default), auto-detecting which it was given.
func (k *gpgKey) decrypt(ciphertext []byte) ([]byte, error) {
	keyring, err := k.decryptionKeyring()
	if err != nil {
		return nil, err
	}

	r, err := dearmorIfNeeded(ciphertext)
	if err != nil {
		return nil, err
	}
	md, err := openpgp.ReadMessage(r, keyring, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting message: %w", err)
	}
	return io.ReadAll(md.UnverifiedBody)
}

// sign produces a detached signature over message using the given version
// (0 = latest).
func (k *gpgKey) sign(message []byte, version int, asciiArmor bool) ([]byte, error) {
	if version == 0 {
		version = k.LatestVersion
	}
	e, err := k.entityForVersion(version)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if asciiArmor {
		err = openpgp.ArmoredDetachSign(&buf, e, bytes.NewReader(message), nil)
	} else {
		err = openpgp.DetachSign(&buf, e, bytes.NewReader(message), nil)
	}
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return buf.Bytes(), nil
}

// verify checks a detached signature against every public version. A malformed
// or non-matching signature returns (false, nil); only unexpected failures
// return an error.
func (k *gpgKey) verify(message, signature []byte) (bool, error) {
	keyring, err := k.verifyKeyring()
	if err != nil {
		return false, err
	}
	sigReader, err := dearmorIfNeeded(signature)
	if err != nil {
		return false, nil
	}
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(message), sigReader, nil); err != nil {
		return false, nil
	}
	return true, nil
}

// --- OpenPGP (de)serialization helpers ---

func armorPrivateKey(e *openpgp.Entity) (string, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", err
	}
	if err := e.SerializePrivate(w, nil); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func armorPublicKey(e *openpgp.Entity) (string, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}
	if err := e.Serialize(w); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func readArmoredEntity(a string) (*openpgp.Entity, error) {
	block, err := armor.Decode(strings.NewReader(a))
	if err != nil {
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}

// dearmorIfNeeded returns a reader over the raw OpenPGP packets, transparently
// stripping ASCII armor when present.
func dearmorIfNeeded(data []byte) (io.Reader, error) {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte(armorPrefix)) {
		block, err := armor.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return block.Body, nil
	}
	return bytes.NewReader(data), nil
}

func entityIdentity(e *openpgp.Entity) string {
	for _, id := range e.Identities {
		return id.Name
	}
	return ""
}

func algoLabel(e *openpgp.Entity) string {
	switch e.PrimaryKey.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		if bl, err := e.PrimaryKey.BitLength(); err == nil {
			return fmt.Sprintf("rsa-%d", bl)
		}
		return "rsa"
	case packet.PubKeyAlgoEdDSA, packet.PubKeyAlgoEd25519:
		return "ed25519"
	case packet.PubKeyAlgoECDSA:
		return "ecdsa"
	default:
		return "unknown"
	}
}
