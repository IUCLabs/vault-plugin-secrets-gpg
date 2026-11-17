package gpg

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func newTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return b, config.StorageView
}

func do(t *testing.T, b logical.Backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Data:      data,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("%s %s: err %v", op, path, err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("%s %s: %v", op, path, resp.Error())
	}
	return resp
}

func createKey(t *testing.T, b logical.Backend, s logical.Storage, name, algorithm string) *logical.Response {
	t.Helper()
	return do(t, b, s, logical.CreateOperation, "keys/"+name, map[string]interface{}{
		"algorithm": algorithm,
		"identity":  "Test Key <test@example.com>",
	})
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestKeyLifecycle(t *testing.T) {
	b, s := newTestBackend(t)

	resp := createKey(t, b, s, "app", "rsa-2048")
	if resp.Data["latest_version"].(int) != 1 {
		t.Fatalf("expected latest_version 1, got %v", resp.Data["latest_version"])
	}
	pub, _ := resp.Data["public_key"].(string)
	if !strings.HasPrefix(pub, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Fatalf("public_key not armored: %q", pub[:min(40, len(pub))])
	}

	// Creation is idempotent — same fingerprint, no regeneration.
	fp := resp.Data["fingerprint"].(string)
	resp2 := createKey(t, b, s, "app", "rsa-2048")
	if resp2.Data["fingerprint"].(string) != fp {
		t.Fatal("re-create regenerated the key")
	}

	// List.
	list := do(t, b, s, logical.ListOperation, "keys/", nil)
	if keys, _ := list.Data["keys"].([]string); len(keys) != 1 || keys[0] != "app" {
		t.Fatalf("unexpected list: %v", list.Data["keys"])
	}
}

func TestSignVerify(t *testing.T) {
	b, s := newTestBackend(t)
	createKey(t, b, s, "signer", "ed25519")

	sign := do(t, b, s, logical.UpdateOperation, "sign/signer", map[string]interface{}{
		"input": b64("hello world"),
	})
	sig := sign.Data["signature"].(string)
	if !strings.HasPrefix(sig, "-----BEGIN PGP SIGNATURE-----") {
		t.Fatalf("signature not armored: %q", sig[:min(40, len(sig))])
	}

	ok := do(t, b, s, logical.UpdateOperation, "verify/signer", map[string]interface{}{
		"input":     b64("hello world"),
		"signature": sig,
	})
	if !ok.Data["valid"].(bool) {
		t.Fatal("valid signature reported invalid")
	}

	bad := do(t, b, s, logical.UpdateOperation, "verify/signer", map[string]interface{}{
		"input":     b64("tampered"),
		"signature": sig,
	})
	if bad.Data["valid"].(bool) {
		t.Fatal("tampered message reported valid")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	b, s := newTestBackend(t)
	createKey(t, b, s, "box", "rsa-2048")
	secret := "correct horse battery staple"

	for _, format := range []string{"base64", "ascii-armor"} {
		enc := do(t, b, s, logical.UpdateOperation, "encrypt/box", map[string]interface{}{
			"plaintext": b64(secret),
			"format":    format,
		})
		ct := enc.Data["ciphertext"].(string)

		dec := do(t, b, s, logical.UpdateOperation, "decrypt/box", map[string]interface{}{
			"ciphertext": ct,
		})
		got, _ := base64.StdEncoding.DecodeString(dec.Data["plaintext"].(string))
		if string(got) != secret {
			t.Fatalf("[%s] roundtrip mismatch: %q", format, got)
		}
	}
}

func TestRotateRetainsOldCiphertext(t *testing.T) {
	b, s := newTestBackend(t)
	createKey(t, b, s, "rot", "rsa-2048")

	// Encrypt against version 1.
	enc := do(t, b, s, logical.UpdateOperation, "encrypt/rot", map[string]interface{}{
		"plaintext": b64("v1 secret"),
	})
	oldCt := enc.Data["ciphertext"].(string)

	// Rotate to version 2.
	r := do(t, b, s, logical.UpdateOperation, "keys/rot/rotate", nil)
	if r.Data["latest_version"].(int) != 2 {
		t.Fatalf("expected latest_version 2, got %v", r.Data["latest_version"])
	}

	// Old ciphertext must still decrypt.
	dec := do(t, b, s, logical.UpdateOperation, "decrypt/rot", map[string]interface{}{
		"ciphertext": oldCt,
	})
	got, _ := base64.StdEncoding.DecodeString(dec.Data["plaintext"].(string))
	if string(got) != "v1 secret" {
		t.Fatalf("post-rotation decrypt of v1 ciphertext failed: %q", got)
	}

	// Raising min_decryption_version past v1 locks the old ciphertext out.
	do(t, b, s, logical.UpdateOperation, "keys/rot/config", map[string]interface{}{
		"min_decryption_version": 2,
	})
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/rot",
		Data:      map[string]interface{}{"ciphertext": oldCt},
		Storage:   s,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected decrypt to fail once v1 is below min_decryption_version")
	}
}

func TestExportImportRoundtrip(t *testing.T) {
	b, s := newTestBackend(t)

	do(t, b, s, logical.CreateOperation, "keys/src", map[string]interface{}{
		"algorithm":  "ed25519",
		"identity":   "Exportable <e@example.com>",
		"exportable": true,
	})

	exp := do(t, b, s, logical.ReadOperation, "export/private-key/src", nil)
	keys := exp.Data["keys"].(map[string]interface{})
	priv := keys["1"].(string)
	if !strings.HasPrefix(priv, "-----BEGIN PGP PRIVATE KEY BLOCK-----") {
		t.Fatalf("private key not armored: %q", priv[:min(40, len(priv))])
	}

	do(t, b, s, logical.CreateOperation, "keys/dst/import", map[string]interface{}{
		"private_key": priv,
	})

	// The imported key must sign and verify like any other.
	sign := do(t, b, s, logical.UpdateOperation, "sign/dst", map[string]interface{}{
		"input": b64("imported"),
	})
	ok := do(t, b, s, logical.UpdateOperation, "verify/dst", map[string]interface{}{
		"input":     b64("imported"),
		"signature": sign.Data["signature"].(string),
	})
	if !ok.Data["valid"].(bool) {
		t.Fatal("imported key failed to verify its own signature")
	}
}

func TestDeletionGuard(t *testing.T) {
	b, s := newTestBackend(t)
	createKey(t, b, s, "keep", "rsa-2048")

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/keep",
		Storage:   s,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("delete should be refused when deletion_allowed is false")
	}

	do(t, b, s, logical.UpdateOperation, "keys/keep/config", map[string]interface{}{
		"deletion_allowed": true,
	})
	do(t, b, s, logical.DeleteOperation, "keys/keep", nil)

	if got := do(t, b, s, logical.ReadOperation, "keys/keep", nil); got != nil {
		t.Fatal("key still present after allowed delete")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
