package gpg

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestGPGInterop proves the pass/gpg integration contract end to end using the
// real gpg binary: our exported public key imports into a gpg keyring, gpg
// encrypts to it producing a *binary* OpenPGP message (exactly what `pass`
// writes), and our engine's decrypt path opens it. It also checks the reverse:
// gpg verifies a detached signature the engine produced.
func TestGPGInterop(t *testing.T) {
	gpgBin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed")
	}

	b, s := newTestBackend(t)
	createKey(t, b, s, "pass", "rsa-2048")

	read := do(t, b, s, logical.ReadOperation, "keys/pass", nil)
	pubArmored := read.Data["public_key"].(string)
	fingerprint := read.Data["fingerprint"].(string)

	// Isolated gpg home so we never touch the user's real keyring.
	gnupg := t.TempDir()
	run := func(stdin string, args ...string) (string, string) {
		t.Helper()
		cmd := exec.Command(gpgBin, append([]string{"--homedir", gnupg, "--batch", "--yes", "--trust-model", "always"}, args...)...)
		cmd.Stdin = strings.NewReader(stdin)
		var out, errb strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			t.Fatalf("gpg %v: %v\n%s", args, err, errb.String())
		}
		return out.String(), errb.String()
	}

	// 1. Import the engine's public key into gpg.
	run(pubArmored, "--import")

	// 2. Encrypt with gpg the way pass does: binary (no --armor) OpenPGP.
	secret := "hunter2\n"
	binCipher := filepath.Join(gnupg, "msg.gpg")
	cmd := exec.Command(gpgBin, "--homedir", gnupg, "--batch", "--yes", "--trust-model", "always",
		"-r", fingerprint, "--output", binCipher, "--encrypt")
	cmd.Stdin = strings.NewReader(secret)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gpg encrypt: %v\n%s", err, out)
	}
	binBytes, err := os.ReadFile(binCipher)
	if err != nil {
		t.Fatal(err)
	}

	// 3. The engine decrypts gpg's binary ciphertext (base64-wrapped for the API).
	dec := do(t, b, s, logical.UpdateOperation, "decrypt/pass", map[string]interface{}{
		"ciphertext": base64.StdEncoding.EncodeToString(binBytes),
	})
	got, _ := base64.StdEncoding.DecodeString(dec.Data["plaintext"].(string))
	if string(got) != secret {
		t.Fatalf("engine failed to decrypt gpg's binary ciphertext: %q", got)
	}

	// 4. Reverse direction: engine signs, gpg verifies.
	sign := do(t, b, s, logical.UpdateOperation, "sign/pass", map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte(secret)),
	})
	sigFile := filepath.Join(gnupg, "msg.sig")
	msgFile := filepath.Join(gnupg, "msg.txt")
	if err := os.WriteFile(sigFile, []byte(sign.Data["signature"].(string)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(msgFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	run("", "--verify", sigFile, msgFile)
}

// TestPassInterop drives the actual `pass` binary end to end: it initialises a
// password store against the engine's exported public key, inserts a secret
// (pass shells out to gpg to write a binary .gpg file), and the engine then
// decrypts that file — the real-world flow the engine is built for.
func TestPassInterop(t *testing.T) {
	passBin, err := exec.LookPath("pass")
	if err != nil {
		t.Skip("pass not installed")
	}
	gpgBin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed")
	}

	b, s := newTestBackend(t)
	createKey(t, b, s, "store", "rsa-2048")
	read := do(t, b, s, logical.ReadOperation, "keys/store", nil)
	pubArmored := read.Data["public_key"].(string)
	fingerprint := read.Data["fingerprint"].(string)

	gnupg := t.TempDir()
	storeDir := t.TempDir()
	env := append(os.Environ(),
		"GNUPGHOME="+gnupg,
		"PASSWORD_STORE_DIR="+storeDir,
		// The engine's key is imported without an ownertrust ultimatum, so tell
		// pass's gpg invocations to trust it anyway (as a real deployment would
		// via ownertrust or a signed key).
		"PASSWORD_STORE_GPG_OPTS=--trust-model always",
	)

	// Import the public key so pass/gpg can encrypt to it.
	imp := exec.Command(gpgBin, "--homedir", gnupg, "--batch", "--yes", "--import")
	imp.Stdin = strings.NewReader(pubArmored)
	if out, err := imp.CombinedOutput(); err != nil {
		t.Fatalf("gpg import: %v\n%s", err, out)
	}

	passRun := func(stdin string, args ...string) {
		t.Helper()
		cmd := exec.Command(passBin, args...)
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("pass %v: %v\n%s", args, err, out)
		}
	}

	passRun("", "init", fingerprint)
	passRun("s3cr3t\n", "insert", "--echo", "email/test")

	// pass wrote email/test.gpg as a binary OpenPGP message; decrypt it via the engine.
	gpgFile := filepath.Join(storeDir, "email", "test.gpg")
	binBytes, err := os.ReadFile(gpgFile)
	if err != nil {
		t.Fatalf("reading pass-written file: %v", err)
	}
	dec := do(t, b, s, logical.UpdateOperation, "decrypt/store", map[string]interface{}{
		"ciphertext": base64.StdEncoding.EncodeToString(binBytes),
	})
	got, _ := base64.StdEncoding.DecodeString(dec.Data["plaintext"].(string))
	if strings.TrimSpace(string(got)) != "s3cr3t" {
		t.Fatalf("engine failed to decrypt pass entry: %q", got)
	}
}
