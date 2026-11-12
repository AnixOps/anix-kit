package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/AnixOps/anix-kit/sign"
)

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	file := filepath.Join(dir, "release.zip")
	sig := filepath.Join(dir, "release.zip.sig")
	if err := run([]string{"keygen", key}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(key); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", info, err)
	}
	if err := run([]string{"keygen", key}); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	if err := os.WriteFile(file, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(key)
	priv, err := sign.ParsePrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sig, []byte(sign.Sign(priv, []byte("payload"))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pub := sign.EncodePublicKey(priv.Public().(ed25519.PublicKey))
	if err := run([]string{"verify", pub, file, sig}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := os.WriteFile(file, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", pub, file, sig}); err == nil {
		t.Fatal("tampered file verified")
	}
	if err := run([]string{"sign", key}); err == nil {
		t.Fatal("missing argument accepted")
	}
}
