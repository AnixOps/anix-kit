package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/AnixOps/anix-kit/sign"
)

func TestItemFeedVerify(t *testing.T) {
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	pub, priv, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pemKey, _ := sign.MarshalPrivateKey(priv)
	write := func(name string, data []byte) {
		if err := os.WriteFile(path(name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("key.pem", pemKey)
	write("app.zip", []byte("release bytes"))

	var item bytes.Buffer
	if err := run([]string{"item", path("key.pem"), "anixops-net-windows", "0.3.4", "120", "10.0.19041",
		"https://updates.example.com/app.zip", path("app.zip")}, &item); err != nil {
		t.Fatalf("item: %v", err)
	}
	write("items.json", append(append([]byte("["), item.Bytes()...), ']'))

	var feed bytes.Buffer
	if err := run([]string{"feed", path("key.pem"), "anixops-net-windows", "stable", "4", path("items.json")}, &feed); err != nil {
		t.Fatalf("feed: %v", err)
	}
	write("feed.json", feed.Bytes())

	other, _, _ := sign.GenerateKey()
	keys := sign.EncodePublicKey(other) + "," + sign.EncodePublicKey(pub)
	if err := run([]string{"verify", keys, "anixops-net-windows", path("feed.json"), path("app.zip"), "120"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := run([]string{"verify", keys, "anixops-net-macos", path("feed.json")}, &bytes.Buffer{}); err == nil {
		t.Fatal("feed of another product verified")
	}
	write("app.zip", []byte("release byteZ"))
	if err := run([]string{"verify", keys, "anixops-net-windows", path("feed.json"), path("app.zip"), "120"}, &bytes.Buffer{}); err == nil {
		t.Fatal("tampered archive verified")
	}
	if err := run([]string{"verify", sign.EncodePublicKey(other), "anixops-net-windows", path("feed.json")}, &bytes.Buffer{}); err == nil {
		t.Fatal("feed verified with an untrusted key")
	}
}
