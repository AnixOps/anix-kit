package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-kit/sign"
)

const product = "anixops-net-macos"

func pair(t *testing.T) (ed25519.PrivateKey, *Verifier) {
	t.Helper()
	pub, priv, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(product, []string{sign.EncodePublicKey(pub)})
	if err != nil {
		t.Fatal(err)
	}
	return priv, v
}

func item(key ed25519.PrivateKey, build int, archive []byte) Item {
	length, digest, _ := Digest(bytes.NewReader(archive))
	return Item{
		Version:              "0.3." + strconv.Itoa(build),
		Build:                build,
		MinimumSystemVersion: "14.0",
		URL:                  "https://updates.example.com/AnixOps-Net.pkg",
		Length:               length,
		SHA256:               digest,
		Signature:            ArchiveSignature(key, product, build, length, digest),
		Notes:                "Fixes.",
	}
}

func signed(t *testing.T, key ed25519.PrivateKey, sequence int64, items ...Item) []byte {
	t.Helper()
	data, err := SignFeed(key, Feed{
		Schema:      Schema,
		Product:     product,
		Channel:     "stable",
		Sequence:    sequence,
		GeneratedAt: time.Unix(1_800_000_000, 123_000_000),
		Items:       items,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRoundTrip(t *testing.T) {
	key, v := pair(t)
	archive := []byte("installer package")
	data := signed(t, key, 5, item(key, 7, archive))

	feed, err := v.VerifyFeed(data, 5)
	if err != nil {
		t.Fatalf("verify feed: %v", err)
	}
	if err := v.VerifyArchive(bytes.NewReader(archive), feed.Items[0]); err != nil {
		t.Fatalf("verify archive: %v", err)
	}
	// The payload carries whole-second UTC times, the form Swift's .iso8601 reads.
	var env Envelope
	_ = json.Unmarshal(data, &env)
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	if !strings.Contains(string(payload), `"generatedAt":"2027-01-15T08:00:00Z"`) {
		t.Fatalf("generatedAt not in whole seconds UTC: %s", payload)
	}
}

func TestFeedRefusals(t *testing.T) {
	key, v := pair(t)
	stranger, _ := pair(t)
	good := signed(t, key, 5, item(key, 7, []byte("x")))

	var env Envelope
	_ = json.Unmarshal(good, &env)
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	tampered := env
	tampered.Payload = base64.StdEncoding.EncodeToString(bytes.Replace(payload, []byte("example.com"), []byte("evil.example"), 1))
	tamperedData, _ := json.Marshal(tampered)

	otherProduct, _ := SignFeed(key, Feed{Schema: Schema, Product: "anixops-net-windows", Sequence: 5})
	insecure := item(key, 7, []byte("x"))
	insecure.URL = "http://updates.example.com/AnixOps-Net.pkg"
	badItem := item(key, 7, []byte("x"))
	badItem.SHA256 = "zz"

	cases := []struct {
		name string
		data []byte
		last int64
		want error
	}{
		{"not json", []byte("<html>"), 0, ErrMalformed},
		{"tampered payload", tamperedData, 0, ErrFeedSignature},
		{"another key", signed(t, stranger, 5), 0, ErrFeedSignature},
		{"replayed old feed", good, 6, ErrStale},
		{"another product", otherProduct, 0, ErrWrongProduct},
		{"plain http item", signed(t, key, 5, insecure), 0, ErrInsecureURL},
		{"malformed item", signed(t, key, 5, badItem), 0, ErrItem},
	}
	for _, c := range cases {
		if _, err := v.VerifyFeed(c.data, c.last); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestArchiveRefusals(t *testing.T) {
	key, v := pair(t)
	stranger, _ := pair(t)
	archive := []byte("installer package")
	it := item(key, 7, archive)

	if err := v.VerifyArchive(bytes.NewReader([]byte("installer pack")), it); !errors.Is(err, ErrArchive) {
		t.Errorf("truncated archive: %v", err)
	}
	if err := v.VerifyArchive(bytes.NewReader([]byte("installer packagE")), it); !errors.Is(err, ErrArchive) {
		t.Errorf("replaced archive: %v", err)
	}
	moved := it
	moved.Build = 8 // a signed archive of build 7 presented as build 8
	if err := v.VerifyArchive(bytes.NewReader(archive), moved); !errors.Is(err, ErrArchiveSigning) {
		t.Errorf("archive of another build: %v", err)
	}
	if err := v.VerifyArchive(bytes.NewReader(archive), item(stranger, 7, archive)); !errors.Is(err, ErrArchiveSigning) {
		t.Errorf("archive signed by another key: %v", err)
	}
}

func TestNewest(t *testing.T) {
	key, _ := pair(t)
	a, b, c := item(key, 5, nil), item(key, 7, nil), item(key, 9, nil)
	c.MinimumSystemVersion = "15.1"
	feed := &Feed{Items: []Item{a, c, b}}

	if got := Newest(feed, 4, "14.6.1"); got == nil || got.Build != 7 {
		t.Fatalf("newest on 14.6.1: %+v", got)
	}
	if got := Newest(feed, 4, "15.1"); got == nil || got.Build != 9 {
		t.Fatalf("newest on 15.1: %+v", got)
	}
	if got := Newest(feed, 9, "15.1"); got != nil {
		t.Fatalf("no downgrade or same build: %+v", got)
	}
}

// A feed and archive signed by the AnixOps Net macOS tests' Python fixture
// (RFC 8032 section 7.1 test 1 key), so the Go and Swift verifiers read the
// same bytes the same way.
func TestForeignFeed(t *testing.T) {
	seed, _ := base64.StdEncoding.DecodeString("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if sign.EncodePublicKey(pub) != "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" {
		t.Fatal("RFC 8032 test key mismatch")
	}
	v, err := NewVerifier(product, []string{sign.EncodePublicKey(pub)})
	if err != nil {
		t.Fatal(err)
	}
	feed, err := v.VerifyFeed([]byte(foreignFeed), 3)
	if err != nil {
		t.Fatalf("foreign feed: %v", err)
	}
	if feed.Items[0].Version != "0.3.1" || !feed.GeneratedAt.Equal(time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("foreign feed content: %+v", feed)
	}
	if err := v.VerifyArchive(strings.NewReader("AnixOps Net test archive\n"), feed.Items[0]); err != nil {
		t.Fatalf("foreign archive: %v", err)
	}
}

const foreignFeed = `{"format": "anixops-appcast-v1", "payload": "eyJzY2hlbWEiOjEsInByb2R1Y3QiOiJhbml4b3BzLW5ldC1tYWNvcyIsImNoYW5uZWwiOiJzdGFibGUiLCJzZXF1ZW5jZSI6MywiZ2VuZXJhdGVkQXQiOiIyMDI2LTExLTEyVDAwOjAwOjAwWiIsIml0ZW1zIjpbeyJ2ZXJzaW9uIjoiMC4zLjEiLCJidWlsZCI6NywibWluaW11bVN5c3RlbVZlcnNpb24iOiIxNC4wIiwidXJsIjoiaHR0cHM6Ly91cGRhdGVzLmV4YW1wbGUuY29tL0FuaXhPcHMtTmV0LTAuMy4xLnBrZyIsImxlbmd0aCI6MjUsInNoYTI1NiI6ImY3YzRkZDk2ZDRjMjlkNjY1NDViZTBkMmU3NjNkMzM2MTQzYjFhYmUxNzE5MTU5MDVlYmY2MjBjNGI1Y2RiNGIiLCJzaWduYXR1cmUiOiJZVUc5Nk9iVEtRUko1Q1EvOFhPWWpaY2gxcEE3WFVNVHR4YUs2ZmJjVU4zZ2d3L2d0VlBFcmNDcXdKUjIxMVErWDZNUDAzY1dGUmZaZ0xDRWhkcWtDZz09Iiwibm90ZXMiOiJGaXh0dXJlIn1dfQ==", "signature": "HBMWShgz+pwjkGGCirsHxQVRmWGL0XGPGp9UiIfSi0fK7iaS+siOKzJh0nclL40Bn2ohA065mTHDLGKsobMEBg=="}`
