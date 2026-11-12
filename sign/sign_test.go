package sign

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pemKey, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePrivateKey(pemKey)
	if err != nil || !parsed.Equal(priv) {
		t.Fatalf("private key round trip: %v", err)
	}
	encoded := EncodePublicKey(pub)
	back, err := ParsePublicKey(" " + encoded + "\n")
	if err != nil || !back.Equal(pub) {
		t.Fatalf("public key round trip: %v", err)
	}
	msg := []byte("release.zip bytes")
	sig := Sign(priv, msg)
	wrapped := sig[:20] + "\n" + sig[20:] + "\n"
	if err := Verify(pub, msg, wrapped); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := Verify(pub, []byte("other"), sig); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered message verified: %v", err)
	}
	if err := Verify(pub, msg, "not base64"); !errors.Is(err, ErrSignature) {
		t.Fatalf("garbage signature: %v", err)
	}
}

// The fixtures pin the formats deployed products verify with.
func TestFormatsAreStable(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	if got, want := EncodePublicKey(pub), "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="; got != want {
		t.Fatalf("public key = %s, want %s", got, want)
	}
	if got, want := KeyID(pub), "139e3940e64b5491"; got != want {
		t.Fatalf("key id = %s, want %s", got, want)
	}
	if got, want := Digest([]byte("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Fatalf("digest = %s", got)
	}
	pemPub := "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAO2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=\n-----END PUBLIC KEY-----\n"
	fromPEM, err := ParsePublicKey(pemPub)
	if err != nil || !fromPEM.Equal(pub) {
		t.Fatalf("PEM public key: %v", err)
	}
	if _, err := ParsePublicKey("AAAA"); !errors.Is(err, ErrKey) {
		t.Fatalf("short key accepted: %v", err)
	}
}
