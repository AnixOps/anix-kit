// Command anixsign signs and verifies in the AnixOps format (package sign).
//
//	anixsign keygen KEY.pem          write a new private key (0600), print its public key and id
//	anixsign pub KEY.pem             print the public key of a private key
//	anixsign id PUBLIC_KEY           print the key id of a public key (base64 or PEM file)
//	anixsign digest FILE             print the SHA-256 of FILE
//	anixsign sign KEY.pem FILE       print the signature of FILE
//	anixsign verify PUBLIC_KEY FILE SIGNATURE_FILE
//
// PUBLIC_KEY is the base64 raw key or a path to a file holding it.
package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/AnixOps/anix-kit/sign"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "anixsign:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: anixsign keygen|pub|id|digest|sign|verify ...")
	}
	need := map[string]int{"keygen": 1, "pub": 1, "id": 1, "digest": 1, "sign": 2, "verify": 3}
	n, ok := need[args[0]]
	if !ok || len(args)-1 != n {
		return fmt.Errorf("%s: wrong command or argument count", args[0])
	}
	a := args[1:]
	switch args[0] {
	case "keygen":
		pub, priv, err := sign.GenerateKey()
		if err != nil {
			return err
		}
		data, err := sign.MarshalPrivateKey(priv)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(a[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Println(sign.EncodePublicKey(pub), sign.KeyID(pub))
	case "pub":
		priv, err := privateKey(a[0])
		if err != nil {
			return err
		}
		fmt.Println(sign.EncodePublicKey(priv.Public().(ed25519.PublicKey)))
	case "id":
		pub, err := publicKey(a[0])
		if err != nil {
			return err
		}
		fmt.Println(sign.KeyID(pub))
	case "digest":
		data, err := os.ReadFile(a[0])
		if err != nil {
			return err
		}
		fmt.Println(sign.Digest(data))
	case "sign":
		priv, err := privateKey(a[0])
		if err != nil {
			return err
		}
		data, err := os.ReadFile(a[1])
		if err != nil {
			return err
		}
		fmt.Println(sign.Sign(priv, data))
	case "verify":
		pub, err := publicKey(a[0])
		if err != nil {
			return err
		}
		data, err := os.ReadFile(a[1])
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(a[2])
		if err != nil {
			return err
		}
		if err := sign.Verify(pub, data, string(sig)); err != nil {
			return err
		}
		fmt.Println("OK", sign.KeyID(pub))
	}
	return nil
}

func privateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return sign.ParsePrivateKey(data)
}

// publicKey takes the key itself or a file holding it.
func publicKey(value string) (ed25519.PublicKey, error) {
	if data, err := os.ReadFile(value); err == nil {
		value = string(data)
	}
	return sign.ParsePublicKey(value)
}
