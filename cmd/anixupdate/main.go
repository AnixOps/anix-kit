// Command anixupdate builds and checks signed update feeds (package update).
//
//	anixupdate item KEY.pem PRODUCT VERSION BUILD MIN_SYSTEM URL ARCHIVE
//	    print the signed item JSON of ARCHIVE
//	anixupdate feed KEY.pem PRODUCT CHANNEL SEQUENCE ITEMS.json
//	    print the signed feed; ITEMS.json is a JSON array of items
//	anixupdate verify PUBLIC_KEYS PRODUCT FEED [ARCHIVE BUILD]
//	    verify a feed and, given ARCHIVE, the item of BUILD against it
//
// KEY.pem is a sign-format private key (anixsign keygen). PUBLIC_KEYS is a
// comma-separated list of base64 keys, or a path to a file holding one.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AnixOps/anix-kit/sign"
	"github.com/AnixOps/anix-kit/update"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "anixupdate:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: anixupdate item|feed|verify ...")
	}
	a := args[1:]
	switch {
	case args[0] == "item" && len(a) == 7:
		key, err := privateKey(a[0])
		if err != nil {
			return err
		}
		build, err := strconv.Atoi(a[3])
		if err != nil {
			return err
		}
		f, err := os.Open(a[6])
		if err != nil {
			return err
		}
		length, digest, err := update.Digest(f)
		f.Close()
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Second)
		item := update.Item{
			Version:              a[2],
			Build:                build,
			MinimumSystemVersion: a[4],
			URL:                  a[5],
			Length:               length,
			SHA256:               digest,
			Signature:            update.ArchiveSignature(key, a[1], build, length, digest),
			PublishedAt:          &now,
		}
		if err := update.Validate(item); err != nil {
			return err
		}
		return printJSON(out, item)
	case args[0] == "feed" && len(a) == 5:
		key, err := privateKey(a[0])
		if err != nil {
			return err
		}
		sequence, err := strconv.ParseInt(a[3], 10, 64)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(a[4])
		if err != nil {
			return err
		}
		var items []update.Item
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		for _, item := range items {
			if err := update.Validate(item); err != nil {
				return err
			}
		}
		signed, err := update.SignFeed(key, update.Feed{
			Schema:      update.Schema,
			Product:     a[1],
			Channel:     a[2],
			Sequence:    sequence,
			GeneratedAt: time.Now(),
			Items:       items,
		})
		if err != nil {
			return err
		}
		fmt.Fprintln(out, string(signed))
	case args[0] == "verify" && (len(a) == 3 || len(a) == 5):
		keys := a[0]
		if data, err := os.ReadFile(keys); err == nil {
			keys = string(data)
		}
		v, err := update.NewVerifier(a[1], strings.Split(strings.TrimSpace(keys), ","))
		if err != nil {
			return err
		}
		data, err := os.ReadFile(a[2])
		if err != nil {
			return err
		}
		feed, err := v.VerifyFeed(data, 0)
		if err != nil {
			return err
		}
		if len(a) == 5 {
			build, err := strconv.Atoi(a[4])
			if err != nil {
				return err
			}
			if err := verifyArchive(v, feed, a[3], build); err != nil {
				return err
			}
		}
		fmt.Fprintln(out, "OK sequence", feed.Sequence, "items", len(feed.Items))
	default:
		return fmt.Errorf("%s: wrong command or argument count", args[0])
	}
	return nil
}

func verifyArchive(v *update.Verifier, feed *update.Feed, path string, build int) error {
	for _, item := range feed.Items {
		if item.Build != build {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return v.VerifyArchive(f, item)
	}
	return fmt.Errorf("feed has no item of build %d", build)
}

func privateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return sign.ParsePrivateKey(data)
}

func printJSON(out io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}
