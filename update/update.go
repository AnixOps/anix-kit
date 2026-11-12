// Package update is the AnixOps signed update feed: the document an
// installed program fetches to learn about new releases, and the checks a
// downloaded release must pass before it is installed. AnixOps Net for
// macOS shipped it first (format "anixops-appcast-v1"); every updater of an
// AnixOps product uses the same format, one product name per program and
// platform ("anixops-net-macos", "anixops-net-windows", ...).
//
// The feed URL serves a JSON envelope {"format", "payload", "signature"}:
// payload is the Feed JSON as base64, signature the sign-format Ed25519
// signature over FeedPrefix + the payload bytes. Signing the bytes as they
// are needs no canonical JSON. Each item carries its own signature over
// ArchiveMessage, which binds the archive's size and digest to the product
// and build, so a signed archive of one build cannot pass as another, and
// the distinct prefixes keep a feed signature from passing as an archive
// signature.
//
// Every check fails closed: a feed no trusted key verifies, a feed of
// another product, an older sequence than the last one accepted (a replayed
// feed hiding a newer release), an item that is not HTTPS or malformed, an
// archive whose size, digest or signature differ from its item.
//
// Like every AnixOps format this one only grows: deployed programs verify
// with it.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AnixOps/anix-kit/sign"
)

// Wire constants.
const (
	Format        = "anixops-appcast-v1"
	Schema        = 1
	FeedPrefix    = "anixops-appcast-v1\n"
	ArchivePrefix = "anixops-update-archive-v1\n"
)

// Errors a check returns; wrapped with detail where there is some.
var (
	ErrMalformed      = errors.New("update: malformed feed")
	ErrFeedSignature  = errors.New("update: feed signature does not verify")
	ErrWrongProduct   = errors.New("update: feed is for another product")
	ErrStale          = errors.New("update: feed is older than one already accepted")
	ErrItem           = errors.New("update: malformed item")
	ErrInsecureURL    = errors.New("update: item URL is not HTTPS")
	ErrArchive        = errors.New("update: archive does not match its item")
	ErrArchiveSigning = errors.New("update: archive signature does not verify")
)

// Item is one signed release.
type Item struct {
	// Version is shown to the user.
	Version string `json:"version"`
	// Build orders releases; an update must have a higher build than the
	// running program.
	Build int `json:"build"`
	// MinimumSystemVersion is the oldest OS version the build runs on:
	// "14", "14.2" or "14.2.1".
	MinimumSystemVersion string `json:"minimumSystemVersion"`
	// URL of the archive; HTTPS only.
	URL    string `json:"url"`
	Length int64  `json:"length"`
	// SHA256 is 64 lowercase hex digits.
	SHA256 string `json:"sha256"`
	// Signature is the sign-format signature over ArchiveMessage.
	Signature   string     `json:"signature"`
	Notes       string     `json:"notes,omitempty"`
	PublishedAt *time.Time `json:"publishedAt,omitempty"`
}

// Feed is the signed payload.
type Feed struct {
	Schema  int    `json:"schema"`
	Product string `json:"product"`
	// Channel is informational; the feed URL selects the channel.
	Channel string `json:"channel"`
	// Sequence grows with every published feed.
	Sequence    int64     `json:"sequence"`
	GeneratedAt time.Time `json:"generatedAt"`
	Items       []Item    `json:"items"`
}

// Envelope is the document served at the feed URL.
type Envelope struct {
	Format    string `json:"format"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// FeedMessage is what a feed signature covers.
func FeedMessage(payload []byte) []byte {
	return append([]byte(FeedPrefix), payload...)
}

// ArchiveMessage is what an archive signature covers.
func ArchiveMessage(product string, build int, length int64, sha256Hex string) []byte {
	return []byte(fmt.Sprintf("%s%s\n%d\n%d\n%s", ArchivePrefix, product, build, length, strings.ToLower(sha256Hex)))
}

// Verifier checks feeds and archives of one product against the public
// keys the program ships. More than one key lets a new key roll out before
// the old one is retired.
type Verifier struct {
	Product string
	Keys    []ed25519.PublicKey
}

// NewVerifier parses sign-format public keys; at least one is required.
func NewVerifier(product string, publicKeys []string) (*Verifier, error) {
	if len(publicKeys) == 0 {
		return nil, sign.ErrKey
	}
	v := &Verifier{Product: product}
	for _, text := range publicKeys {
		key, err := sign.ParsePublicKey(text)
		if err != nil {
			return nil, err
		}
		v.Keys = append(v.Keys, key)
	}
	return v, nil
}

// VerifyFeed verifies a downloaded envelope and returns its feed.
// lastAccepted is the highest sequence accepted before (0 when none); an
// older feed is refused, the same one is accepted again.
func (v *Verifier) VerifyFeed(data []byte, lastAccepted int64) (*Feed, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, ErrMalformed
	}
	if env.Format != Format {
		return nil, fmt.Errorf("%w: format %q", ErrMalformed, env.Format)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, ErrMalformed
	}
	if !v.verify(FeedMessage(payload), env.Signature) {
		return nil, ErrFeedSignature
	}
	// Only signed bytes are parsed from here on.
	var feed Feed
	if err := json.Unmarshal(payload, &feed); err != nil {
		return nil, ErrMalformed
	}
	if feed.Schema != Schema {
		return nil, fmt.Errorf("%w: schema %d", ErrMalformed, feed.Schema)
	}
	if feed.Product != v.Product {
		return nil, fmt.Errorf("%w: %q", ErrWrongProduct, feed.Product)
	}
	if feed.Sequence < lastAccepted {
		return nil, fmt.Errorf("%w: sequence %d < %d", ErrStale, feed.Sequence, lastAccepted)
	}
	for _, item := range feed.Items {
		if err := Validate(item); err != nil {
			return nil, err
		}
	}
	return &feed, nil
}

// VerifyArchive reads the downloaded archive and checks its size, digest
// and signature against item. Run it on the file the installer will open,
// after the download finished and before anything opens it.
func (v *Verifier) VerifyArchive(r io.Reader, item Item) error {
	if err := Validate(item); err != nil {
		return err
	}
	length, digest, err := Digest(r)
	if err != nil {
		return err
	}
	if length != item.Length || digest != strings.ToLower(item.SHA256) {
		return ErrArchive
	}
	if !v.verify(ArchiveMessage(v.Product, item.Build, length, digest), item.Signature) {
		return ErrArchiveSigning
	}
	return nil
}

func (v *Verifier) verify(message []byte, signature string) bool {
	for _, key := range v.Keys {
		if sign.Verify(key, message, signature) == nil {
			return true
		}
	}
	return false
}

// Newest returns the item with the highest build above currentBuild that
// runs on systemVersion, or nil.
func Newest(feed *Feed, currentBuild int, systemVersion string) *Item {
	system, ok := parseSystemVersion(systemVersion)
	if !ok {
		return nil
	}
	var best *Item
	for i := range feed.Items {
		item := &feed.Items[i]
		minimum, ok := parseSystemVersion(item.MinimumSystemVersion)
		if !ok || item.Build <= currentBuild || older(system, minimum) {
			continue
		}
		if best == nil || item.Build > best.Build {
			best = item
		}
	}
	return best
}

// Validate checks an item's fields.
func Validate(item Item) error {
	u, err := url.Parse(item.URL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return fmt.Errorf("%w: build %d", ErrInsecureURL, item.Build)
	}
	sig, err := base64.StdEncoding.DecodeString(item.Signature)
	digest, hexErr := hex.DecodeString(item.SHA256)
	_, versionOK := parseSystemVersion(item.MinimumSystemVersion)
	if item.Build <= 0 || item.Length <= 0 || err != nil || len(sig) != ed25519.SignatureSize ||
		hexErr != nil || len(digest) != sha256.Size || !versionOK {
		return fmt.Errorf("%w: build %d", ErrItem, item.Build)
	}
	return nil
}

// Digest returns the size and lowercase hex SHA-256 of r.
func Digest(r io.Reader) (int64, string, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// ArchiveSignature signs an item of product with this build, size and
// digest. Release pipelines only; programs never hold a private key.
func ArchiveSignature(key ed25519.PrivateKey, product string, build int, length int64, sha256Hex string) string {
	return sign.Sign(key, ArchiveMessage(product, build, length, sha256Hex))
}

// SignFeed encodes feed and returns the envelope to serve. Times are
// written in whole seconds, UTC, the form every verifier reads.
func SignFeed(key ed25519.PrivateKey, feed Feed) ([]byte, error) {
	feed.GeneratedAt = feed.GeneratedAt.UTC().Truncate(time.Second)
	items := make([]Item, len(feed.Items))
	for i, item := range feed.Items {
		if item.PublishedAt != nil {
			t := item.PublishedAt.UTC().Truncate(time.Second)
			item.PublishedAt = &t
		}
		items[i] = item
	}
	feed.Items = items
	payload, err := json.Marshal(feed)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(Envelope{
		Format:    Format,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: sign.Sign(key, FeedMessage(payload)),
	}, "", "  ")
}

type systemVersion [3]int

func parseSystemVersion(text string) (systemVersion, bool) {
	var v systemVersion
	parts := strings.Split(text, ".")
	if len(parts) > 3 {
		return v, false
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func older(a, b systemVersion) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
