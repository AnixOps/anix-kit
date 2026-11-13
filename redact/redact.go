// Package redact removes personal data from text that leaves a user's
// hands: crash reports, diagnostics, log tails. It is the AnixOps rule set
// AnixOps Net applies on the client (crates/client-health redact), so a
// server that receives a report, or a program that exports its own logs,
// redacts the same way.
//
// Each run of token characters is looked at on its own and replaced when
// it is a URL (<url>), an e-mail address (<email>), an IPv4 or IPv6
// address with an optional port (<ip>), a UUID (<id>), a long key-like
// token (<secret>) or a host name (<host>). Source file names (main.rs:12)
// and code paths (std::panicking) are kept, since a crash report needs
// them. Account replaces a home directory and an account name.
//
// testdata/vectors.json holds input and expected output pairs; every
// implementation of the rule set checks itself against them.
package redact

import (
	"net/netip"
	"strings"
	"unicode"
)

// fileExtensions mark a token as a file name rather than a host.
var fileExtensions = map[string]bool{
	"rs": true, "toml": true, "json": true, "txt": true, "swift": true, "so": true, "dll": true,
	"exe": true, "dylib": true, "md": true, "log": true, "ts": true, "tsx": true, "js": true,
	"c": true, "h": true,
}

func isTokenChar(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsNumber(c) || strings.ContainsRune("._-:/@%+=?&#~[]", c)
}

// Redact returns text with personal data replaced.
func Redact(text string) string {
	var out strings.Builder
	start := -1
	for i, c := range text {
		if isTokenChar(c) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out.WriteString(token(text[start:i]))
			start = -1
		}
		out.WriteRune(c)
	}
	if start >= 0 {
		out.WriteString(token(text[start:]))
	}
	return out.String()
}

// Account replaces home (when longer than 3 bytes) with "~" and the
// account name user (3 bytes or more) with "<user>" where it is a whole
// word, then applies Redact.
func Account(text, home, user string) string {
	if len(home) > 3 {
		text = strings.ReplaceAll(text, home, "~")
	}
	if len(user) >= 3 {
		text = replaceWord(text, user, "<user>")
	}
	return Redact(text)
}

func replaceWord(text, word, with string) string {
	var out strings.Builder
	rest := text
	for {
		at := strings.Index(rest, word)
		if at < 0 {
			break
		}
		before := lastRune(rest[:at])
		after := firstRune(rest[at+len(word):])
		out.WriteString(rest[:at])
		if alnum(before) || alnum(after) {
			out.WriteString(word)
		} else {
			out.WriteString(with)
		}
		rest = rest[at+len(word):]
	}
	out.WriteString(rest)
	return out.String()
}

func lastRune(s string) rune {
	r := []rune(s)
	if len(r) == 0 {
		return 0
	}
	return r[len(r)-1]
}

func firstRune(s string) rune {
	for _, r := range s {
		return r
	}
	return 0
}

func alnum(c rune) bool {
	return c != 0 && (unicode.IsLetter(c) || unicode.IsNumber(c))
}

func token(t string) string {
	// Trailing sentence punctuation stays outside the token.
	core := strings.TrimRight(t, ".:,")
	if replaced := classify(core); replaced != "" {
		return replaced + t[len(core):]
	}
	return t
}

func classify(t string) string {
	switch {
	case t == "":
		return ""
	case strings.Contains(t, "://"):
		return "<url>"
	case isEmail(t):
		return "<email>"
	case isIP(t):
		return "<ip>"
	case isUUID(t):
		return "<id>"
	case isSecret(t):
		return "<secret>"
	case isHost(t):
		return "<host>"
	}
	return ""
}

func isEmail(t string) bool {
	user, domain, ok := strings.Cut(t, "@")
	return ok && user != "" && strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".")
}

func isIP(t string) bool {
	host := strings.TrimSuffix(strings.TrimPrefix(stripPort(t), "["), "]")
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Zone() == ""
}

func stripPort(t string) string {
	if rest, ok := strings.CutPrefix(t, "["); ok {
		if host, _, found := strings.Cut(rest, "]"); found {
			return host
		}
		return t
	}
	at := strings.LastIndex(t, ":")
	if at < 0 {
		return t
	}
	host, port := t[:at], t[at+1:]
	if strings.Contains(host, ":") || port == "" || strings.TrimLeft(port, "0123456789") != "" {
		return t
	}
	return host
}

func isUUID(t string) bool {
	groups := strings.Split(t, "-")
	if len(groups) != 5 {
		return false
	}
	for i, n := range []int{8, 4, 4, 4, 12} {
		if len(groups[i]) != n || !isHex(groups[i]) {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for _, b := range []byte(s) {
		if !('0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F') {
			return false
		}
	}
	return true
}

// isSecret: 20 or more base64- or hex-like characters mixing letters and
// digits: keys, passwords, tokens.
func isSecret(t string) bool {
	core := strings.TrimLeft(t, "/=")
	run := ""
	for _, part := range strings.FieldsFunc(core, func(c rune) bool { return strings.ContainsRune("/:?&#@[]", c) }) {
		if len(part) >= 20 {
			run = part
			break
		}
	}
	if run == "" || strings.Contains(run, "..") || isRustSymbol(run) {
		return false
	}
	digit, alpha := false, false
	for _, b := range []byte(run) {
		switch {
		case '0' <= b && b <= '9':
			digit = true
		case 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z':
			alpha = true
		case strings.IndexByte("+=_-.", b) < 0:
			return false
		}
	}
	return digit && alpha
}

// isRustSymbol: hashed symbols in backtraces (h1a2b3c4d5e6f7a8b) are kept.
func isRustSymbol(run string) bool {
	return len(run) == 17 && run[0] == 'h' && isHex(run[1:])
}

// isHost: name.tld or name.tld:port, where the last label is alphabetic
// and not a file extension.
func isHost(t string) bool {
	if strings.Contains(t, "::") || strings.ContainsAny(t, "/@") {
		return false
	}
	labels := strings.Split(stripPort(t), ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
		for _, c := range label {
			if !alnum(c) && c != '-' && c != '_' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 || fileExtensions[strings.ToLower(tld)] {
		return false
	}
	for _, b := range []byte(tld) {
		if !('a' <= b && b <= 'z' || 'A' <= b && b <= 'Z') {
			return false
		}
	}
	return true
}
