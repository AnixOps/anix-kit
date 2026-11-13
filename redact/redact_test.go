package redact

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Redact []struct{ In, Out string }
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Redact) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range file.Redact {
		if got := Redact(v.In); got != v.Out {
			t.Errorf("Redact(%q)\n got %q\nwant %q", v.In, got, v.Out)
		}
	}
}

func TestAccount(t *testing.T) {
	got := Account("/home/alice/app crashed for alice and alicebob", "/home/alice", "alice")
	if want := "~/app crashed for <user> and alicebob"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := Account("al here", "/x", "al"); got != "al here" {
		t.Fatalf("short names must be left alone: %q", got)
	}
}
