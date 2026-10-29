package expose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		target  Target
		remote  bool
		wantErr bool
	}{
		{"loopback ok", Target{Name: "ollama", Origin: "http://127.0.0.1:11434"}, false, false},
		{"localhost ok", Target{Name: "ollama", Origin: "http://localhost:11434"}, false, false},
		{"https ok", Target{Name: "lm", Origin: "https://127.0.0.1:8443"}, false, false},
		{"remote refused", Target{Name: "db", Origin: "http://192.168.29.50:5432"}, false, true},
		{"remote allowed by flag", Target{Name: "db", Origin: "http://192.168.29.50:5432"}, true, false},
		{"public host refused", Target{Name: "web", Origin: "http://example.com"}, false, true},
		{"credentials refused", Target{Name: "x", Origin: "http://user:pass@127.0.0.1:8080"}, false, true},
		{"path refused", Target{Name: "x", Origin: "http://127.0.0.1:8080/api"}, false, true},
		{"query refused", Target{Name: "x", Origin: "http://127.0.0.1:8080?a=1"}, false, true},
		{"scheme refused", Target{Name: "x", Origin: "ftp://127.0.0.1:21"}, false, true},
		{"bad name", Target{Name: "My Service!", Origin: "http://127.0.0.1:1"}, false, true},
		{"uppercase name", Target{Name: "Ollama", Origin: "http://127.0.0.1:1"}, false, true},
		{"no host", Target{Name: "x", Origin: "http://"}, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Validate(c.target, c.remote)
			if (err != nil) != c.wantErr {
				t.Fatalf("Validate = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestNormalizeOrigin(t *testing.T) {
	cases := map[string]string{
		"11434":                 "http://127.0.0.1:11434",
		"127.0.0.1:11434":       "http://127.0.0.1:11434",
		"localhost:11434/":      "http://localhost:11434",
		"http://127.0.0.1:8080": "http://127.0.0.1:8080",
		"  localhost:3000  ":    "http://localhost:3000",
		"":                      "",
	}
	for in, want := range cases {
		if got := NormalizeOrigin(in); got != want {
			t.Errorf("NormalizeOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("a fresh store should be empty")
	}

	if err := s.Add(Target{Name: "ollama", Origin: "http://127.0.0.1:11434", Description: "local models"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, ok := s.Get("ollama")
	if !ok {
		t.Fatal("target not found after Add")
	}
	if got.Description != "local models" {
		t.Errorf("description = %q", got.Description)
	}
	if got.Added.IsZero() {
		t.Error("Added was not stamped")
	}

	// A second store on the same file sees it: the daemon and the CLI are
	// different processes.
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := s2.Get("ollama"); !ok {
		t.Fatal("a second store did not see the write")
	}

	// The file must not be world-readable.
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600", perm)
	}

	removed, err := s2.Remove("ollama")
	if err != nil || !removed {
		t.Fatalf("Remove = %v, %v", removed, err)
	}
	if _, ok := s.Get("ollama"); ok {
		t.Error("the first store still sees a removed target")
	}
	if removed, _ := s.Remove("ollama"); removed {
		t.Error("removing twice reported success")
	}
}

func TestStoreRejectsInvalidOnAdd(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Add(Target{Name: "bad", Origin: "http://10.0.0.5:80"}); err == nil {
		t.Fatal("Add accepted a non-loopback origin")
	}
}

func TestBrokenFileIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("Open accepted a corrupt file")
	}
}
