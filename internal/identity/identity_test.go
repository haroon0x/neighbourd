package identity

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIsStable(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	first, err := LoadOrCreate("laptop")
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	second, err := LoadOrCreate("laptop")
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}

	if first.ID != second.ID {
		t.Errorf("id changed across reload: %s then %s", first.ID, second.ID)
	}
	if first.Token != second.Token {
		t.Error("token changed across reload")
	}
	if first.Name != "laptop" {
		t.Errorf("name = %q, want laptop", first.Name)
	}
}

func TestIdentityShapes(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	id, err := LoadOrCreate("")
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	if len(id.ID) != 32 {
		t.Errorf("id is %d chars, want 32 hex chars", len(id.ID))
	}
	if _, err := hex.DecodeString(id.ID); err != nil {
		t.Errorf("id is not hex: %v", err)
	}
	if len(id.Token) != 64 {
		t.Errorf("token is %d chars, want 64 hex chars (32 bytes)", len(id.Token))
	}
	if id.Name == "" {
		t.Error("name is empty; expected a hostname fallback")
	}
	if _, err := id.PublicKeyBytes(); err != nil {
		t.Errorf("public key does not decode: %v", err)
	}
}

func TestIdentityFileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if _, err := LoadOrCreate("laptop"); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	path := filepath.Join(dir, "neighbourd", "identity.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("identity file mode = %o, want 600; the token lives in it", perm)
	}
}

func TestNameOverridePersists(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, err := LoadOrCreate("laptop"); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	renamed, err := LoadOrCreate("workstation")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if renamed.Name != "workstation" {
		t.Errorf("name = %q, want workstation", renamed.Name)
	}
	again, err := LoadOrCreate("")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if again.Name != "workstation" {
		t.Errorf("stored name = %q, want workstation", again.Name)
	}
}
