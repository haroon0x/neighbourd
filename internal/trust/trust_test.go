package trust

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func outbound(name, id string) Peer {
	return Peer{
		ID:          id,
		Name:        name,
		PublicKey:   "their-key",
		TokenToPeer: "token-they-issued",
		BaseURL:     "http://10.0.0.1:7717",
		PairedAt:    time.Now().UTC(),
	}
}

func TestRememberOutboundThenInboundKeepsBothTokens(t *testing.T) {
	// The regression this exists for: a mutual pairing touches one peer id
	// from two directions, and a naive replace loses the outbound credentials.
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.RememberOutbound(outbound("laptop", "id1")); err != nil {
		t.Fatalf("RememberOutbound: %v", err)
	}
	if err := s.RememberInbound("id1", "laptop", "their-key", "token-we-issued"); err != nil {
		t.Fatalf("RememberInbound: %v", err)
	}

	p, ok := s.Get("id1")
	if !ok {
		t.Fatal("peer vanished")
	}
	if p.TokenToPeer != "token-they-issued" {
		t.Errorf("TokenToPeer = %q, want the outbound token to survive", p.TokenToPeer)
	}
	if p.TokenFromPeer != "token-we-issued" {
		t.Errorf("TokenFromPeer = %q, want the inbound token", p.TokenFromPeer)
	}
	if p.BaseURL == "" {
		t.Error("BaseURL was lost; status would have no address to call")
	}
}

func TestRememberInboundFirstThenOutbound(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.RememberInbound("id1", "laptop", "their-key", "token-we-issued"); err != nil {
		t.Fatalf("RememberInbound: %v", err)
	}
	if err := s.RememberOutbound(outbound("laptop", "id1")); err != nil {
		t.Fatalf("RememberOutbound: %v", err)
	}

	p, _ := s.Get("id1")
	if p.TokenFromPeer != "token-we-issued" {
		t.Errorf("TokenFromPeer = %q, want the inbound token to survive", p.TokenFromPeer)
	}
	if p.TokenToPeer == "" {
		t.Error("TokenToPeer is empty")
	}
}

func TestRememberRejectsIncompleteRecords(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.RememberOutbound(Peer{ID: "id1"}); err == nil {
		t.Error("outbound record without a token was accepted")
	}
	if err := s.RememberInbound("id1", "n", "key", ""); err == nil {
		t.Error("inbound record without a token was accepted")
	}
	if err := s.RememberInbound("id1", "n", "", "tok"); err == nil {
		t.Error("inbound record without a key was accepted")
	}
}

func TestPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.RememberOutbound(outbound("laptop", "id1")); err != nil {
		t.Fatalf("RememberOutbound: %v", err)
	}

	again, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	p, ok := again.Get("id1")
	if !ok {
		t.Fatal("peer did not survive reopening the store")
	}
	if p.TokenToPeer != "token-they-issued" || p.BaseURL == "" {
		t.Errorf("record lost fields across reload: %+v", p)
	}
}

func TestStoreFileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.RememberOutbound(outbound("laptop", "id1")); err != nil {
		t.Fatalf("RememberOutbound: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "peers.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("peers.json mode = %o, want 600; it holds tokens", perm)
	}
}

func TestRemoveRevokesBothDirections(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.RememberOutbound(outbound("laptop", "id1")); err != nil {
		t.Fatalf("RememberOutbound: %v", err)
	}
	if err := s.Remove("id1"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := s.Get("id1"); ok {
		t.Error("peer is still present after Remove")
	}
	if err := s.Remove("id1"); err == nil {
		t.Error("removing a missing peer returned no error")
	}
}

func TestByNameRequiresUnambiguousMatch(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.RememberOutbound(outbound("laptop", "id1")); err != nil {
		t.Fatalf("RememberOutbound: %v", err)
	}
	if _, err := s.ByName("laptop"); err != nil {
		t.Errorf("ByName with one match: %v", err)
	}
	if _, err := s.ByName("desktop"); err == nil {
		t.Error("ByName with no match returned no error")
	}

	if err := s.RememberOutbound(outbound("laptop", "id2")); err != nil {
		t.Fatalf("RememberOutbound: %v", err)
	}
	if _, err := s.ByName("laptop"); err == nil {
		t.Error("ByName with two matches returned no error")
	}
}

func TestListIsSorted(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, p := range []Peer{outbound("zulu", "z"), outbound("alpha", "a"), outbound("mike", "m")} {
		if err := s.RememberOutbound(p); err != nil {
			t.Fatalf("RememberOutbound: %v", err)
		}
	}
	got := s.List()
	want := []string{"alpha", "mike", "zulu"}
	for i := range want {
		if got[i].Name != want[i] {
			t.Errorf("List()[%d] = %q, want %q", i, got[i].Name, want[i])
		}
	}
}

func TestTouchOnlyMovesLastSeen(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.RememberOutbound(outbound("laptop", "id1")); err != nil {
		t.Fatalf("RememberOutbound: %v", err)
	}
	at := time.Now().Add(time.Minute).UTC()
	s.Touch("id1", at)

	p, _ := s.Get("id1")
	if !p.LastSeen.Equal(at) {
		t.Errorf("LastSeen = %v, want %v", p.LastSeen, at)
	}
	if p.TokenToPeer == "" || p.BaseURL == "" {
		t.Error("Touch clobbered other fields")
	}
	s.Touch("missing", at) // must not panic or create a record
	if _, ok := s.Get("missing"); ok {
		t.Error("Touch created a record for an unknown peer")
	}
}

func TestTwoStoresSeeEachOthersWrites(t *testing.T) {
	// Stands in for the real deployment: `serve` holds a store for its whole
	// lifetime while `pair` mutates the same file from the shell.
	dir := t.TempDir()
	daemon, err := Open(dir)
	if err != nil {
		t.Fatalf("open daemon store: %v", err)
	}
	cli, err := Open(dir)
	if err != nil {
		t.Fatalf("open cli store: %v", err)
	}

	if err := cli.RememberOutbound(outbound("laptop", "id1")); err != nil {
		t.Fatalf("cli RememberOutbound: %v", err)
	}
	// The daemon has never re-read the file at this point.
	if err := daemon.RememberInbound("id1", "laptop", "their-key", "token-we-issued"); err != nil {
		t.Fatalf("daemon RememberInbound: %v", err)
	}

	p, ok := daemon.Get("id1")
	if !ok {
		t.Fatal("peer missing after inbound write")
	}
	if p.TokenToPeer != "token-they-issued" {
		t.Errorf("TokenToPeer = %q; the daemon overwrote the pairing the CLI just made", p.TokenToPeer)
	}
	if p.BaseURL == "" {
		t.Error("BaseURL lost; the daemon flushed a stale map over the CLI's write")
	}
	if p.TokenFromPeer != "token-we-issued" {
		t.Errorf("TokenFromPeer = %q, want the inbound token", p.TokenFromPeer)
	}
}

func TestNewTokenShape(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if len(tok) != 64 {
		t.Errorf("token is %d chars, want 64 hex chars", len(tok))
	}
	other, _ := NewToken()
	if tok == other {
		t.Error("two tokens were identical")
	}
}
