// Package trust stores peers this node has paired with.
//
// Two properties drive the shape of this package:
//
//  1. Pairing is directional. The token you hold for a peer is not the token the
//     peer holds for you, and a mutual pairing has both at once for the same peer
//     id. Each record therefore carries two credential slots rather than one.
//
//  2. Two processes share the file. `serve` holds it open for the life of the
//     daemon while `pair` and `trust remove` mutate it from the shell. The store
//     re-reads the file whenever it changes on disk and replaces it atomically,
//     so a long-running daemon cannot flush a stale map over a fresh pairing.
package trust

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Peer is a paired node as this machine remembers it.
type Peer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`

	// TokenToPeer was issued by them and is sent by us when calling them.
	TokenToPeer string `json:"token_to_peer,omitempty"`

	// TokenFromPeer was issued by us and is what they must send when calling
	// us. Holding it is only half the check: the request must also be signed
	// with PublicKey.
	TokenFromPeer string `json:"token_from_peer,omitempty"`

	// BaseURL is where they answered when we paired. It goes stale as soon as
	// DHCP moves them; re-pair or resolve via mDNS rather than trusting it.
	BaseURL string `json:"base_url,omitempty"`

	PairedAt time.Time `json:"paired_at"`
	LastSeen time.Time `json:"last_seen,omitempty"`
}

// Store is a set of peers persisted to disk. All methods are safe for
// concurrent use within one process, and observe changes made by other
// processes on the next call.
type Store struct {
	mu    sync.Mutex
	path  string
	peers map[string]Peer
	stamp stamp
}

// stamp identifies a file version cheaply, to decide whether to re-read it.
type stamp struct {
	mod  time.Time
	size int64
}

// Open loads the peer store from dir, creating an empty one if absent.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	s := &Store{path: filepath.Join(dir, "peers.json"), peers: map[string]Peer{}}

	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.path, err)
	}
	if err := s.load(raw); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load(raw []byte) error {
	var list []Peer
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("parse %s: %w", s.path, err)
	}
	s.peers = make(map[string]Peer, len(list))
	for _, p := range list {
		s.peers[p.ID] = p
	}
	if info, err := os.Stat(s.path); err == nil {
		s.stamp = stamp{mod: info.ModTime(), size: info.Size()}
	}
	return nil
}

// refreshLocked re-reads the file when another process has changed it.
func (s *Store) refreshLocked() error {
	info, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.peers = map[string]Peer{}
			s.stamp = stamp{}
			return nil
		}
		return fmt.Errorf("stat %s: %w", s.path, err)
	}
	if info.ModTime().Equal(s.stamp.mod) && info.Size() == s.stamp.size {
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read %s: %w", s.path, err)
	}
	return s.load(raw)
}

// List returns peers sorted by name.
func (s *Store) List() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshLocked()

	out := make([]Peer, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].ID < out[j].ID
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Get looks a peer up by exact id.
func (s *Store) Get(id string) (Peer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshLocked()
	p, ok := s.peers[id]
	return p, ok
}

// ByName looks a peer up by its label. Names are not unique and not verified;
// this is a convenience for the CLI, and ambiguity is an error.
func (s *Store) ByName(name string) (Peer, error) {
	var matches []Peer
	for _, p := range s.List() {
		if p.Name == name {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 0:
		return Peer{}, fmt.Errorf("no paired peer named %q", name)
	case 1:
		return matches[0], nil
	default:
		return Peer{}, fmt.Errorf("%d paired peers named %q; use the id", len(matches), name)
	}
}

// RememberOutbound records a peer we just paired with: the token they issued to
// us and the address they answered on. Inbound credentials already held for the
// same peer are preserved.
func (s *Store) RememberOutbound(p Peer) error {
	if p.ID == "" || p.TokenToPeer == "" {
		return fmt.Errorf("outbound peer record needs an id and a token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return err
	}

	if existing, had := s.peers[p.ID]; had {
		if p.TokenFromPeer == "" {
			p.TokenFromPeer = existing.TokenFromPeer
		}
		if p.PairedAt.IsZero() {
			p.PairedAt = existing.PairedAt
		}
		if p.LastSeen.IsZero() {
			p.LastSeen = existing.LastSeen
		}
	}
	if p.PairedAt.IsZero() {
		p.PairedAt = time.Now().UTC()
	}
	s.peers[p.ID] = p
	return s.flushLocked()
}

// RememberInbound records a peer that paired with us: the token we issued and
// the key it proved it holds. Outbound credentials for the same peer survive.
func (s *Store) RememberInbound(id, name, publicKey, token string) error {
	if id == "" || publicKey == "" || token == "" {
		return fmt.Errorf("inbound peer record needs an id, key and token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return err
	}

	p, had := s.peers[id]
	if !had {
		p = Peer{ID: id, PairedAt: time.Now().UTC()}
	}
	if name != "" {
		p.Name = name
	}
	p.PublicKey = publicKey
	p.TokenFromPeer = token
	s.peers[id] = p
	return s.flushLocked()
}

// Touch records that a peer just made a request. It writes at most once per
// second per peer, so a busy peer does not rewrite the file on every request.
func (s *Store) Touch(id string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return
	}
	p, ok := s.peers[id]
	if !ok || p.LastSeen.Unix() == at.Unix() {
		return
	}
	p.LastSeen = at
	s.peers[id] = p
	_ = s.flushLocked()
}

// Remove drops a peer and revokes both tokens in the relationship.
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return err
	}
	if _, ok := s.peers[id]; !ok {
		return fmt.Errorf("peer %s is not paired", id)
	}
	delete(s.peers, id)
	return s.flushLocked()
}

// NewToken issues a token for a peer. Tokens are per-peer so a single leak costs
// one relationship, not the machine.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// flushLocked writes the whole set through a temp file and a rename, so a crash
// mid-write leaves the previous file intact rather than a truncated one.
func (s *Store) flushLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	list := make([]Peer, 0, len(s.peers))
	for _, p := range s.peers {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })

	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".peers-*.json")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace %s: %w", s.path, err)
	}

	if info, err := os.Stat(s.path); err == nil {
		s.stamp = stamp{mod: info.ModTime(), size: info.Size()}
	}
	return nil
}
