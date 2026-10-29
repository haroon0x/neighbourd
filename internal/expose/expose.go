// Package expose records the local services this machine offers to paired peers.
//
// An entry is a name and an origin. The origin is expected to be something bound
// to loopback — an Ollama daemon, a local vector store, a job runner — that the
// operator does not want on the Wi-Fi directly. Peers reach it through this node,
// which is the only place that talks to it.
//
// The file is edited by the `expose` subcommand while the daemon is running, so
// it is re-read on change rather than cached, the same way the peer store is.
package expose

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// FileName is the store inside the config directory.
const FileName = "exposures.json"

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Target is one local service offered to peers.
type Target struct {
	Name        string    `json:"name"`
	Origin      string    `json:"origin"`
	Description string    `json:"description,omitempty"`
	Added       time.Time `json:"added"`
}

type file struct {
	Version int               `json:"version"`
	Targets map[string]Target `json:"targets"`
}

// Store is a file-backed set of targets.
type Store struct {
	path string

	cached  file
	modTime time.Time
	size    int64
	loaded  bool
}

// Open returns the store at dir, creating nothing until something is added.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("expose: empty directory")
	}
	s := &Store{path: filepath.Join(dir, FileName)}
	if err := s.refresh(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path is where the store lives.
func (s *Store) Path() string { return s.path }

// refresh re-reads the file when its metadata changed. A missing file is an
// empty store, not an error: exposing nothing is the normal case.
func (s *Store) refresh() error {
	info, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.cached = file{Version: 1, Targets: map[string]Target{}}
			s.loaded = true
			s.modTime, s.size = time.Time{}, 0
			return nil
		}
		return err
	}
	if s.loaded && info.ModTime().Equal(s.modTime) && info.Size() == s.size {
		return nil
	}

	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("%s is not valid JSON: %w", s.path, err)
	}
	if f.Targets == nil {
		f.Targets = map[string]Target{}
	}
	s.cached = f
	s.modTime, s.size = info.ModTime(), info.Size()
	s.loaded = true
	return nil
}

// List returns every target, ordered by name.
func (s *Store) List() []Target {
	if err := s.refresh(); err != nil {
		return nil
	}
	out := make([]Target, 0, len(s.cached.Targets))
	for _, t := range s.cached.Targets {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get looks up one target by name.
func (s *Store) Get(name string) (Target, bool) {
	if err := s.refresh(); err != nil {
		return Target{}, false
	}
	t, ok := s.cached.Targets[name]
	return t, ok
}

// Add validates a target and writes it. An existing name is replaced, because
// re-exposing the same thing with a new port is normal.
func (s *Store) Add(t Target) error {
	if err := Validate(t, false); err != nil {
		return err
	}
	if err := s.refresh(); err != nil {
		return err
	}
	if t.Added.IsZero() {
		t.Added = time.Now().UTC()
	}
	if s.cached.Targets == nil {
		s.cached.Targets = map[string]Target{}
	}
	s.cached.Targets[t.Name] = t
	s.cached.Version = 1
	return s.flush()
}

// Remove deletes a target, reporting whether it existed.
func (s *Store) Remove(name string) (bool, error) {
	if err := s.refresh(); err != nil {
		return false, err
	}
	if _, ok := s.cached.Targets[name]; !ok {
		return false, nil
	}
	delete(s.cached.Targets, name)
	return true, s.flush()
}

// flush writes through a temp file and renames, so a reader never sees half a
// document and a crash never truncates the list.
func (s *Store) flush() error {
	raw, err := json.MarshalIndent(s.cached, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".exposures-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	s.loaded = false
	return s.refresh()
}

// Validate checks a target before it is stored or used.
//
// allowRemote defaults to false: an exposed origin must be loopback. Without
// that rule a paired peer could use this node as a pivot to reach other hosts on
// the network, which is not what "expose my local service" means.
func Validate(t Target, allowRemote bool) error {
	if !nameRE.MatchString(t.Name) {
		return fmt.Errorf("name %q must be lowercase letters, digits and dashes, starting with a letter or digit (max 32)", t.Name)
	}
	if len(t.Description) > 200 {
		return errors.New("description is limited to 200 characters; it appears in peer listings")
	}
	u, err := url.Parse(t.Origin)
	if err != nil {
		return fmt.Errorf("origin %q is not a URL: %w", t.Origin, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("origin %q must be http or https", t.Origin)
	}
	if u.User != nil {
		return errors.New("origin must not contain credentials")
	}
	if u.Host == "" {
		return fmt.Errorf("origin %q has no host", t.Origin)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("origin %q must not have a path; put the path in the request instead", t.Origin)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("origin %q must not have a query or fragment", t.Origin)
	}
	if !allowRemote && !IsLoopbackHost(u.Host) {
		return fmt.Errorf("origin %q is not loopback; exposing a remote host would use this node as a pivot (pass --allow-remote if you mean it)", t.Origin)
	}
	return nil
}

// IsLoopbackHost reports whether host (with optional port) names this machine.
func IsLoopbackHost(host string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// NormalizeOrigin canonicalizes an operator's shorthand: "11434", "localhost:11434"
// and "127.0.0.1:11434/" all mean the same thing, and requiring the scheme is the
// kind of friction that stops people using a feature.
func NormalizeOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// A bare port is the shortest thing a person types.
	if isAllDigits(raw) {
		raw = "127.0.0.1:" + raw
	}
	if !strings.Contains(raw, "://") {
		host := raw
		if !strings.Contains(host, ":") {
			host += ":80"
		}
		raw = "http://" + host
	}
	raw = strings.TrimSuffix(raw, "/")
	return raw
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
