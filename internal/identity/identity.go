// Package identity holds the long-lived state for one veranda node: an Ed25519
// keypair, the id derived from it, and the device token peers must present.
//
// The keypair is generated in v0.1 but not yet used for signing. It exists so
// the id is derived from something that can later carry a signature — changing
// the id derivation after peers have pinned each other would be a breaking
// change, so it is fixed now.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Identity is the on-disk state of a node. It is written 0600 and should be
// treated as a secret: the token in it is the whole of v0.1's authorisation.
type Identity struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	PublicKey  string    `json:"public_key"`
	PrivateKey string    `json:"private_key"`
	Token      string    `json:"token"`
	CreatedAt  time.Time `json:"created_at"`
}

// Dir returns the directory holding veranda state, without creating it.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config dir: %w", err)
	}
	return filepath.Join(base, "veranda"), nil
}

// ShortID is the first 8 characters of the id, for display only. Never use it
// to identify a peer programmatically.
func (i *Identity) ShortID() string {
	if len(i.ID) < 8 {
		return i.ID
	}
	return i.ID[:8]
}

// PublicKeyBytes returns the decoded public key.
func (i *Identity) PublicKeyBytes() (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(i.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// LoadOrCreate reads the identity for this machine, or creates one. If name is
// non-empty and differs from the stored name, the stored name is updated.
func LoadOrCreate(name string) (*Identity, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}

	path := filepath.Join(dir, "identity.json")
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var id Identity
		if err := json.Unmarshal(raw, &id); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if name != "" && name != id.Name {
			id.Name = name
			if err := id.save(path); err != nil {
				return nil, err
			}
		}
		return &id, nil
	case errors.Is(err, fs.ErrNotExist):
		// fall through to creation
	default:
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	id, err := generate(name)
	if err != nil {
		return nil, err
	}
	if err := id.save(path); err != nil {
		return nil, err
	}
	return id, nil
}

func generate(name string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// 32 bytes of entropy, hex encoded. Not a password: it never leaves the
	// machine except when the operator copies it to a peer on purpose.
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	sum := sha256.Sum256(pub)
	if name == "" {
		name, _ = os.Hostname()
	}

	return &Identity{
		ID:         hex.EncodeToString(sum[:16]),
		Name:       name,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed()),
		Token:      hex.EncodeToString(tok),
		CreatedAt:  time.Now().UTC(),
	}, nil
}

func (i *Identity) save(path string) error {
	raw, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
