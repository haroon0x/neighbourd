// Package identity holds the long-lived state for one neighbourd node: an Ed25519
// keypair, the id derived from it, and the device token the operator uses.
//
// From v0.2 the keypair does real work: every request a paired peer makes is
// signed with it, so a stolen token is not enough to impersonate anyone.
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

// Identity is the on-disk state of a node. It is written 0600 and is a secret:
// the seed in it signs every request this machine makes.
type Identity struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	PublicKey  string    `json:"public_key"`
	PrivateKey string    `json:"private_key"`
	Token      string    `json:"token"`
	CreatedAt  time.Time `json:"created_at"`
}

// Dir returns the directory holding neighbourd state, without creating it.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config dir: %w", err)
	}
	return filepath.Join(base, "neighbourd"), nil
}

// ShortID is the first 8 characters of the id, for display only. Never use it
// to identify a peer programmatically.
func (i *Identity) ShortID() string { return shortID(i.ID) }

func shortID(id string) string {
	if len(id) < 8 {
		return id
	}
	return id[:8]
}

// PublicKeyBytes returns the decoded public key.
func (i *Identity) PublicKeyBytes() (ed25519.PublicKey, error) {
	return decodePublic(i.PublicKey)
}

// SigningKey returns the Ed25519 key derived from the stored seed. The field
// holding the seed is called PrivateKey, so this method cannot share the name.
func (i *Identity) SigningKey() (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(i.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("private seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Sign signs msg with this node's key.
func (i *Identity) Sign(msg []byte) ([]byte, error) {
	priv, err := i.SigningKey()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, msg), nil
}

// IDFromPublicKey derives the node id from a public key. The mapping is one way
// and fixed: peers pin ids, so changing it would break every pairing.
func IDFromPublicKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// IDFromPublicKeyB64 is IDFromPublicKey for the base64 form used on the wire.
func IDFromPublicKeyB64(s string) (string, error) {
	pub, err := decodePublic(s)
	if err != nil {
		return "", err
	}
	return IDFromPublicKey(pub), nil
}

// Verify checks sig over msg against a base64 public key.
func Verify(pubB64 string, msg, sig []byte) error {
	pub, err := decodePublic(pubB64)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

func decodePublic(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
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

	// 32 bytes of entropy, hex encoded. Never leaves the machine except when
	// the operator copies it on purpose.
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	if name == "" {
		name, _ = os.Hostname()
	}

	return &Identity{
		ID:         IDFromPublicKey(pub),
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
