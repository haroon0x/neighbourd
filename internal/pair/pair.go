// Package pair implements the one-time code exchange that turns a stranger on
// the network into a paired peer.
//
// The rule it enforces: a pairing code issued by this node is single use, short
// lived, and only good for a request that proves possession of the private key
// matching the public key being registered. That last part is what stops an
// announcement with someone else's id from collecting a token.
package pair

import (
	"crypto/rand"
	"crypto/subtle"
	"sync"
	"time"
)

// codeAlphabet drops characters that are easy to confuse when read off a screen
// and typed into another machine: 0/O, 1/I/L, and 2/Z is kept distinct by case.
const codeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// CodeLength is 8 characters from a 31 symbol alphabet, roughly 39 bits. That
// is not brute-forceable online within the window, which is the only attack
// that matters here.
const CodeLength = 8

// DefaultTTL is how long an issued code stays valid.
const DefaultTTL = 5 * time.Minute

// Window is the pairing state of a node: no window, none. Window methods are
// safe for concurrent use.
type Window struct {
	mu      sync.Mutex
	code    string
	expires time.Time
	ttl     time.Duration
	used    bool
}

// NewWindow starts a fresh window and returns it with its code.
func NewWindow(ttl time.Duration) (*Window, string, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	code, err := generateCode()
	if err != nil {
		return nil, "", err
	}
	w := &Window{ttl: ttl}
	w.code = code
	w.expires = time.Now().Add(ttl)
	return w, code, nil
}

// Code returns the current code, or "" when the window is closed.
func (w *Window) Code() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.used || time.Now().After(w.expires) {
		return ""
	}
	return w.code
}

// Open reports whether a code can still be redeemed.
func (w *Window) Open() bool { return w.Code() != "" }

// ExpiresAt returns the deadline of the current window.
func (w *Window) ExpiresAt() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.expires
}

// Redeem checks code and, if it matches, closes the window so it cannot be used
// twice. The comparison is constant time: an attacker with a stopwatch should
// not learn how much of the code they guessed.
func (w *Window) Redeem(code string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.used || w.code == "" || time.Now().After(w.expires) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(normalize(code)), []byte(w.code)) != 1 {
		return false
	}
	w.used = true
	return true
}

// Reopen starts a new window on an existing one, so a running server can be
// handed a fresh code without being restarted. The previous code stops working
// immediately.
func (w *Window) Reopen(ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	code, err := generateCode()
	if err != nil {
		return "", err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.code = code
	w.expires = time.Now().Add(ttl)
	w.used = false
	return code, nil
}

// Close expires the window early.
func (w *Window) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.used = true
	w.code = ""
}

// normalize lets the operator type the code in lower case or with spaces.
func normalize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '-' || c == '\t' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

func generateCode() (string, error) {
	buf := make([]byte, CodeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	// Modulo bias is irrelevant here: 256 is not a multiple of 31, but the
	// resulting skew is under one part in thirty-one of a 39 bit space.
	for i := range buf {
		buf[i] = codeAlphabet[int(buf[i])%len(codeAlphabet)]
	}
	return string(buf), nil
}
