package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/haroon0x/neighbourd/internal/identity"
	"github.com/haroon0x/neighbourd/internal/proto"
	"github.com/haroon0x/neighbourd/internal/trust"
)

// maxBody caps how much of a body is read for hashing. Every endpoint here
// takes small JSON or nothing; a large body is an attack, not a request.
const maxBody = 1 << 20

// authError carries the status a rejection should be reported with.
type authError struct {
	status int
	msg    string
}

func (e *authError) Error() string { return e.msg }

func deny(status int, format string, args ...any) error {
	return &authError{status: status, msg: fmt.Sprintf(format, args...)}
}

// authorizer decides whether a request may proceed.
//
// Two ways in:
//
//  1. The operator, over loopback, with the node's own token. This exists so
//     curl on the machine works. It is deliberately impossible from anywhere
//     else, because that token is not per-peer and cannot be revoked without
//     regenerating the identity.
//  2. A paired peer, with the token this node issued to it and a valid
//     signature over the request. The token alone is not enough: the signature
//     must verify against the key pinned at pairing time.
type authorizer struct {
	self   *identity.Identity
	peers  *trust.Store
	nonces *nonceCache
	log    *log.Logger
}

// who describes who was allowed through, for handlers and logs.
type who struct {
	ID       string
	Name     string
	Operator bool
}

func (a *authorizer) authorize(r *http.Request) (who, error) {
	token, ok := bearer(r)
	if !ok {
		return who{}, deny(http.StatusUnauthorized, "missing bearer token")
	}

	// Operator path: loopback only.
	if isLoopback(r.RemoteAddr) && a.self.Token != "" &&
		subtle.ConstantTimeCompare([]byte(token), []byte(a.self.Token)) == 1 {
		return who{ID: a.self.ID, Name: a.self.Name, Operator: true}, nil
	}

	id := r.Header.Get(proto.HeaderID)
	if id == "" {
		return who{}, deny(http.StatusUnauthorized, "missing %s header", proto.HeaderID)
	}
	peer, ok := a.peers.Get(id)
	if !ok {
		return who{}, deny(http.StatusUnauthorized, "peer %s is not paired", id)
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(peer.TokenFromPeer)) != 1 {
		return who{}, deny(http.StatusUnauthorized, "token does not match the one issued to this peer")
	}

	tsStr := r.Header.Get(proto.HeaderTS)
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return who{}, deny(http.StatusUnauthorized, "missing or malformed %s header", proto.HeaderTS)
	}
	skew := time.Since(time.Unix(ts, 0))
	if skew > proto.MaxSkew || skew < -proto.MaxSkew {
		return who{}, deny(http.StatusUnauthorized,
			"request timestamp is %.0fs away from local time; check both machines' clocks", skew.Seconds())
	}

	nonce := r.Header.Get(proto.HeaderNonce)
	if nonce == "" {
		return who{}, deny(http.StatusUnauthorized, "missing %s header", proto.HeaderNonce)
	}

	body, err := readAndReplaceBody(r)
	if err != nil {
		return who{}, deny(http.StatusBadRequest, "read body: %v", err)
	}

	target := r.URL.RequestURI()
	if err := identity.Verify(peer.PublicKey, proto.Request(r.Method, target, tsStr, nonce, body), decodeSig(r)); err != nil {
		return who{}, deny(http.StatusUnauthorized, "signature check failed: %v", err)
	}

	// Only spend a nonce slot once the signature is known good, so an
	// unauthenticated flood cannot fill the cache and lock out real peers.
	if !a.nonces.use(peer.ID+":"+nonce, time.Now()) {
		return who{}, deny(http.StatusUnauthorized, "nonce was already used; this request looks replayed")
	}
	a.peers.Touch(peer.ID, time.Now())

	return who{ID: peer.ID, Name: peer.Name}, nil
}

func decodeSig(r *http.Request) []byte {
	s := r.Header.Get(proto.HeaderSig)
	if s == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func readAndReplaceBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return "", false
	}
	return h[len(prefix):], true
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// nonceCache remembers request nonces for as long as a timestamp could still be
// inside the skew window, which is the only period a replay would be accepted.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
	max  int
}

func newNonceCache(ttl time.Duration) *nonceCache {
	if ttl <= 0 {
		ttl = 2 * proto.MaxSkew
	}
	return &nonceCache{seen: make(map[string]time.Time), ttl: ttl, max: 8192}
}

// use records key and reports false if it has been seen before.
func (c *nonceCache) use(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.seen[key]; exists {
		return false
	}
	if len(c.seen) >= c.max {
		c.pruneLocked(now)
		if len(c.seen) >= c.max {
			// Fail closed: refusing a request is better than forgetting a
			// nonce and accepting a replay.
			return false
		}
	}
	c.seen[key] = now
	return true
}

func (c *nonceCache) pruneLocked(now time.Time) {
	for k, at := range c.seen {
		if now.Sub(at) > c.ttl {
			delete(c.seen, k)
		}
	}
}
