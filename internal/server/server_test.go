package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/haroon0x/neighbourd/internal/card"
	"github.com/haroon0x/neighbourd/internal/client"
	"github.com/haroon0x/neighbourd/internal/discovery"
	"github.com/haroon0x/neighbourd/internal/identity"
	"github.com/haroon0x/neighbourd/internal/pair"
	"github.com/haroon0x/neighbourd/internal/proto"
	"github.com/haroon0x/neighbourd/internal/trust"
)

// node is a running test server plus everything needed to talk to it.
type node struct {
	srv    *httptest.Server
	self   *identity.Identity
	peers  *trust.Store
	window *pair.Window
	code   string
}

func newTestNode(t *testing.T) *node {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	self, err := identity.LoadOrCreate("server")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	peers, err := trust.Open(filepath.Join(t.TempDir(), "trust"))
	if err != nil {
		t.Fatalf("trust: %v", err)
	}
	window, code, err := pair.NewWindow(time.Minute)
	if err != nil {
		t.Fatalf("pair window: %v", err)
	}

	n := &node{self: self, peers: peers, window: window, code: code}
	n.srv = httptest.NewServer(New(Options{
		Card:  card.New(self.ID, self.Name, "test", "", 0),
		Self:  self,
		Trust: peers,
		Pair:  window,
		Browse: func(time.Duration) []discovery.Peer {
			return []discovery.Peer{{Name: "someone", ID: "aaa", Port: 1, Addr: "10.0.0.1"}}
		},
	}).Handler)
	t.Cleanup(n.srv.Close)
	return n
}

// paired returns a client identity that has completed pairing with n.
func (n *node) paired(t *testing.T) (*client.Client, trust.Peer) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	other, err := identity.LoadOrCreate("client")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	c := client.New(other)
	peer, err := c.Pair(context.Background(), n.srv.URL, n.code)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	return c, peer
}

func TestPublicEndpointsNeedNoCredential(t *testing.T) {
	n := newTestNode(t)
	for _, path := range []string{proto.PathCard, proto.PathHealth} {
		resp, err := http.Get(n.srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, resp.StatusCode)
		}
	}
}

func TestProtectedEndpointsRejectStrangers(t *testing.T) {
	n := newTestNode(t)
	for _, path := range []string{proto.PathPing, proto.PathPeers, proto.PathIdentity} {
		resp, err := http.Get(n.srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without credentials = %d, want 401", path, resp.StatusCode)
		}
	}
}

func TestPairingThenSignedRequestWorks(t *testing.T) {
	n := newTestNode(t)
	c, peer := n.paired(t)

	if peer.ID == "" || peer.TokenToPeer == "" {
		t.Fatalf("pairing returned an incomplete peer: %+v", peer)
	}
	// The server's store is keyed by the caller's id, not by the server id the
	// caller received back.
	if _, ok := n.peers.Get(c.ID.ID); !ok {
		t.Fatal("pairing did not store the peer on the server side")
	}

	body, err := c.Get(context.Background(), peer, n.srv.URL, proto.PathIdentity)
	if err != nil {
		t.Fatalf("signed GET: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if got["id"] != n.self.ID {
		t.Errorf("identity id = %v, want %s", got["id"], n.self.ID)
	}
}

func TestPairingCodeIsSingleUse(t *testing.T) {
	n := newTestNode(t)
	n.paired(t)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	second, err := identity.LoadOrCreate("client-two")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	_, err = client.New(second).Pair(context.Background(), n.srv.URL, n.code)
	if err == nil {
		t.Fatal("second pairing with the same code succeeded; the code should be spent")
	}
}

func TestPairingRejectsWrongCode(t *testing.T) {
	n := newTestNode(t)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	other, err := identity.LoadOrCreate("client")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if _, err := client.New(other).Pair(context.Background(), n.srv.URL, "WRONGCODE"); err == nil {
		t.Fatal("pairing with a wrong code succeeded")
	}
	if !n.window.Open() {
		t.Error("a wrong code burned the window; it should survive a failed attempt")
	}
}

func TestPairingClosedWhenNoWindow(t *testing.T) {
	n := newTestNode(t)
	n.window.Close()

	resp, err := http.Post(n.srv.URL+proto.PathPairRequest, "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("pairing with a closed window = %d, want 404", resp.StatusCode)
	}
}

func TestRevokedPeerIsRejected(t *testing.T) {
	n := newTestNode(t)
	c, peer := n.paired(t)

	if _, err := c.Get(context.Background(), peer, n.srv.URL, proto.PathPing); err != nil {
		t.Fatalf("signed GET before revoke: %v", err)
	}
	// The server stores the caller's id, which is the client identity, not the
	// peer record the client received (that one describes the server).
	if err := n.peers.Remove(c.ID.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := c.Get(context.Background(), peer, n.srv.URL, proto.PathPing); err == nil {
		t.Fatal("a revoked peer was still accepted")
	}
}

// signed builds a raw request with explicit signature material, for the cases
// the client package deliberately does not expose.
func signed(t *testing.T, id *identity.Identity, peer trust.Peer, method, target, ts, nonce string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	sig, err := id.Sign(proto.Request(method, req.URL.RequestURI(), ts, nonce, body))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+peer.TokenToPeer)
	req.Header.Set(proto.HeaderID, id.ID)
	req.Header.Set(proto.HeaderTS, ts)
	req.Header.Set(proto.HeaderNonce, nonce)
	req.Header.Set(proto.HeaderSig, base64.StdEncoding.EncodeToString(sig))
	return req
}

func (n *node) raw(t *testing.T, req *http.Request) int {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// serve runs a request through the handler directly, which is the only way to
// control RemoteAddr: the client cannot set it.
func (n *node) serve(t *testing.T, req *http.Request) int {
	t.Helper()
	rec := httptest.NewRecorder()
	n.srv.Config.Handler.ServeHTTP(rec, req)
	return rec.Code
}

func TestReplayedNonceIsRejected(t *testing.T) {
	n := newTestNode(t)
	c, peer := n.paired(t)
	_ = c

	nonce := "deadbeefdeadbeefdeadbeefdeadbeef"
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	if code := n.raw(t, signed(t, c.ID, peer, http.MethodGet, n.srv.URL+proto.PathPing, ts, nonce, nil)); code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", code)
	}
	if code := n.raw(t, signed(t, c.ID, peer, http.MethodGet, n.srv.URL+proto.PathPing, ts, nonce, nil)); code != http.StatusUnauthorized {
		t.Errorf("replayed request = %d, want 401", code)
	}
}

func TestSignatureBoundToPath(t *testing.T) {
	n := newTestNode(t)
	c, peer := n.paired(t)

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req := signed(t, c.ID, peer, http.MethodGet, n.srv.URL+proto.PathPing, ts, "nonce-a", nil)
	// Point the signed request at a different endpoint than the one signed.
	req.URL.Path = proto.PathIdentity

	if code := n.raw(t, req); code != http.StatusUnauthorized {
		t.Errorf("signature reused on another path = %d, want 401", code)
	}
}

func TestStaleTimestampIsRejected(t *testing.T) {
	n := newTestNode(t)
	c, peer := n.paired(t)

	ts := strconv.FormatInt(time.Now().Add(-2*proto.MaxSkew).Unix(), 10)
	if code := n.raw(t, signed(t, c.ID, peer, http.MethodGet, n.srv.URL+proto.PathPing, ts, "nonce-b", nil)); code != http.StatusUnauthorized {
		t.Errorf("stale request = %d, want 401", code)
	}
}

func TestTokenWithoutSignatureIsRejected(t *testing.T) {
	n := newTestNode(t)
	_, peer := n.paired(t)

	req, _ := http.NewRequest(http.MethodGet, n.srv.URL+proto.PathPing, nil)
	req.Header.Set("Authorization", "Bearer "+peer.TokenToPeer)
	req.Header.Set(proto.HeaderID, peer.ID)

	if code := n.raw(t, req); code != http.StatusUnauthorized {
		t.Errorf("token without signature = %d, want 401", code)
	}
}

func TestOperatorTokenOnlyFromLoopback(t *testing.T) {
	n := newTestNode(t)

	req, _ := http.NewRequest(http.MethodGet, n.srv.URL+proto.PathPing, nil)
	req.Header.Set("Authorization", "Bearer "+n.self.Token)
	req.RemoteAddr = "127.0.0.1:54321"
	if code := n.serve(t, req); code != http.StatusOK {
		t.Errorf("operator token from loopback = %d, want 200", code)
	}

	req2, _ := http.NewRequest(http.MethodGet, n.srv.URL+proto.PathPing, nil)
	req2.Header.Set("Authorization", "Bearer "+n.self.Token)
	req2.RemoteAddr = "192.168.29.50:54321"
	if code := n.serve(t, req2); code != http.StatusUnauthorized {
		t.Errorf("operator token from another machine = %d, want 401", code)
	}
}

func TestEmptyOperatorTokenNeverAuthorises(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	self, err := identity.LoadOrCreate("server")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	self.Token = ""

	peers, err := trust.Open(filepath.Join(t.TempDir(), "trust"))
	if err != nil {
		t.Fatalf("trust: %v", err)
	}
	h := New(Options{Card: card.New(self.ID, self.Name, "test", "", 0), Self: self, Trust: peers}).Handler

	req, _ := http.NewRequest(http.MethodGet, proto.PathPing, nil)
	req.Header.Set("Authorization", "Bearer ")
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("empty token = %d, want 401", rec.Code)
	}
}

func TestBearerParsing(t *testing.T) {
	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "", false},
		{"Basic abc", "", false},
		{"Bearer ", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		got, ok := bearer(req)
		if got != c.want || ok != c.ok {
			t.Errorf("bearer(%q) = (%q,%v), want (%q,%v)", c.header, got, ok, c.want, c.ok)
		}
	}
}

func TestNonceCacheBlocksReuse(t *testing.T) {
	c := newNonceCache(time.Hour)
	now := time.Now()

	if !c.use("a", now) {
		t.Fatal("first use of a nonce was rejected")
	}
	if c.use("a", now) {
		t.Fatal("second use of the same nonce was accepted")
	}
	// Entries deliberately outlive the skew window rather than being dropped
	// early: forgetting a nonce too soon would accept a replay. Failing to
	// forget it only costs a rejected request.
	if c.use("a", now.Add(2*time.Hour)) {
		t.Error("nonce was forgotten before being pruned; that opens a replay hole")
	}
}

func TestNonceCacheFailsClosedAtCapacity(t *testing.T) {
	now := time.Now()

	full := newNonceCache(time.Hour)
	full.max = 2
	full.use("x", now)
	full.use("y", now)
	if full.use("z", now) {
		t.Error("cache accepted a nonce past its cap instead of failing closed")
	}

	// Once entries are old enough to prune, capacity returns.
	expired := newNonceCache(time.Hour)
	expired.max = 2
	expired.use("x", now.Add(-2*time.Hour))
	expired.use("y", now.Add(-2*time.Hour))
	if !expired.use("z", now) {
		t.Error("expired entries were not pruned, so the cache stayed full")
	}
}

func TestLoopbackDetection(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:80":     true,
		"[::1]:80":         true,
		"192.168.29.50:80": false,
		"not-an-address":   false,
		"":                 false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

var _ = fmt.Sprint
