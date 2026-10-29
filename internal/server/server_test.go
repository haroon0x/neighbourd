package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/haroon0x/veranda/internal/card"
	"github.com/haroon0x/veranda/internal/discovery"
)

const testToken = "0123456789abcdef"

func testServer() http.Handler {
	return New(Options{
		Card:  card.New("id123", "laptop", "0.1.0", "192.168.29.93", 7717),
		Token: testToken,
		Browse: func(_ time.Duration) []discovery.Peer {
			return []discovery.Peer{{Name: "desktop", ID: "abc", Port: 7717, Addr: "192.168.29.94"}}
		},
	}).Handler
}

func TestPublicEndpointsNeedNoToken(t *testing.T) {
	h := testServer()
	for _, path := range []string{"/.well-known/agent-card.json", "/healthz"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, rec.Code)
		}
	}
}

func TestProtectedEndpointsRejectWithoutToken(t *testing.T) {
	h := testServer()
	for _, path := range []string{"/v1/ping", "/v1/peers"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without token = %d, want 401", path, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got == "" {
			t.Errorf("%s missing WWW-Authenticate", path)
		}
	}
}

func TestProtectedEndpointsRejectWrongToken(t *testing.T) {
	h := testServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token = %d, want 401", rec.Code)
	}
}

func TestProtectedEndpointsAcceptCorrectToken(t *testing.T) {
	h := testServer()
	for _, path := range []string{"/v1/ping", "/v1/peers"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s with token = %d, want 200", path, rec.Code)
		}
	}
}

func TestEmptyTokenNeverAuthorises(t *testing.T) {
	h := New(Options{Card: card.New("id", "n", "0.1.0", "", 0), Token: ""}).Handler
	req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	req.Header.Set("Authorization", "Bearer ")
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
