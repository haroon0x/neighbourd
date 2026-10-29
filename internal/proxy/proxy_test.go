package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// upstream is the local service the peer should reach but cannot dial itself.
func upstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/generate" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"response":"hel`))
			w.Write([]byte(`lo"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"models":["qwen2.5:0.5b"]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestForwardsPathAndQuery(t *testing.T) {
	up := upstream(t)
	h := &Handler{Origin: up.URL}

	req := httptest.NewRequest(http.MethodGet, "/v1/proxy/ollama/api/tags?x=1", nil)
	rr := httptest.NewRecorder()
	h.Serve(rr, req, "/api/tags")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), "qwen2.5") {
		t.Errorf("body = %q", rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type = %q", ct)
	}
}

// A peer must not be able to smuggle credentials into a local service that
// trusts whatever arrives on loopback.
func TestStripsCallerCredentials(t *testing.T) {
	var gotAuth, gotCookie, gotPeerID, gotCT string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		gotPeerID = r.Header.Get("X-Neighbourd-Id")
		gotCT = r.Header.Get("Content-Type")
		w.Write([]byte("ok"))
	}))
	defer up.Close()

	h := &Handler{Origin: up.URL}
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/ollama/api/chat", strings.NewReader(`{"model":"x"}`))
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("X-Neighbourd-Id", "abc123")
	req.Header.Set("X-Neighbourd-Sig", "sig")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	h.Serve(rr, req, "/api/chat")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body)
	}
	if gotAuth != "" {
		t.Errorf("Authorization was forwarded: %q", gotAuth)
	}
	if gotCookie != "" {
		t.Errorf("Cookie was forwarded: %q", gotCookie)
	}
	if gotPeerID != "" {
		t.Errorf("protocol header was forwarded: %q", gotPeerID)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type was not forwarded: %q", gotCT)
	}
}

func TestForwardsPostBody(t *testing.T) {
	var body string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64)
		n, _ := r.Body.Read(buf)
		body = string(buf[:n])
		w.Write([]byte(`{"response":"hi"}`))
	}))
	defer up.Close()

	h := &Handler{Origin: up.URL}
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/ollama/api/generate", strings.NewReader(`{"prompt":"hi"}`))
	rr := httptest.NewRecorder()
	h.Serve(rr, req, "/api/generate")

	if !strings.Contains(body, `"prompt":"hi"`) {
		t.Errorf("body was not forwarded: %q", body)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d", rr.Code)
	}
}

// The dial guard is the difference between a proxy and a pivot: a hostname that
// resolves off-box must be refused, checked after resolution.
func TestRefusesNonLoopbackTarget(t *testing.T) {
	for _, origin := range []string{"http://192.0.2.1:80", "http://10.255.255.1:8080"} {
		h := &Handler{Origin: origin, AllowRemote: false}
		req := httptest.NewRequest(http.MethodGet, "/v1/proxy/db/x", nil)
		rr := httptest.NewRecorder()
		h.Serve(rr, req, "/x")
		if rr.Code != http.StatusBadGateway {
			t.Errorf("%s: status = %d, want 502", origin, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "not loopback") {
			t.Errorf("%s: body does not explain the refusal: %q", origin, rr.Body.String())
		}
	}
}

func TestUpstreamStatusPassesThrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "model not found", http.StatusNotFound)
	}))
	defer up.Close()

	h := &Handler{Origin: up.URL}
	req := httptest.NewRequest(http.MethodGet, "/v1/proxy/ollama/api/tags", nil)
	rr := httptest.NewRecorder()
	h.Serve(rr, req, "/api/tags")

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 passthrough", rr.Code)
	}
}

func TestDeadUpstreamIs502(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead := up.URL
	up.Close() // nothing listening now

	h := &Handler{Origin: dead}
	req := httptest.NewRequest(http.MethodGet, "/v1/proxy/ollama/api/tags", nil)
	rr := httptest.NewRecorder()
	h.Serve(rr, req, "/api/tags")

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "local service did not answer") {
		t.Errorf("body = %q", rr.Body.String())
	}
}

func TestEmptyRestMeansRoot(t *testing.T) {
	var gotPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte("ok"))
	}))
	defer up.Close()

	h := &Handler{Origin: up.URL}
	rr := httptest.NewRecorder()
	h.Serve(rr, httptest.NewRequest(http.MethodGet, "/v1/proxy/ollama", nil), "")

	if gotPath != "/" {
		t.Errorf("path = %q, want /", gotPath)
	}
}
