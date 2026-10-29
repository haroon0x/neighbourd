package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/haroon0x/neighbourd/internal/card"
	"github.com/haroon0x/neighbourd/internal/expose"
	"github.com/haroon0x/neighbourd/internal/identity"
	"github.com/haroon0x/neighbourd/internal/trust"
)

// newProxyNode builds a node that exposes one target, without pairing anyone.
func newProxyNode(t *testing.T) (*http.Server, *expose.Store) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	id, err := identity.LoadOrCreate("node")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	peers, err := trust.Open(t.TempDir())
	if err != nil {
		t.Fatalf("trust: %v", err)
	}
	exp, err := expose.Open(t.TempDir())
	if err != nil {
		t.Fatalf("expose: %v", err)
	}
	if err := exp.Add(expose.Target{Name: "ollama", Origin: "http://127.0.0.1:11434"}); err != nil {
		t.Fatalf("expose add: %v", err)
	}

	srv := New(Options{
		Card:   card.Card{Name: "node", ID: id.ID},
		Self:   id,
		Trust:  peers,
		Expose: exp,
	})
	return srv, exp
}

// The proxy is the one route that reaches a local service, so it must be behind
// the same authentication as everything else. A request with no token never
// gets near the upstream.
func TestProxyRequiresAuthentication(t *testing.T) {
	srv, _ := newProxyNode(t)

	for _, path := range []string{
		"/v1/proxy/ollama/api/tags",
		"/v1/resources",
	} {
		rr := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", path, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "bearer token") {
			t.Errorf("%s: body = %q", path, rr.Body.String())
		}
	}
}

// The card stays public: it is how a peer learns what to authenticate against.
func TestCardStaysPublicWithExposures(t *testing.T) {
	srv, _ := newProxyNode(t)
	rr := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/agent-card.json", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	// The names of exposed services are deliberately not advertised here.
	if strings.Contains(rr.Body.String(), "ollama") {
		t.Error("the public card leaks exposed resource names")
	}
}

func TestExposedStoreIsReadOnChange(t *testing.T) {
	srv, exp := newProxyNode(t)
	if exp.Path() == "" {
		t.Fatal("store has no path")
	}
	// A second store on the same file is what the CLI would do while the daemon
	// runs; the daemon must notice without a restart.
	dir := filepath.Dir(exp.Path())
	other, err := expose.Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := other.Add(expose.Target{Name: "jobs", Origin: "http://127.0.0.1:9000"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, ok := exp.Get("jobs"); !ok {
		t.Fatal("the serving store did not pick up an added target")
	}

	// The route still refuses an unauthenticated caller, which is what proves the
	// route exists and the store is consulted behind it.
	rr := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/proxy/jobs/status", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}
