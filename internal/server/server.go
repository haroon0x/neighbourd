// Package server is the HTTP surface of a node.
//
// Two endpoints are public on purpose: a peer has to be able to read the card
// before it holds a token. Nothing private belongs in either.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/haroon0x/veranda/internal/card"
	"github.com/haroon0x/veranda/internal/discovery"
)

// Options configures a node's HTTP server.
type Options struct {
	Card  card.Card
	Token string
	// Browses the network for /v1/peers. Injected so tests do not need mDNS.
	Browse func(wait time.Duration) []discovery.Peer
	Log    *log.Logger
}

// New returns a server with routes and auth wired up. The caller owns the
// listener and shutdown.
func New(opts Options) *http.Server {
	if opts.Log == nil {
		opts.Log = log.Default()
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, opts.Card)
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"name": opts.Card.Name,
			"id":   opts.Card.ID,
			"time": time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("GET /v1/ping", requireToken(opts.Token, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"id":      opts.Card.ID,
			"name":    opts.Card.Name,
			"version": opts.Card.Version,
		})
	}))

	mux.HandleFunc("GET /v1/peers", requireToken(opts.Token, func(w http.ResponseWriter, r *http.Request) {
		if opts.Browse == nil {
			writeJSON(w, http.StatusOK, []discovery.Peer{})
			return
		}
		writeJSON(w, http.StatusOK, opts.Browse(2*time.Second))
	}))

	return &http.Server{
		Handler:           logRequests(opts.Log, mux),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// requireToken gates a handler behind `Authorization: Bearer <token>`.
//
// The comparison is constant time because the alternative is a timing oracle on
// a shared network. It does not make the token an identity: whoever holds it is
// accepted, which is exactly the weakness v0.2's pairing handshake addresses.
func requireToken(token string, next http.HandlerFunc) http.HandlerFunc {
	want := []byte(token)
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := bearer(r)
		if !ok || token == "" || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="veranda"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid token"})
			return
		}
		next(w, r)
	}
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return "", false
	}
	return h[len(prefix):], true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Status is already written; nothing useful left to say to the client.
		return
	}
}

func logRequests(l *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		l.Printf("%s %s %s %s %s",
			r.RemoteAddr, r.Method, r.URL.Path, r.UserAgent(), time.Since(start).Round(time.Millisecond))
	})
}
