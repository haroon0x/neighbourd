// Package server is the HTTP surface of a node.
//
// Three endpoints are public on purpose: a peer has to be able to read the card
// and reach the pairing endpoint before it holds any credential. Nothing you
// would not shout across a room belongs in either.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/haroon0x/neighbourd/internal/card"
	"github.com/haroon0x/neighbourd/internal/discovery"
	"github.com/haroon0x/neighbourd/internal/expose"
	"github.com/haroon0x/neighbourd/internal/identity"
	"github.com/haroon0x/neighbourd/internal/pair"
	"github.com/haroon0x/neighbourd/internal/proto"
	"github.com/haroon0x/neighbourd/internal/proxy"
	"github.com/haroon0x/neighbourd/internal/trust"
)

// Options configures a node's HTTP server.
type Options struct {
	Card  card.Card
	Self  *identity.Identity
	Trust *trust.Store

	// Pair is the current pairing window. Nil means pairing is closed and the
	// endpoint refuses everything, which is the default.
	Pair *pair.Window

	// Browse scans the network for /v1/peers. Injected so tests need no mDNS.
	Browse func(wait time.Duration) []discovery.Peer

	// Expose lists local services offered to paired peers. Nil means the node
	// offers nothing and both the listing and the proxy answer 404.
	Expose *expose.Store

	// ProxyAllowRemote lets an exposed origin live off-box. Only ever set from
	// an explicit operator flag; the default keeps this node from being a pivot.
	ProxyAllowRemote bool

	Log *log.Logger
}

// New returns a server with routes and auth wired up. The caller owns the
// listener and shutdown.
func New(opts Options) *http.Server {
	if opts.Log == nil {
		opts.Log = log.Default()
	}

	a := &authorizer{
		self:   opts.Self,
		peers:  opts.Trust,
		nonces: newNonceCache(0),
		log:    opts.Log,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET "+proto.PathCard, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, opts.Card)
	})

	mux.HandleFunc("GET "+proto.PathHealth, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"name": opts.Card.Name,
			"id":   opts.Card.ID,
			"time": time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("POST "+proto.PathPairRequest, func(w http.ResponseWriter, r *http.Request) {
		handlePair(w, r, opts, a)
	})

	mux.HandleFunc("GET "+proto.PathPing, authed(a, func(w http.ResponseWriter, r *http.Request, caller who) {
		writeJSON(w, http.StatusOK, map[string]any{
			"id":       opts.Card.ID,
			"name":     opts.Card.Name,
			"version":  opts.Card.Version,
			"you":      caller.ID,
			"operator": caller.Operator,
		})
	}))

	mux.HandleFunc("GET "+proto.PathIdentity, authed(a, func(w http.ResponseWriter, r *http.Request, _ who) {
		writeJSON(w, http.StatusOK, map[string]any{
			"id":         opts.Card.ID,
			"name":       opts.Card.Name,
			"public_key": opts.Self.PublicKey,
			"version":    opts.Card.Version,
			"protocol":   proto.Protocol,
		})
	}))

	mux.HandleFunc("GET "+proto.PathPeers, authed(a, func(w http.ResponseWriter, r *http.Request, _ who) {
		network := []discovery.Peer{}
		if opts.Browse != nil {
			network = opts.Browse(2 * time.Second)
		}
		paired := make([]map[string]any, 0)
		for _, p := range opts.Trust.List() {
			entry := map[string]any{
				"id":        p.ID,
				"name":      p.Name,
				"paired_at": p.PairedAt,
			}
			if !p.LastSeen.IsZero() {
				entry["last_seen"] = p.LastSeen
			}
			paired = append(paired, entry)
		}
		writeJSON(w, http.StatusOK, map[string]any{"network": network, "paired": paired})
	}))

	// What this node offers. Authenticated: the names of a machine's local
	// services are not public information, and the card is world-readable on the
	// LAN. A peer learns these after pairing, which is when it has earned them.
	mux.HandleFunc("GET "+proto.PathResources, authed(a, func(w http.ResponseWriter, r *http.Request, _ who) {
		resources := []map[string]any{}
		if opts.Expose != nil {
			for _, t := range opts.Expose.List() {
				entry := map[string]any{"name": t.Name}
				if t.Description != "" {
					entry["description"] = t.Description
				}
				resources = append(resources, entry)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id":        opts.Card.ID,
			"name":      opts.Card.Name,
			"resources": resources,
		})
	}))

	// Forwarding. The path is part of the signed canonical form, so a caller
	// cannot swap the resource or the target path without invalidating the
	// signature. Any method is allowed because local APIs are not all GETs.
	mux.HandleFunc(proto.PathProxy+"/", authed(a, func(w http.ResponseWriter, r *http.Request, _ who) {
		if opts.Expose == nil {
			writeError(w, http.StatusNotFound, "this node exposes nothing")
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, proto.PathProxy+"/")
		name, tail, _ := strings.Cut(rest, "/")
		target, ok := opts.Expose.Get(name)
		if !ok {
			writeError(w, http.StatusNotFound, "no exposed resource named %q", name)
			return
		}
		if escapesOrigin(tail) {
			writeError(w, http.StatusBadRequest, "path may not contain '..' segments")
			return
		}
		if opts.Log != nil {
			opts.Log.Printf("proxy %s -> %s/%s", name, target.Origin, tail)
		}
		h := &proxy.Handler{Origin: target.Origin, AllowRemote: opts.ProxyAllowRemote}
		h.Serve(w, r, tail)
	}))

	return &http.Server{
		Handler:           logRequests(opts.Log, mux),
		ReadHeaderTimeout: 5 * time.Second,
		// No WriteTimeout on purpose: a proxied request can stream a model's
		// output for minutes, and a deadline here would cut it off mid-sentence.
		IdleTimeout: 60 * time.Second,
	}
}

// escapesOrigin rejects path traversal before the request reaches a local
// service. The dial guard already pins the destination, so this is defence in
// depth rather than the only barrier.
func escapesOrigin(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// handlePair registers a requester as a peer.
//
// Order matters: the requester's self-signature is checked before the code is
// redeemed, so a malformed request does not burn the operator's one-time code,
// and possession of the private key for the submitted public key is proven
// before anything is pinned.
func handlePair(w http.ResponseWriter, r *http.Request, opts Options, a *authorizer) {
	if opts.Pair == nil || !opts.Pair.Open() {
		writeError(w, http.StatusNotFound, "pairing is closed on this node; start serve with --pair")
		return
	}

	body, err := readAndReplaceBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: %v", err)
		return
	}

	var req struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
		Protocol  string `json:"protocol"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "body is not the expected JSON")
		return
	}
	if req.ID == "" || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "id and public_key are required")
		return
	}
	if req.Protocol != proto.Protocol {
		writeError(w, http.StatusBadRequest, "protocol %q is not supported; this node speaks %s", req.Protocol, proto.Protocol)
		return
	}

	// The claimed id must be the one the submitted key actually produces,
	// otherwise a peer could register a key it does not hold.
	derived, err := identity.IDFromPublicKeyB64(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "public_key is not a valid Ed25519 key")
		return
	}
	if derived != req.ID {
		writeError(w, http.StatusBadRequest, "id does not match public_key")
		return
	}

	// Prove possession of the private key before pinning anything.
	if err := identity.Verify(req.PublicKey, proto.Pairing(body), decodeSig(r)); err != nil {
		writeError(w, http.StatusUnauthorized, "request must be signed with the key being registered: %v", err)
		return
	}

	// Only now spend the code, so the window survives a failed attempt.
	if !opts.Pair.Redeem(r.Header.Get(proto.HeaderPairCode)) {
		writeError(w, http.StatusUnauthorized, "pairing code is wrong, expired, or already used")
		return
	}

	token, err := trust.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate token: %v", err)
		return
	}
	if err := opts.Trust.RememberInbound(req.ID, req.Name, req.PublicKey, token); err != nil {
		writeError(w, http.StatusInternalServerError, "store peer: %v", err)
		return
	}

	a.log.Printf("paired with %s (%s) from %s", req.Name, req.ID, r.RemoteAddr)

	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"you":   map[string]any{"id": req.ID, "name": req.Name},
		"server": map[string]any{
			"id":         opts.Card.ID,
			"name":       opts.Card.Name,
			"public_key": opts.Self.PublicKey,
			"version":    opts.Card.Version,
			"protocol":   proto.Protocol,
		},
	})
}

func authed(a *authorizer, next func(http.ResponseWriter, *http.Request, who)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, err := a.authorize(r)
		if err != nil {
			var ae *authError
			if errors.As(err, &ae) {
				if ae.status == http.StatusUnauthorized {
					w.Header().Set("WWW-Authenticate", `Bearer realm="neighbourd"`)
				}
				writeError(w, ae.status, "%s", ae.msg)
				return
			}
			writeError(w, http.StatusInternalServerError, "authorisation error")
			return
		}
		next(w, r, caller)
	}
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

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, args...)})
}

func logRequests(l *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		l.Printf("%s %s %s %s %s",
			r.RemoteAddr, r.Method, r.URL.Path, r.UserAgent(), time.Since(start).Round(time.Millisecond))
	})
}
