// Package mcp is a Model Context Protocol server over stdio.
//
// The transport is newline-delimited JSON-RPC 2.0 on stdin and stdout. Nothing
// may be written to stdout except protocol messages, so every diagnostic in this
// package goes to stderr.
//
// The tools are deliberately narrow: a peer is chosen by id, and call_peer is
// restricted to a path allowlist. An MCP client is an agent with its own ideas
// about what to do next, and "make arbitrary signed requests to every machine on
// your network" is not a capability worth handing it by default.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/haroon0x/neighbourd/internal/card"
	"github.com/haroon0x/neighbourd/internal/client"
	"github.com/haroon0x/neighbourd/internal/discovery"
	"github.com/haroon0x/neighbourd/internal/identity"
	"github.com/haroon0x/neighbourd/internal/proto"
	"github.com/haroon0x/neighbourd/internal/trust"
)

// ProtocolVersion is the MCP revision this server implements.
const ProtocolVersion = "2025-06-18"

// DefaultAllowlist is what call_peer may reach without an explicit flag.
var DefaultAllowlist = []string{proto.PathPing, proto.PathIdentity, proto.PathPeers}

// Options configures the server.
type Options struct {
	ID      *identity.Identity
	Trust   *trust.Store
	Version string

	// Browse scans the LAN. Nil disables the network half of list_peers.
	Browse func(wait time.Duration) []discovery.Peer

	// Allow is the set of paths call_peer may request.
	Allow []string

	In  io.Reader
	Out io.Writer
	Log io.Writer
}

// Server answers MCP requests until its input ends.
type Server struct {
	opts Options
	enc  *json.Encoder
}

// New builds a server with defaults filled in.
func New(opts Options) *Server {
	if opts.In == nil {
		opts.In = strings.NewReader("")
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	if len(opts.Allow) == 0 {
		opts.Allow = DefaultAllowlist
	}
	if opts.Browse == nil {
		opts.Browse = func(time.Duration) []discovery.Peer { return nil }
	}
	enc := json.NewEncoder(opts.Out)
	return &Server{opts: opts, enc: enc}
}

// Run reads messages until EOF. One message per line.
func (s *Server) Run(ctx context.Context) error {
	sc := bufio.NewScanner(s.opts.In)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.writeError(nil, -32700, "parse error")
			continue
		}
		if req.ID == nil {
			// Notification: nothing to answer, but initialised must not error.
			continue
		}
		s.handle(ctx, req)
	}
	return sc.Err()
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) handle(ctx context.Context, req request) {
	switch req.Method {
	case "initialize":
		s.writeResult(req.ID, map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{
				"name":    "neighbourd",
				"version": s.opts.Version,
			},
			"instructions": "Neighbours on the local network. Start with list_peers; call_peer needs a peer id and an allowlisted path.",
		})

	case "ping":
		s.writeResult(req.ID, map[string]any{})

	case "tools/list":
		s.writeResult(req.ID, map[string]any{"tools": s.tools()})

	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			s.writeError(req.ID, -32602, "tools/call params must be {name, arguments}")
			return
		}
		text, err := s.callTool(ctx, p.Name, p.Arguments)
		if err != nil {
			// Tool failures are results, not protocol errors: the client should
			// see them as text it can reason about.
			s.writeResult(req.ID, map[string]any{
				"content": []map[string]string{{"type": "text", "text": err.Error()}},
				"isError": true,
			})
			return
		}
		s.writeResult(req.ID, map[string]any{
			"content": []map[string]string{{"type": "text", "text": text}},
			"isError": false,
		})

	default:
		s.writeError(req.ID, -32601, "method not found: "+req.Method)
	}
}

func (s *Server) tools() []map[string]any {
	obj := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{
			"type":                 "object",
			"properties":           props,
			"required":             required,
			"additionalProperties": false,
		}
	}
	str := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}

	return []map[string]any{
		{
			"name":        "list_peers",
			"description": "List machines on this network. 'paired' means you can call it; 'network' is what mDNS announced, including nodes you have not paired with.",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        "peer_card",
			"description": "Fetch a peer's agent card. This is a public, unauthenticated document: a claim the peer makes about itself, not a verified fact.",
			"inputSchema": obj(map[string]any{
				"id": str("peer id, as shown by list_peers"),
			}, "id"),
		},
		{
			"name":        "call_peer",
			"description": "Make a signed request to a paired peer. Only allowlisted paths are reachable; /v1/ping confirms a live, authenticated peer.",
			"inputSchema": obj(map[string]any{
				"id":   str("peer id"),
				"path": str("path to request, must be allowlisted; defaults to /v1/ping"),
			}, "id"),
		},
		{
			"name":        "my_identity",
			"description": "This machine's id and name, which the other side needs in order to pair with you.",
			"inputSchema": obj(map[string]any{}),
		},
	}
}

func (s *Server) callTool(ctx context.Context, name string, raw json.RawMessage) (string, error) {
	switch name {
	case "list_peers":
		return s.listPeers()
	case "my_identity":
		return marshal(map[string]any{
			"id":       s.opts.ID.ID,
			"name":     s.opts.ID.Name,
			"version":  s.opts.Version,
			"protocol": proto.Protocol,
		})
	case "peer_card":
		var a struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &a); err != nil || a.ID == "" {
			return "", fmt.Errorf("id is required")
		}
		peer, err := s.resolve(a.ID)
		if err != nil {
			return "", err
		}
		if peer.BaseURL == "" {
			return "", fmt.Errorf("%s (%s) has no recorded address; pair again with a host:port", peer.Name, shortID(peer.ID))
		}
		body, err := client.New(s.opts.ID).Unsigned(ctx, peer.BaseURL, proto.PathCard)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(body)), nil
	case "call_peer":
		var a struct {
			ID   string `json:"id"`
			Path string `json:"path"`
		}
		if err := json.Unmarshal(raw, &a); err != nil || a.ID == "" {
			return "", fmt.Errorf("id is required")
		}
		path := a.Path
		if path == "" {
			path = proto.PathPing
		}
		if !s.allowed(path) {
			return "", fmt.Errorf("%s is not in the allowlist (allowed: %s)", path, strings.Join(s.opts.Allow, ", "))
		}
		peer, err := s.resolve(a.ID)
		if err != nil {
			return "", err
		}
		if peer.TokenToPeer == "" {
			return "", fmt.Errorf("not paired with %s (%s); run: neighbourd pair <host:port> then trust list", peer.Name, shortID(peer.ID))
		}
		if peer.BaseURL == "" {
			return "", fmt.Errorf("%s has no recorded address; pair again with a host:port", peer.Name)
		}
		body, err := client.New(s.opts.ID).Get(ctx, peer, peer.BaseURL, path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(body)), nil
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

func (s *Server) listPeers() (string, error) {
	paired := []map[string]any{}
	for _, p := range s.opts.Trust.List() {
		entry := map[string]any{
			"id":       p.ID,
			"name":     p.Name,
			"can_call": p.TokenToPeer != "",
		}
		if p.BaseURL != "" {
			entry["address"] = p.BaseURL
		}
		if !p.LastSeen.IsZero() {
			entry["last_seen"] = p.LastSeen.Format(time.RFC3339)
		}
		paired = append(paired, entry)
	}

	network := []map[string]any{}
	for _, p := range s.opts.Browse(2 * time.Second) {
		network = append(network, map[string]any{
			"id":     p.ID,
			"name":   p.Name,
			"addr":   p.Addr,
			"port":   p.Port,
			"paired": p.ID == s.opts.ID.ID || hasPeer(s.opts.Trust, p.ID),
		})
	}
	sort.Slice(network, func(i, j int) bool {
		return fmt.Sprint(network[i]["name"]) < fmt.Sprint(network[j]["name"])
	})

	return marshal(map[string]any{
		"me":      map[string]string{"id": s.opts.ID.ID, "name": s.opts.ID.Name},
		"paired":  paired,
		"network": network,
	})
}

func (s *Server) resolve(ref string) (trust.Peer, error) {
	if p, ok := s.opts.Trust.Get(ref); ok {
		return p, nil
	}
	// A name is accepted for convenience, but ambiguity is refused rather than
	// guessed: calling the wrong machine with a valid signature is worse than
	// an error message.
	return s.opts.Trust.ByName(ref)
}

func (s *Server) allowed(path string) bool {
	base, _, _ := strings.Cut(path, "?")
	for _, a := range s.opts.Allow {
		if a == base {
			return true
		}
	}
	return false
}

func (s *Server) writeResult(id json.RawMessage, result any) {
	s.enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (s *Server) writeError(id json.RawMessage, code int, msg string) {
	s.enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcError{Code: code, Message: msg}})
}

func marshal(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func hasPeer(store *trust.Store, id string) bool {
	_, ok := store.Get(id)
	return ok
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

var _ = card.Card{}
