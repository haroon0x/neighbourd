package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/haroon0x/neighbourd/internal/discovery"
	"github.com/haroon0x/neighbourd/internal/identity"
	"github.com/haroon0x/neighbourd/internal/trust"
)

func newServer(t *testing.T, input string) (*Server, *bytes.Buffer) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	id, err := identity.LoadOrCreate("test-node")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	peers, err := trust.Open(filepath.Join(t.TempDir(), "trust"))
	if err != nil {
		t.Fatalf("trust: %v", err)
	}

	var out bytes.Buffer
	s := New(Options{
		ID:      id,
		Trust:   peers,
		Version: "test",
		Browse: func(time.Duration) []discovery.Peer {
			return nil
		},
		In:  strings.NewReader(input),
		Out: &out,
	})
	return s, &out
}

// responses decodes the newline-delimited JSON the server wrote.
func responses(t *testing.T, out *bytes.Buffer) []map[string]any {
	t.Helper()
	var msgs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("output is not one JSON object per line: %q", line)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

func TestInitializeHandshake(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	s, out := newServer(t, input)
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	msgs := responses(t, out)
	if len(msgs) != 1 {
		t.Fatalf("got %d responses, want 1: the notification must not be answered", len(msgs))
	}
	res := msgs[0]["result"].(map[string]any)
	if res["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v, want %s", res["protocolVersion"], ProtocolVersion)
	}
	info := res["serverInfo"].(map[string]any)
	if info["name"] != "neighbourd" {
		t.Errorf("serverInfo.name = %v", info["name"])
	}
	if _, ok := res["capabilities"].(map[string]any)["tools"]; !ok {
		t.Error("initialize did not advertise the tools capability")
	}
}

func TestToolsListIsWellFormed(t *testing.T) {
	s, out := newServer(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	tools := responses(t, out)[0]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("got %d tools, want 4", len(tools))
	}
	want := map[string]bool{"list_peers": false, "peer_card": false, "call_peer": false, "my_identity": false}
	for _, raw := range tools {
		tool := raw.(map[string]any)
		name, _ := tool["name"].(string)
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected tool %q", name)
			continue
		}
		want[name] = true
		if tool["description"] == "" {
			t.Errorf("%s has no description; the model reads this to choose", name)
		}
		schema, ok := tool["inputSchema"].(map[string]any)
		if !ok || schema["type"] != "object" {
			t.Errorf("%s inputSchema is not an object schema", name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tool %q missing from tools/list", name)
		}
	}
}

func TestUnknownMethodIsAProtocolError(t *testing.T) {
	s, out := newServer(t, `{"jsonrpc":"2.0","id":7,"method":"tools/explode"}`+"\n")
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	msg := responses(t, out)[0]
	errObj, ok := msg["error"].(map[string]any)
	if !ok {
		t.Fatal("unknown method did not produce a JSON-RPC error")
	}
	if errObj["code"].(float64) != -32601 {
		t.Errorf("error code = %v, want -32601", errObj["code"])
	}
}

func TestMalformedLineIsAParseError(t *testing.T) {
	s, out := newServer(t, "{not json}\n"+`{"jsonrpc":"2.0","id":2,"method":"ping"}`+"\n")
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	msgs := responses(t, out)
	if len(msgs) != 2 {
		t.Fatalf("got %d responses, want 2", len(msgs))
	}
	if msgs[0]["error"].(map[string]any)["code"].(float64) != -32700 {
		t.Errorf("first response is not a parse error: %v", msgs[0])
	}
	if _, ok := msgs[1]["result"]; !ok {
		t.Errorf("stream did not recover after a parse error: %v", msgs[1])
	}
}

func TestCallPeerRejectsNonAllowlistedPath(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_peer","arguments":{"id":"abc","path":"/admin/shutdown"}}}` + "\n"
	s, out := newServer(t, input)
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	res := responses(t, out)[0]["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatal("non-allowlisted path was not refused")
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "allowlist") {
		t.Errorf("error text does not explain the allowlist: %q", text)
	}
}

func TestCallPeerOnUnpairedPeerExplainsItself(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_peer","arguments":{"id":"nobody"}}}` + "\n"
	s, out := newServer(t, input)
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	res := responses(t, out)[0]["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatal("calling an unpaired peer did not fail")
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "nobody") {
		t.Errorf("error text does not name the peer: %q", text)
	}
}

func TestMyIdentityReflectsThisNode(t *testing.T) {
	s, out := newServer(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"my_identity","arguments":{}}}`+"\n")
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	text := responses(t, out)[0]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var got map[string]string
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("my_identity is not JSON: %v", err)
	}
	if got["id"] != s.opts.ID.ID {
		t.Errorf("id = %q, want %q", got["id"], s.opts.ID.ID)
	}
	if got["name"] == "" {
		t.Error("name is empty")
	}
}

func TestAllowlistMatching(t *testing.T) {
	s := New(Options{Allow: []string{"/v1/ping"}})
	for path, want := range map[string]bool{
		"/v1/ping":      true,
		"/v1/ping?x=1":  true,
		"/v1/identity":  false,
		"/v1/ping/../x": false,
	} {
		if got := s.allowed(path); got != want {
			t.Errorf("allowed(%q) = %v, want %v", path, got, want)
		}
	}
}
