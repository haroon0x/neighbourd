// Package client talks to a paired peer.
//
// Every call is signed with this node's key. The token alone is not enough on
// the far side, which is the point of v0.2: a stolen peers.json does not let
// anyone impersonate you, and a stolen token does not either.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/haroon0x/neighbourd/internal/identity"
	"github.com/haroon0x/neighbourd/internal/proto"
	"github.com/haroon0x/neighbourd/internal/trust"
)

// Client makes signed requests to peers.
type Client struct {
	ID   *identity.Identity
	HTTP *http.Client
}

// CallResource makes a signed request through a peer's proxy to a local service
// that peer exposes. method is "" for GET, and body may be nil.
//
// The method and the whole path sit inside the signature, so the far side knows
// exactly which resource and which path it agreed to serve, and a caller cannot
// retarget the request without invalidating it.
func (c *Client) CallResource(ctx context.Context, peer trust.Peer, baseURL, resource, path, method string, body []byte, contentType string) ([]byte, error) {
	if method == "" {
		method = http.MethodGet
	}
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.do(ctx, peer, method, baseURL, proto.PathProxy+"/"+resource+path, body, contentType)
}

// New returns a client that signs as id.
func New(id *identity.Identity) *Client {
	return &Client{ID: id, HTTP: &http.Client{
		// No overall Timeout: a proxied call can be a model generating for
		// minutes, and the caller's context is the real deadline. A blanket
		// timeout here would cut long answers off mid-stream, which is exactly
		// the failure this had on the first attempt.
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: 5 * time.Minute,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   4,
		},
	}}
}

// Pair redeems a pairing code at baseURL and returns the peer record to store.
//
// The code was read off the other machine's screen. The request is signed with
// this node's key, so the far side pins a key it knows the requester holds.
func (c *Client) Pair(ctx context.Context, baseURL, code string) (trust.Peer, error) {
	body, err := json.Marshal(map[string]string{
		"id":         c.ID.ID,
		"name":       c.ID.Name,
		"public_key": c.ID.PublicKey,
		"protocol":   proto.Protocol,
	})
	if err != nil {
		return trust.Peer{}, err
	}
	sig, err := c.ID.Sign(proto.Pairing(body))
	if err != nil {
		return trust.Peer{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+proto.PathPairRequest, bytes.NewReader(body))
	if err != nil {
		return trust.Peer{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proto.HeaderPairCode, code)
	req.Header.Set(proto.HeaderSig, base64.StdEncoding.EncodeToString(sig))

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return trust.Peer{}, fmt.Errorf("contact %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		return trust.Peer{}, fmt.Errorf("%s replied %d: %s", baseURL, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out struct {
		Token  string `json:"token"`
		Server struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			Version   string `json:"version,omitempty"`
		} `json:"server"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return trust.Peer{}, fmt.Errorf("parse pairing response: %w", err)
	}
	if out.Token == "" || out.Server.ID == "" {
		return trust.Peer{}, fmt.Errorf("pairing response is missing token or server identity")
	}

	// The server's id must be derived from the key it claims. Otherwise a peer
	// could pick a name that collides with one already pinned.
	derived, err := identity.IDFromPublicKeyB64(out.Server.PublicKey)
	if err != nil {
		return trust.Peer{}, fmt.Errorf("peer public key: %w", err)
	}
	if derived != out.Server.ID {
		return trust.Peer{}, fmt.Errorf("peer id %s does not match its public key (derived %s)", out.Server.ID, derived)
	}

	return trust.Peer{
		ID:          out.Server.ID,
		Name:        out.Server.Name,
		PublicKey:   out.Server.PublicKey,
		TokenToPeer: out.Token,
		BaseURL:     strings.TrimRight(baseURL, "/"),
		PairedAt:    time.Now().UTC(),
	}, nil
}

// Get makes a signed GET to a peer and returns the response body.
func (c *Client) Get(ctx context.Context, peer trust.Peer, baseURL, target string) ([]byte, error) {
	return c.do(ctx, peer, http.MethodGet, baseURL, target, nil, "")
}

func (c *Client) do(ctx context.Context, peer trust.Peer, method, baseURL, target string, body []byte, contentType string) ([]byte, error) {
	ts := fmt.Sprint(time.Now().Unix())
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	sig, err := c.ID.Sign(proto.Request(method, target, ts, nonce, body))
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(baseURL, "/") + target
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer "+peer.TokenToPeer)
	req.Header.Set(proto.HeaderID, c.ID.ID)
	req.Header.Set(proto.HeaderTS, ts)
	req.Header.Set(proto.HeaderNonce, nonce)
	req.Header.Set(proto.HeaderSig, base64.StdEncoding.EncodeToString(sig))

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Minute}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contact %s: %w", url, err)
	}
	defer resp.Body.Close()
	// Generous: a proxied model response can be long.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s replied %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
