// Package proto defines what goes on the wire: header names, the canonical
// bytes a signature covers, and the protocol version.
//
// Both the client and the server build signatures from this package. If the two
// sides ever computed different canonical bytes, every request would fail to
// verify, so there is exactly one implementation of it and both import it.
//
// The canonical forms are domain separated: a signature made for a pairing
// request cannot be replayed as a normal request, and vice versa.
package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Protocol is the wire protocol version spoken by this build.
const Protocol = "neighbourd/0.2"

// Paths.
const (
	PathCard        = "/.well-known/agent-card.json"
	PathHealth      = "/healthz"
	PathPairRequest = "/v1/pair/request"
	PathPing        = "/v1/ping"
	PathPeers       = "/v1/peers"
	PathIdentity    = "/v1/identity"
	PathResources   = "/v1/resources"
	PathProxy       = "/v1/proxy"
)

// Headers.
const (
	HeaderID       = "X-Neighbourd-Id"
	HeaderTS       = "X-Neighbourd-Ts"
	HeaderNonce    = "X-Neighbourd-Nonce"
	HeaderSig      = "X-Neighbourd-Sig"
	HeaderPairCode = "X-Neighbourd-Pair-Code"
)

// MaxSkew is how far a request timestamp may differ from local time. It is
// generous because two laptops' clocks drift; replay is prevented by the nonce
// cache, not by a tight window.
const MaxSkew = 5 * time.Minute

// Request is the bytes a peer signs for an authenticated request.
//
// target is the request URI including any query string, so a signature cannot
// be moved onto a different endpoint or have its parameters swapped. bodyHash
// covers the body, empty bodies included.
func Request(method, target, ts, nonce string, body []byte) []byte {
	return []byte("neighbourd/req/v1\n" + method + "\n" + target + "\n" + ts + "\n" + nonce + "\n" + BodyHash(body))
}

// Pairing is the bytes a requester signs to prove it holds the private key for
// the public key it is registering.
func Pairing(body []byte) []byte {
	return []byte("neighbourd/pair/v1\n" + BodyHash(body))
}

// BodyHash is the lowercase hex sha256 of a body.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
