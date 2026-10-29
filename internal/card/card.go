// Package card defines the document a node publishes at its well-known path.
//
// The shape follows A2A's agent card closely enough that an A2A client can pick
// out name, description and url, while neighbourd's own fields stay nested so the
// two can drift without breaking each other.
//
// A card is a claim about yourself. Nothing in it is verified by anyone. Do not
// treat a peer's card as a statement of fact.
package card

import "github.com/haroon0x/neighbourd/internal/proto"

// Protocol is the wire protocol this build speaks.
const Protocol = proto.Protocol

// Endpoints are the paths a peer will find on this node. Relative by design:
// the host and port come from discovery, not from the card, because DHCP moves
// them.
type Endpoints struct {
	Card   string `json:"card"`
	Health string `json:"health"`
	Ping   string `json:"ping"`
	Peers  string `json:"peers"`
}

// Card is the agent card.
type Card struct {
	SchemaVersion string    `json:"schema_version"`
	Protocol      string    `json:"protocol"`
	Name          string    `json:"name"`
	ID            string    `json:"id"`
	Version       string    `json:"version"`
	Description   string    `json:"description,omitempty"`
	Endpoints     Endpoints `json:"endpoints"`
	Capabilities  []string  `json:"capabilities"`

	// Host and Port are informational. They are what this node believed its
	// address was when it started, and they go stale. Callers must dial the
	// address mDNS resolved, never these.
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
}

// New builds the card for a node.
func New(id, name, version, host string, port int) Card {
	return Card{
		SchemaVersion: "1",
		Protocol:      Protocol,
		Name:          name,
		ID:            id,
		Version:       version,
		Description:   "neighbourd node: discoverable on the local network",
		Endpoints: Endpoints{
			Card:   "/.well-known/agent-card.json",
			Health: "/healthz",
			Ping:   "/v1/ping",
			Peers:  "/v1/peers",
		},
		Capabilities: []string{"discovery", "identity"},
		Host:         host,
		Port:         port,
	}
}
