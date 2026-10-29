# Roadmap

Ordered by what unblocks the next thing, not by what is fun to write.

## v0.1 — the skeleton (current)

- [x] persistent identity: Ed25519 keypair, stable id, device token
- [x] mDNS announce with TXT record
- [x] mDNS browse, printed as a table
- [x] agent card at `/.well-known/agent-card.json`
- [x] bearer auth on `/v1/*`, constant-time compare
- [x] `/v1/ping`, `/v1/peers`
- [ ] resolve mDNS name to a dialable address in `peers` output
- [ ] `--bind` validation that refuses a non-loopback v6 bind unless forced

## v0.2 — pairing

- [ ] `veranda pair <id>` — request a token from a peer that is showing a
      short-lived code; token bound to the requester's public key
- [ ] signed cards: `sig` field over the card body, verified on browse, shown as
      "unsigned" when absent
- [ ] token rotation and revocation
- [ ] `veranda trust` listing pinned peers

The point of this version is that a rogue announcement cannot collect a token.
Until it lands, treat every peer as unauthenticated.

## v0.3 — MCP adapter

- [ ] `veranda mcp` — stdio MCP server exposing `list_peers`, `call_peer`,
      `peer_card`
- [ ] peer selection by id, never by name
- [ ] per-peer tool allowlist so a remote agent cannot call everything

This is the version that makes veranda useful to an MCP client with no
configuration step.

## v0.4 — A2A conformance

- [ ] speak A2A for agent-to-agent messages instead of a private envelope
- [ ] align the card with the A2A schema where it overlaps
- [ ] track LAD-A2A draft revisions; document deviations
- [ ] `well-known` discovery endpoint for the LAD-A2A path

## Later

- blob transfer, delegated to LocalSend's REST API rather than reimplemented
- TLS with certificate pinning, after pairing exists to make pinning meaningful
- a read-only browser view for phones, since a phone will not run this
- router-agnostic reachability across VLANs, only if it can avoid becoming a
  tunnel

## Explicitly not planned

- any form of internet exposure, relay, or hole punching
- a central server, hosted or self-hosted
- a GUI before the protocol is stable
