# Roadmap

Ordered by what unblocks the next thing, not by what is fun to write.

## v0.1 — the skeleton (done)

- [x] persistent identity: Ed25519 keypair, stable id, operator token
- [x] mDNS announce with TXT record
- [x] mDNS browse, printed as a table
- [x] agent card at `/.well-known/agent-card.json`
- [x] bearer auth on `/v1/*`, constant-time compare
- [x] interface filtering, so Docker bridges are not announced

## v0.2 — pairing and signed requests (done)

- [x] one-time pairing codes: 8 characters, single use, 5 minute window
- [x] self-signed pairing request, so a key must be held to be pinned
- [x] per-peer tokens, two credential slots per record
- [x] Ed25519 signature over method, target, timestamp, nonce, body hash
- [x] replay protection by nonce, with a fail-closed cache
- [x] clock skew rejection that names the offset
- [x] operator token limited to loopback
- [x] `SIGHUP` opens a new pairing window without a restart
- [x] `trust list` / `trust remove`, revocation in both directions
- [x] store safe against two processes sharing one file
- [x] golden tests for the canonical signing forms

## v0.3 — MCP adapter (done)

- [x] `neighbourd mcp` — stdio MCP server exposing `list_peers`, `peer_card`,
      `call_peer`, `my_identity`
- [x] `mcp --print-config` emits the client block with the absolute binary path
- [x] peer selection by id, falling back to an unambiguous name
- [x] per-path allowlist for `call_peer`, defaults to the three read endpoints
- [x] `up` and interactive `pair` so setup is three commands, not five

## v0.4 — expose and proxy (done)

- [x] `neighbourd expose <host:port> --as NAME` records a loopback service
- [x] `GET /v1/resources` lists what a node offers, authenticated
- [x] `/v1/proxy/<resource>/<path>` forwards signed requests, streaming
- [x] `neighbourd call <peer> --resource NAME` from the other machine
- [x] MCP: `peer_resources`, and `resource` on `call_peer`, allowlisted by name
- [x] dial guard: loopback only, verified after resolution, no pivot
- [x] caller credentials and protocol headers stripped before forwarding

## v0.5 — A2A conformance and TLS

- [ ] speak A2A for agent-to-agent messages instead of a private envelope
- [ ] align the card with the A2A schema where it overlaps
- [ ] track LAD-A2A draft revisions; document deviations
- [ ] TLS with certificate pinning, using the keys already pinned at pairing
- [ ] refresh `base_url` from discovery when a peer moves

## Later

- blob transfer, delegated to LocalSend's REST API rather than reimplemented
- a read-only browser view for phones, since a phone will not run this
- reachability across VLANs, only if it can avoid becoming a tunnel

## Explicitly not planned

- any form of internet exposure, relay, or hole punching
- a central server, hosted or self-hosted
- a GUI before the protocol is stable
