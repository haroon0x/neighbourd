# veranda

Agents on your LAN, meeting without a broker.

Two machines on the same Wi-Fi cannot find each other without being told where
to look. Agent frameworks assume one of two things: the other agent has a public
URL, or a human pasted a host and port into a config file. On a home network
neither is true.

veranda makes local agents discoverable. Start it on each machine and it
announces itself over mDNS, serves its agent card, and hands out a token so the
other machine has something to authenticate against. No cloud, no broker, no
port forwarding.

A veranda is the threshold of a house: outside the walls, inside the property,
where neighbours actually meet. That is the boundary this tool is built for.

## What works today (v0.1)

- persistent identity per machine (Ed25519 keypair, id = first 16 hex chars of
  the key's sha256) stored in `~/.config/veranda/identity.json`
- advertises `_veranda._tcp` over mDNS with a TXT record carrying name, id,
  version and protocol
- serves `/.well-known/agent-card.json` in the A2A agent-card shape
- serves `/healthz` unauthenticated, `/v1/ping` and `/v1/peers` behind a bearer
  token
- `veranda peers` browses the LAN and prints everyone who answered

Not built yet: the pairing handshake, A2A message transport, the MCP adapter,
file transfer. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Try it

```sh
go build -o veranda ./cmd/veranda

# terminal 1
./veranda serve --name laptop

# terminal 2, same machine or another one on the same network
./veranda peers
```

`serve` prints its card URL, its mDNS name and a device token. `peers` should
list it within a second or two — a machine finding itself is the cheapest proof
that discovery works.

## Design in one paragraph

mDNS gives you discovery and nothing else. Anyone on the Wi-Fi can read the
announcement and answer it, so discovery is not authentication. veranda treats
the LAN as a place, not a trust boundary: the announcement is public by design
and every endpoint that returns data requires a token you move out of band once.
[docs/DESIGN.md](docs/DESIGN.md) has the threat model, including what this
deliberately does not defend.

## What it isn't

- not a file transfer tool — LocalSend, Syncthing and croc already do that well;
  veranda should call them, not replace them
- not a tunnel — nothing here is reachable from outside your network, and that
  is a design constraint, not a missing feature
- not a mesh or a VPN
- not an LLM runtime
- not a replacement for A2A or MCP — it is the discovery layer both assume you
  already have

## How it relates to existing work

**A2A** defines how agents talk and how an agent describes itself (the agent
card), but assumes you already know the other agent's URL.
**LAD-A2A** (draft 0.2) standardises exactly the missing piece: finding A2A
agents with mDNS and bootstrapping trust on a local network. veranda implements
towards that spec; where it deviates, DESIGN.md says why.
**MCP** is the tool-call protocol. The planned adapter exposes discovered peers
as MCP tools so an MCP client can call a remote agent it was never configured
with.
**supergateway** solves the neighbouring problem of putting a stdio MCP server
on a network. That is transport. This is discovery.

## Status

Early. v0.1 is a working skeleton: identity, announce, browse, card, token auth.
Interfaces will move. Issues and arguments about the design are welcome.

## Requirements

Go 1.25 or newer. Linux and macOS tested. Windows should work but needs a
working mDNS responder (Bonjour, or the one built into Windows 10+).

## License

MIT
