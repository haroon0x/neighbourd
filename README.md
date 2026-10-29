# neighbourd

Agents on your LAN, meeting without a broker.

Two machines on the same Wi-Fi cannot find each other without being told where
to look. Agent frameworks assume one of two things: the other agent has a public
URL, or a human pasted a host and port into a config file. On a home network
neither is true.

`neighbourd` makes local agents discoverable and then lets them authenticate
each other. Start it on each machine: it announces itself over mDNS, serves an
agent card, and pairs with a one-time code. After pairing, every request carries
a token **and** a signature from that machine's key, so a stolen token is not
enough to impersonate anyone.

No cloud, no broker, no port forwarding.

The name is the thing it does: a daemon that knows its neighbours. Neighbours
talk because they are near each other, not because a server introduced them.

## What works today (v0.2)

- persistent identity per machine: Ed25519 keypair, id = first 16 bytes of the
  key's sha256, stored in `~/.config/neighbourd/identity.json`
- announces `_neighbourd._tcp` over mDNS; `neighbourd peers` prints who answered
- serves `/.well-known/agent-card.json` in the A2A agent-card shape
- one-time pairing codes: 8 characters, single use, 5 minute window, `SIGHUP`
  for a new one
- per-peer tokens plus Ed25519 request signatures, replay protection by nonce,
  clock-skew rejection with a readable error
- `neighbourd trust` lists, and revokes, paired peers

Not built yet: A2A message transport, the MCP adapter, file transfer. See
[docs/ROADMAP.md](docs/ROADMAP.md).

## Try it

```sh
go build -o neighbourd ./cmd/neighbourd
```

On the machine that should accept the pairing:

```sh
$ ./neighbourd serve --name laptop --pair
neighbourd 0.2.0
  name    laptop
  id      18543c1ba8d88db412a420bbd247be09
  card    http://192.168.29.93:7717/.well-known/agent-card.json
  mdns    laptop._neighbourd._tcp.local

pairing open until 10:42:45
  code    TTUP8WBM
  then    neighbourd pair 192.168.29.93:7717 --code TTUP8WBM
```

On the other machine, run the line it printed:

```sh
$ ./neighbourd pair 192.168.29.93:7717 --code TTUP8WBM
paired with laptop (18543c1b)
  address http://192.168.29.93:7717
  reply   {"id":"18543c1b...","name":"laptop","operator":false,...}
```

Then either side can call the other:

```sh
$ ./neighbourd status laptop
```

Pairing is directional. To let each machine call the other, pair twice — once in
each direction, each with its own code.

## Why the signature matters

An mDNS announcement is a claim, not a fact. Anything on the Wi-Fi can announce
any name and any id, and a token can leak from a backup or a screen share.
`neighbourd` therefore requires both:

```
Authorization: Bearer <token issued to you>
X-Neighbourd-Id: <your id>
X-Neighbourd-Ts: <unix seconds>
X-Neighbourd-Nonce: <32 hex chars, unique per request>
X-Neighbourd-Sig: base64(ed25519 over a canonical form of the request)
```

Holding the token gets a caller past the first check and no further. Without the
private key, the signature does not verify. [docs/PROTOCOL.md](docs/PROTOCOL.md)
has the exact bytes signed.

## Design in one paragraph

mDNS gives discovery and nothing else: anyone on the network can read the
announcement and answer it, so discovery is not authentication. `neighbourd`
treats the LAN as a place, not a trust boundary. The announcement is public by
design, the card is public, and everything that returns data needs a token plus
a signature from a pinned key. [docs/DESIGN.md](docs/DESIGN.md) has the threat
model, including what this deliberately does not defend.

## What it isn't

- not a file transfer tool — LocalSend, Syncthing and croc already do that well;
  this should call them, not replace them
- not a tunnel — nothing here is reachable from outside your network, and that
  is a constraint, not a missing feature
- not a mesh or a VPN
- not an LLM runtime
- not a replacement for A2A or MCP — it is the discovery and pairing layer both
  assume you already have

## How it relates to existing work

**A2A** defines how agents talk and how an agent describes itself (the agent
card), but assumes you already know the other agent's URL.
**LAD-A2A** (draft 0.2) standardises the missing piece: finding A2A agents with
mDNS and bootstrapping trust on a local network. `neighbourd` implements towards
that spec; where it deviates, DESIGN.md says why.
**MCP** is the tool-call protocol. The planned adapter exposes discovered peers
as MCP tools so an MCP client can call a remote agent it was never configured
with.
**supergateway** puts a stdio MCP server on a network. That is transport. This is
discovery and identity.

## Status

Early, and honest about it. v0.2 does discovery, pairing, signed requests and
revocation. Interfaces will move. Issues and arguments about the design are
welcome.

## Requirements

Go 1.25 or newer. Linux and macOS tested. Windows should work but needs a
working mDNS responder (Bonjour, or the one in Windows 10+).

## License

MIT
