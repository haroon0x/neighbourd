# neighbourd

Agents on your LAN, meeting without a broker.

Two machines on the same Wi-Fi cannot find each other without being told where to
look. Agent frameworks assume the other agent has a public URL, or that a human
pasted a host and port into a config file. On a home network neither is true.

`neighbourd` is a single binary that fixes that in three commands. Start it on
each machine and it announces itself over mDNS, serves an agent card, and opens a
pairing window. Pair once with an 8-character code. Point your agent at it as an
MCP server, and from then on the agent can call the other machine as a tool — no
URL, no port, no config file to memorise.

After pairing, every request carries a token **and** an Ed25519 signature from
that machine's key, so a stolen token file is not enough to impersonate anyone.

## Setup

Three commands per machine. Build or install first:

```sh
go build -o neighbourd ./cmd/neighbourd     # or: go install github.com/haroon0x/neighbourd/cmd/neighbourd@latest
```

**1. On the machine that should accept the pairing:**

```sh
$ ./neighbourd up --name desktop
neighbourd 0.3.0
  name    desktop
  id      9057a697f366b94868e15e7e08eae73c
  card    http://192.168.29.93:7717/.well-known/agent-card.json
  mdns    desktop._neighbourd._tcp.local
  paired  0

pairing open until 10:59:05
  code    7HAYUNW5
  then    neighbourd pair 192.168.29.93:7717 --code 7HAYUNW5
```

`up` is the whole thing: announce, serve, and wait for a pairing. `SIGHUP` gives
a new code; codes expire after five minutes and work once.

**2. On the other machine, with no arguments:**

```sh
$ ./neighbourd pair
looking for neighbours … 1 found

  1) desktop  192.168.29.93:7717  9057a697

which one? [1]: 1
pairing code on desktop: 7HAYUNW5
paired with desktop (9057a697)
  address http://192.168.29.93:7717
  reply   {"id":"9057a697...","name":"desktop","operator":false,...}
  now     neighbourd status 9057a697
```

It finds the nodes itself, so nothing needs copying except the code. Pairing is
directional: run it on both machines, each with its own code, if both should be
able to call the other.

**3. Wire your agent to it:**

```sh
$ ./neighbourd mcp --print-config
{
  "mcpServers": {
    "neighbourd": {
      "command": "/home/you/go/bin/neighbourd",
      "args": ["mcp"]
    }
  }
}
```

Paste that into your client's MCP config and restart it. The path is this exact
binary, so there is nothing to edit. See [docs/MCP.md](docs/MCP.md) for what the
tools do.

## Calls, not just introductions

`ping` between two nodes is a demo. The point is reaching a service that only
exists on one machine:

```sh
# on the desktop, where Ollama listens on 127.0.0.1:11434 and nowhere else
$ ./neighbourd expose 11434 --as ollama --desc "local model server"
exposing ollama -> http://127.0.0.1:11434

# on the laptop
$ ./neighbourd call dcb1ad2f --resource ollama /api/tags
{"models":[{"name":"qwen2.5:0.5b",...}]}

$ ./neighbourd call dcb1ad2f --resource ollama /api/generate --method POST \
    --body '{"model":"qwen2.5:0.5b","prompt":"hello","stream":false}'
{"model":"qwen2.5:0.5b","response":"Hello! How can I help you today?"}
```

Ollama stays bound to loopback. Nothing new listens on the network. The request
is signed, and the method and full path are inside the signature, so a caller
cannot retarget it. Responses stream, so a model's answer arrives token by token
instead of after the last one.

[docs/EXPOSE.md](docs/EXPOSE.md) covers the rules: loopback-only targets checked
after DNS, caller credentials stripped, traversal refused, no pivot.

## The MCP tools

| tool             | what it does                                                     |
|------------------|------------------------------------------------------------------|
| `list_peers`     | who is on this network and which of them you can call            |
| `peer_card`      | fetch a peer's agent card (public, unverified)                    |
| `peer_resources` | ask a peer what local services it offers                          |
| `call_peer`      | signed request to a peer: its own endpoint, or a service it exposes |
| `my_identity`    | this machine's id and name, which the other side needs to pair   |

`call_peer` accepts `/v1/ping`, `/v1/identity` and `/v1/peers` by default, and
`--allow resource:<name>` for each exposed service. Anything else needs
`--allow /path`: an agent with a valid signature on every machine it can reach is
not a default worth shipping.

## What works today (v0.4)

- persistent identity per machine: Ed25519 keypair, id = first 16 bytes of the
  key's sha256, in `~/.config/neighbourd/identity.json`
- announces `_neighbourd._tcp` over mDNS; container bridges filtered out
- agent card at `/.well-known/agent-card.json`, A2A-shaped
- one-time pairing codes, single use, 5 minute window
- per-peer tokens plus Ed25519 request signatures, nonce replay protection,
  clock skew rejection that names the offset
- MCP server over stdio: peers as tools, no new dependency
- `expose` a loopback service to paired peers, and `call` it from the other
  machine; the service stays on loopback and the caller's credentials are not
  forwarded
- `trust list` / `trust remove`, revocation in both directions

Not built yet: A2A message transport, TLS, file transfer. See
[docs/ROADMAP.md](docs/ROADMAP.md), and the issue list for what is next.

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

Holding the token gets a caller past the first check and no further.
[docs/PROTOCOL.md](docs/PROTOCOL.md) has the exact bytes signed.

## What it isn't

- not a file transfer tool — LocalSend, Syncthing and croc already do that well;
  this should call them, not replace them
- not a tunnel — nothing here is reachable from outside your network, and that is
  a constraint, not a missing feature
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
**MCP** is the tool-call protocol, and this is now an MCP server, so an existing
agent gets the network for free.
**supergateway** puts a stdio MCP server on a network. That is transport. This is
discovery, identity and pairing.

## Status

Early and honest about it. Interfaces will move. Issues and arguments about the
design are welcome.

## Requirements

Go 1.25 or newer to build. Linux and macOS tested. Windows should work but needs
a working mDNS responder (Bonjour, or the one in Windows 10+).

## License

MIT
