# Design

This document explains what veranda is for, what it refuses to do, and why the
parts look the way they do. It is the file to argue with.

## 1. The problem, split correctly

Three layers get conflated in most "my agents should talk" discussions, and they
have very different maturity:

1. **Transport** — moving bytes between two hosts on a LAN. Solved. HTTP over
   TCP, done.
2. **Discovery** — learning that a peer exists and where to reach it. Not
   solved. Every framework expects a URL from configuration.
3. **Identity** — deciding whether to talk to it. Half-solved on the internet
   (DNS + TLS + OAuth), essentially unsolved at LAN scale, where the only
   signal available is "it is on the same wire".

veranda owns 2 and bootstraps 3. It deliberately does not touch 1.

## 2. Constraints

These decide everything else. Change one and the design changes.

- **LAN only.** The moment this works across the internet it is a different
  product with a different threat model. Nothing here should ever be
  port-forwarded, and the code should not make that easy.
- **No broker.** A central daemon is a single point of failure, a config file
  and a machine that has to stay awake. At two to four devices, peer-to-peer is
  both simpler and more robust. A hub starts paying off around five or when you
  want shared history.
- **Zero configuration on first run.** Any required setup step is a step that
  will not happen on the second machine.
- **One static binary per OS.** The real reason is deployment: copying a Go
  binary beats installing a runtime on a laptop you do not want to pollute.
- **The LAN is not trusted.** Guest Wi-Fi, phones, IoT devices, a router with a
  weak admin password. Discovery is public; data is not.
- **No invented crypto.** Ed25519, `crypto/rand` tokens, constant-time compare.
  No custom handshake, no custom KDF, no rolling your own.

## 3. Components

```
cmd/veranda            subcommands: serve, peers, version
internal/identity      keypair, stable id, device token, on-disk state
internal/card          the agent card served at a well-known path
internal/discovery     mDNS announce + browse
internal/server        HTTP: routes, bearer auth, handlers
```

The MCP adapter is a future component and is not in this tree yet.

## 4. Wire format

### Discovery

Service type `_veranda._tcp`, announce on the local multicast group only.

TXT fields:

| key   | meaning                                    |
|-------|--------------------------------------------|
| `v`   | veranda version, e.g. `0.1.0`              |
| `id`  | stable device id, 32 hex chars             |
| `name`| human label, not unique, not trusted       |
| `proto` | protocol id, `veranda/0.1`               |

The port comes from the SRV record. The address comes from the A/AAAA record,
which is why callers must use whatever mDNS resolved rather than a cached IP —
DHCP will move it.

### Endpoints

| path | auth | body |
|------|------|------|
| `/.well-known/agent-card.json` | none | agent card |
| `/healthz` | none | `{"ok":true,"name":...,"time":...}` |
| `/v1/ping` | bearer | `{"id":...,"name":...}` |
| `/v1/peers` | bearer | array of peers this node can see |

Public endpoints are public on purpose: a peer has to be able to read your card
before it has a token. Nothing private goes in a card.

### Card

A2A-shaped, with veranda's own fields nested so the two can drift independently.
It is deliberately boring: name, id, version, protocol, endpoints, capabilities.
The card is a claim about yourself that nobody has verified — treating it as a
statement of fact is the mistake the threat model exists to prevent.

## 5. Trust model

**What mDNS proves: nothing.** Any device on the network can announce any name,
any id, any service type. Spoofing an existing peer's announcement is a few
lines of code. Discovery gives you a candidate, not a peer.

**What the bearer token proves: the caller has the token.** Not that the caller
is the machine you think. Tokens are per-peer, moved out of band once (copy,
paste, QR later), and stored `0600`.

So the honest summary: veranda turns "there is something on my network" into
"there is something on my network that also knows the token I gave it". That is
a real improvement over hardcoded IPs with no auth, and it is not authentication
of identity. v0.2 closes the gap below.

**Not defended, by design or by omission:**

- active man-in-the-middle on plain HTTP between two peers
- mDNS cache poisoning, or a rogue responder answering before the real one
- denial of service: anything on the LAN can flood or impersonate
- a compromised host that legitimately holds a token
- anyone who can read the token on disk

**v0.2 direction:** a pairing handshake that binds the issued token to the peer's
Ed25519 public key, so an impersonated announcement cannot collect a token meant
for someone else. The keypair already exists in v0.1 and is unused, which is why.

**IPv6:** `bind` defaults to `0.0.0.0`, IPv4 only. Many ISPs hand out globally
routable IPv6 prefixes, and a router that does not filter inbound v6 makes `::`
internet-facing. Opting into v6 is explicit, and should come with a firewall
rule. This is the single most likely way to accidentally expose this tool.

## 6. Failure modes to expect

- **AP client isolation** — many guest SSIDs and some ISP routers block
  client-to-client traffic. Nothing on the LAN can reach anything. Not fixable
  in software; the browse output will just be empty.
- **Split bands** — a device on the 2.4GHz guest network and one on 5GHz may not
  be on the same broadcast domain.
- **DHCP churn** — never persist an IP. Always resolve the mDNS name.
- **Sleep** — a laptop that suspends stops answering. Peers should treat
  absence as normal, not as an error.
- **Two responders on 5353** — avahi, Bonjour and veranda can coexist on Linux
  and macOS via SO_REUSEADDR, but a host running several mDNS stacks is worth
  checking when discovery misbehaves.

## 7. Why Go

The static binary constraint is most of it: one file to copy to the second
machine, no runtime, no venv, no `npm install`. `net/http` and the standard
library cover everything except mDNS, and `hashicorp/mdns` is maintained and
small. Rust would be an equally good choice. Python and Node fail the "copy one
file and it runs" test, which is the test that matters here.

## 8. Deliberately deferred

| thing | why not now |
|-------|-------------|
| A2A message transport | A2A already defines it. Wrap the spec, do not reimplement it. |
| file transfer | LocalSend publishes its REST protocol; call it rather than inventing a third one. |
| MCP adapter | Thin layer over `/v1/*`. Matters only once peers exist. |
| phone support | A phone will not run this. Its role is a browser client or a LocalSend endpoint. |
| TLS | Worth doing, but a self-signed cert on a LAN without pinning is security theatre. Pairing first, then pinning. |
