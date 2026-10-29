# Design

What this is for, what it refuses to do, and why the parts look the way they do.
This is the file to argue with.

## 1. The problem, split correctly

Three layers get conflated in most "my agents should talk" discussions, and they
have very different maturity:

1. **Transport** — moving bytes between two hosts on a LAN. Solved. HTTP over
   TCP, done.
2. **Discovery** — learning that a peer exists and where to reach it. Not solved.
   Every framework expects a URL from configuration.
3. **Identity** — deciding whether to talk to it. Half-solved on the internet
   (DNS + TLS + OAuth), essentially unsolved at LAN scale, where the only signal
   available for free is "it is on the same wire".

`neighbourd` owns 2 and bootstraps 3. It deliberately does not touch 1.

## 2. Constraints

These decide everything else. Change one and the design changes.

- **LAN only.** The moment this works across the internet it is a different
  product with a different threat model. Nothing here should ever be
  port-forwarded, and the code should not make that easy.
- **No broker.** A central daemon is a single point of failure, a config file and
  a machine that has to stay awake. At two to four devices, peer-to-peer is
  simpler and more robust. A hub starts paying off around five, or when you want
  shared history.
- **Zero configuration on first run.** Any required setup step is a step that
  will not happen on the second machine.
- **One static binary per OS.** The real reason is deployment: copying a Go
  binary beats installing a runtime on a laptop you do not want to pollute.
- **The LAN is not trusted.** Guest Wi-Fi, phones, IoT devices, a router with a
  weak admin password. The announcement is public; data is not.
- **No invented crypto.** Ed25519, `crypto/rand`, constant-time compare, sha256.
  No custom handshake, no custom KDF.

## 3. Components

```
cmd/neighbourd        subcommands: serve, peers, pair, status, trust, version
internal/identity     keypair, stable id, operator token, signing
internal/trust        paired peers, two credential slots per peer, atomic writes
internal/pair         one-time codes: generate, normalise, redeem, reopen
internal/proto        header names, canonical signing forms, protocol id
internal/client       signed requests and the pairing client
internal/discovery    mDNS announce + browse, interface filtering
internal/server       HTTP routes, authorisation, pairing handler
```

The MCP adapter (v0.3) is not in this tree yet.

## 4. Trust model

**What mDNS proves: nothing.** Any device on the network can announce any name,
any id, any service type. Spoofing an existing peer's announcement is a few lines
of code. Discovery gives you a candidate, not a peer.

**v0.1 was "a shared token means access".** That had two holes: the token was not
per-peer (one leak, whole machine) and possession of the token was the entire
check, so copying the file was enough to impersonate.

**v0.2 closes both.** Pairing issues a per-peer token *and* pins the peer's
Ed25519 key, proven at pairing time by a self-signature. Every authenticated
request must then carry a signature over the method, target, timestamp, nonce and
body hash. Consequences:

- a stolen `peers.json` yields no access: the tokens are useless without the
  matching private keys
- a stolen `identity.json` yields no access to peers: your outbound tokens are
  not in it, and peers pin keys, not just tokens
- a spoofed announcement cannot collect a token: the pairing handler verifies the
  self-signature before pinning, and only then spends the code
- replay is refused: nonces are recorded after the signature verifies, and
  timestamps outside a five minute window are rejected with the skew in seconds

**Still not defended**, by design or by omission:

- an active man-in-the-middle during pairing itself: the code travels over plain
  HTTP. Someone already on the network, watching at that moment, can read it.
  Pair over a network you trust, and pair rarely.
- traffic analysis and content exposure after pairing: bodies are signed, not
  encrypted. Anyone on the LAN can read the JSON in flight.
- denial of service: anything on the LAN can flood or impersonate.
- a compromised host that legitimately holds keys and tokens.
- mDNS cache poisoning, or a rogue responder answering first.

**Next step, v0.4:** TLS with certificate pinning, which only becomes meaningful
once keys are pinned, and is why pairing came first.

**IPv6:** `--bind` defaults to `0.0.0.0`, IPv4 only. Many ISPs hand out globally
routable IPv6 prefixes, and a router that does not filter inbound v6 makes `::`
internet-facing. Opting into v6 is explicit and should come with a firewall rule.
This is the single most likely way to expose this tool by accident.

## 5. Two processes, one file

`serve` holds the peer store for the life of the daemon, while `pair`, `status`
and `trust remove` mutate it from the shell. A store loaded once and flushed
later silently discards whatever the other process wrote in between — which is
exactly how the first implementation lost a pairing on one side of a mutual
relationship.

The store therefore re-reads the file when its mtime or size changes, on every
access, and writes through a temp file plus `rename` so a crash leaves the old
file intact rather than a truncated one. Two writers at the same instant are
still last-writer-wins; the window is microseconds and the failure mode is
re-pairing, not a security hole. A lock file would close it and is not worth the
portability cost yet.

## 6. Wire format

See [PROTOCOL.md](PROTOCOL.md). The canonical signing strings are covered by
golden tests, so the document and the code cannot drift apart silently.

## 7. Why Go

The static binary constraint is most of it: one file to copy to the second
machine, no runtime, no venv, no `npm install`. `net/http`, `crypto/ed25519` and
`encoding/json` cover everything except mDNS, and `hashicorp/mdns` is maintained
and small. Rust would be an equally good choice. Python and Node fail the "copy
one file and it runs" test, which is the test that matters here.

## 8. Failure modes to expect

- **AP client isolation** — many guest SSIDs and some ISP routers block
  client-to-client traffic. Nothing on the LAN reaches anything. Not fixable in
  software; browse output is just empty.
- **Split bands** — a device on the 2.4GHz guest network and one on 5GHz may not
  share a broadcast domain.
- **DHCP churn** — never persist an address. The `base_url` in a peer record is a
  hint, not a fact.
- **Sleep** — a suspended laptop stops answering. Absence is normal.
- **Clock drift** — signed requests fail with a skew message if the two machines
  disagree by more than five minutes. That is the intended behaviour: a loose
  window would widen the replay surface.
- **Several mDNS responders on 5353** — avahi, Bonjour and this can coexist on
  Linux and macOS. Worth checking when discovery misbehaves.

## 9. Deliberately deferred

| thing | why not now |
|-------|-------------|
| A2A message transport | A2A already defines it. Wrap the spec, do not reimplement. |
| file transfer | LocalSend publishes its REST protocol; call it rather than inventing a third one. |
| MCP adapter | Thin layer over `/v1/*`. Matters once peers can actually be called. |
| phone support | A phone will not run this. Its role is a browser client or a LocalSend endpoint. |
| TLS | Meaningful only with pinning, which needs pairing to exist first. |
