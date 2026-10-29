# Security

## Scope

Runs on a network you control, assumes the neighbours are not friendly.
Discovery is public. Anything returning data needs a token and a signature.

## What v0.2 guarantees

- the announcement is public by design: any device on the LAN can see the name,
  id and version of every node
- `/v1/*` requires `Authorization: Bearer <token>` **and** an Ed25519 signature
  from a key pinned at pairing time
- a request cannot be replayed: nonces are recorded, timestamps outside a five
  minute window are refused
- a pairing request must be signed with the key it registers, and its id must
  derive from that key, so an id cannot be claimed for a key the caller does not
  hold
- pairing codes are single use, 8 characters from a 31 symbol alphabet, and
  expire after five minutes
- the operator token is accepted only from a loopback source address
- `identity.json` and `peers.json` are `0600`, written atomically

## The proxy (v0.4)

Exposing a local service adds an attack surface, and it is deliberate. What is
enforced:

- a request reaches an exposed origin only after the caller proves it holds a
  pinned key and a valid token, exactly like every other protected endpoint
- the method and the whole forwarded path are inside the signature, so a caller
  cannot retarget a request to another resource or another path
- the destination must be loopback, checked after DNS resolution, so a paired
  peer cannot use this node as a pivot into the rest of the network
- `Authorization`, `Cookie` and `X-Neighbourd-*` are stripped before forwarding,
  so a peer cannot smuggle credentials into a local service that trusts loopback
- bodies are capped at 8 MB, and path traversal is refused
- the request is bounded by the caller's context; there is no unbounded work
  started on behalf of a peer

What it does not do: encrypt, rate limit, restrict paths within an origin, or log
usage. A paired peer you have granted a resource can call every endpoint of that
service as fast as it likes, including destructive ones. Grant narrowly, and
revoke with `trust remove`.

## What it does not guarantee

- **Pairing over an untrusted network.** The pairing code travels in plain HTTP.
  Anyone already on the network and watching at that moment can read it and race
  you. Pair on a network you trust, and pair rarely.
- **Confidentiality of traffic.** Bodies are signed, not encrypted. Anyone on the
  LAN can read the JSON in flight. TLS with pinning is a v0.4 item.
- **Availability.** Anything on the LAN can flood or impersonate a node. There is
  no rate limiting.
- **A compromised host.** If the machine itself is owned, its keys and tokens are
  owned.

## Known weaknesses worth naming

- mDNS is unauthenticated: an attacker can announce a name that looks like a peer
  you already have. Nothing prevents a confusing duplicate; the id in the TXT
  record is what you should compare, and `trust list` is the authority.
- Two processes writing `peers.json` at the exact same moment: last writer wins.
  The failure mode is a lost pairing, not a lost check.
- No certificate story yet, so there is no defence against an active
  man-in-the-middle *after* pairing either. Signatures stop impersonation and
  replay; they do not stop interception.

## Please never

- port-forward it
- bind it to a globally routable IPv6 address without a firewall rule in front
- pair over public Wi-Fi and assume the code was not seen
- treat a card, a name or an mDNS announcement as evidence of identity

## Reporting

Open an issue for anything that fits the list above — those are known and
documented, not surprises. For something that defeats the signature check,
escapes the loopback restriction on the operator token, or leaks state outside
`~/.config/neighbourd/`, mail the address on the GitHub profile instead of filing
publicly.
