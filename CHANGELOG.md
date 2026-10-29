# Changelog

## v0.2.0

Pairing, and requests that need more than a token.

- Added: one-time pairing codes (`serve --pair`, `pair`, `SIGHUP` for a new one),
  single use, 5 minute window, 8 characters, no look-alike symbols.
- Added: pairing requires a self-signature over the request body and an id that
  derives from the submitted public key, so a key must be held to be pinned.
- Added: per-peer tokens. One leaked token costs one relationship, not the
  machine.
- Added: Ed25519 signature over method, path, timestamp, nonce and body hash on
  every authenticated request.
- Added: replay protection by nonce cache, fail-closed at capacity.
- Added: clock skew rejection naming the offset in seconds.
- Added: `status` makes a signed call and prints the answer; `pair` proves the
  pairing with a signed request before reporting success.
- Added: `trust list` and `trust remove`, revoking both directions.
- Added: `docs/PROTOCOL.md` with the exact canonical bytes signed, plus golden
  tests so the document and the code cannot drift.
- Changed: the operator token is refused unless the request comes from loopback.
- Changed: peer records carry two credential slots, because pairing is
  directional and one slot let one direction overwrite the other.
- Fixed: the peer store re-reads on change and writes atomically, so a running
  daemon no longer flushes a stale map over a pairing made from the shell.
- Fixed: `pair host --code CODE` works in that order; `flag` stopped parsing at
  the first positional argument and silently ignored the code.
- Fixed: mDNS no longer announces container bridges; Docker's `172.x` address was
  being reported as the peer address.

## v0.1.0

First working skeleton.

- Ed25519 identity, stable id derived from the public key.
- mDNS announce of `_neighbourd._tcp` with a TXT record; browse and print.
- Agent card at `/.well-known/agent-card.json`, A2A-shaped.
- Bearer token on `/v1/*`, constant-time compare.
