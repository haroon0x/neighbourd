# Protocol

What goes on the wire. Two implementations have to agree on exactly these bytes,
so this document is the contract.

Protocol id: `neighbourd/0.2`. A node refuses pairing requests that name a
different protocol id rather than guessing.

## Discovery

mDNS, service type `_neighbourd._tcp`, announced on the local multicast group
only. TXT fields:

| key     | meaning                                |
|---------|----------------------------------------|
| `v`     | software version, e.g. `0.2.0`         |
| `id`    | node id, 32 hex chars                  |
| `name`  | human label, not unique, not trusted   |
| `proto` | protocol id, `neighbourd/0.2`          |

The port is in the SRV record, the address in the A record. Never persist an
address: DHCP moves it. Resolve the mDNS name, or re-pair.

## Public endpoints

| path                           | method | body                     |
|--------------------------------|--------|--------------------------|
| `/.well-known/agent-card.json` | GET    | agent card               |
| `/healthz`                     | GET    | `{ok,name,id,time}`      |
| `/v1/pair/request`             | POST   | pairing request          |

These are public on purpose: a peer must be able to read the card and reach the
pairing endpoint before it holds any credential. Nothing private may go in
either.

## Authenticated endpoints

| path           | method | body                                      |
|----------------|--------|-------------------------------------------|
| `/v1/ping`     | GET    | `{id,name,version,you,operator}`          |
| `/v1/identity` | GET    | `{id,name,public_key,version,protocol}`   |
| `/v1/peers`    | GET    | `{network:[...],paired:[...]}`            |

Two ways to be allowed through:

1. **Operator, loopback only.** `Authorization: Bearer <own token>`, source
   address `127.0.0.1` or `::1`. This exists so `curl` on the machine works. It
   is refused from anywhere else, because that token is not per-peer and cannot
   be revoked without regenerating the identity.
2. **Paired peer.** Token plus signature, as below.

## Signed request

Headers:

```
Authorization: Bearer <token this node issued to you>
X-Neighbourd-Id:       <your node id>
X-Neighbourd-Ts:       <unix seconds>
X-Neighbourd-Nonce:    <32 hex chars, never reused>
X-Neighbourd-Sig:      base64(ed25519 signature)
```

The signed message is these six lines joined by `\n`, with **no** trailing
newline:

```
neighbourd/req/v1
<METHOD>
<request target: path plus query string>
<X-Neighbourd-Ts>
<X-Neighbourd-Nonce>
<hex sha256 of the body>
```

`/v1/ping` with no body, timestamp `1793000000`, nonce `ab`, therefore signs:

```
neighbourd/req/v1
GET
/v1/ping
1793000000
ab
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The server checks, in order, and stops at the first failure:

1. the `Authorization` header parses as a bearer token
2. a peer with `X-Neighbourd-Id` is paired
3. the token matches the one issued to that peer, constant time
4. `|now - ts| <= 5 minutes`, otherwise an error naming the skew in seconds
5. the nonce is non-empty and has not been seen before
6. the signature verifies against the key pinned at pairing time
7. only then is the nonce recorded

The nonce is recorded after the signature check so that an unauthenticated flood
cannot fill the cache and lock out real peers.

## Pairing

The responder opens a window: 8 characters from `23456789ABCDEFGHJKMNPQRSTUVWXYZ`,
valid for 5 minutes, single use. `SIGHUP` replaces it and invalidates the old one.

The requester POSTs to `/v1/pair/request`:

```json
{
  "id": "18543c1ba8d88db412a420bbd247be09",
  "name": "laptop",
  "public_key": "<base64 ed25519 public key>",
  "protocol": "neighbourd/0.2"
}
```

with two extra headers: `X-Neighbourd-Pair-Code` and `X-Neighbourd-Sig`, where
the signature covers:

```
neighbourd/pair/v1
<hex sha256 of the body>
```

The responder checks, in this order:

1. a window is open
2. the body parses and names the protocol this node speaks
3. `id` equals `sha256(public_key)[:16]` in hex — an id cannot be claimed for a
   key the caller does not hold
4. the signature verifies against that same `public_key` — the caller proves
   possession before anything is pinned
5. the pairing code is valid; only now is it spent

It replies:

```json
{
  "token": "<64 hex chars, issued for this peer only>",
  "you": {"id": "...", "name": "..."},
  "server": {"id": "...", "name": "...", "public_key": "...", "version": "0.2.0"}
}
```

The requester verifies that `server.id` derives from `server.public_key` before
storing anything. The token in the response is the one issued *to* the requester;
storing it under the server's id is what lets the requester call back.

Pairing is directional. A mutual relationship means two codes and two requests,
one in each direction, and a node keeps both tokens for the same peer id.

## Versioning

`protocol` is compared as an exact string. It tracks the wire format, not the
software version: v0.3.0 of this program still speaks `neighbourd/0.2` because no
message changed shape. A future revision that does change one bumps the id, and
peers that do not match are refused at pairing rather than half-working.
