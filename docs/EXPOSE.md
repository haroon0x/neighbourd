# Exposing a local service

This is the reason the rest of the project exists. Everything before it was
machines introducing themselves; this is the first thing one machine can actually
*do* for another.

## The problem

A useful service lives on loopback. Ollama, a local vector store, a job runner, a
build cache. It listens on `127.0.0.1` because the alternative — binding it to
`0.0.0.0` — puts an unauthenticated API on a Wi-Fi shared with phones, guests and
whatever the printer is running. On this machine, before anything is exposed:

```sh
$ ss -tln | grep 11434
LISTEN 0 4096 127.0.0.1:11434 0.0.0.0:*

$ curl http://192.168.29.93:11434/api/tags
curl: (7) Failed to connect
```

So the choices are: usable by nothing, or usable by every device on the network
with no idea who is asking. `neighbourd` adds the third: usable by peers you
paired with, with a key you pinned, and by nobody else.

## Exposing

```sh
$ neighbourd expose 11434 --as ollama --desc "local model server"
exposing ollama -> http://127.0.0.1:11434
  store   ~/.config/neighbourd/exposures.json
  running daemon picks this up without a restart
  a peer calls it with: neighbourd call dcb1ad2f --resource ollama /api/tags
```

The service is not restarted, not rebound, and not touched. `neighbourd` only
records where it is. A running daemon reads the file on change, so there is no
restart on this side either.

Shorthands: `11434`, `127.0.0.1:11434` and `http://127.0.0.1:11434` all mean the
same thing. `--as` defaults to `port-<port>` if you leave it out, which is the
name you will regret in a month, so pass one.

```sh
$ neighbourd expose list
NAME    ORIGIN                  DESCRIPTION
ollama  http://127.0.0.1:11434  local model server

$ neighbourd expose remove ollama
stopped exposing ollama
```

Removal is immediate for new requests. It does not wait for a timeout.

## Calling it from the other machine

```sh
$ neighbourd call dcb1ad2f --resource ollama /api/tags
{"models":[{"name":"qwen2.5:0.5b",...}]}

$ neighbourd call dcb1ad2f --resource ollama /api/generate --method POST \
    --body '{"model":"qwen2.5:0.5b","prompt":"hello","stream":false}'
{"model":"qwen2.5:0.5b","response":"Hello! How can I help you today?..."}
```

Real output, from a model answering on a machine whose Ollama is still bound to
`127.0.0.1`. The response came through a signed request, not through an open port.

From an agent, through MCP:

```
list_peers                              -> who is reachable
peer_resources {"id": "dcb1ad2f"}       -> [{"name":"ollama","description":"local model server"}]
call_peer {"id":"dcb1ad2f","resource":"ollama","path":"/api/tags"}
```

`call_peer` needs `--allow resource:ollama` at MCP startup. The allowlist is per
resource name, so granting one service does not grant the rest. An agent that
has not been granted a resource gets an error naming the flag, not a silent 403.

## What the far side sees

The request is a normal signed request. The method and the full path, including
the resource name, are inside the signature:

```
neighbourd/req/v1
POST
/v1/proxy/ollama/api/generate
1793000000
9f2c1a...
<sha256 of body>
```

A caller cannot change `ollama` to another resource, or `/api/tags` to
`/api/delete`, without invalidating the signature. There is no "forward this
somewhere" parameter to abuse.

## Rules the proxy enforces

**Loopback targets only, checked after DNS.** The dialer resolves the host and
refuses any address that is not loopback. This is what stops a paired peer from
using your machine as a pivot to reach a database or a router admin page on the
same network. `--allow-remote` exists (`expose --allow-remote`, `serve
--allow-remote`), it is not the default, and if you turn it on, you have built a
proxy into your network and should know it.

**Caller credentials are stripped.** `Authorization`, `Cookie`, `X-Neighbourd-*`
and other connection-scoped headers are not forwarded. Only `Content-Type`,
`Accept`, `Cache-Control` and `User-Agent` pass through. A peer must not be able
to smuggle an auth header into a local service that trusts whatever arrives from
loopback, and a local service must not see your peer's token.

**Path traversal is refused** before the request is built. Defence in depth: the
dial guard already pins the destination.

**Bodies are capped at 8 MB.** Local APIs take JSON, not uploads.

**Responses stream.** The proxy flushes each chunk, so a token-by-token model
answer arrives as it is generated rather than after the last token. There is
deliberately no `WriteTimeout` on the server for this reason.

## What it does not do

- No TLS. Bodies are signed, not encrypted. Someone capturing traffic on the
  Wi-Fi sees the prompt and the answer. Known limitation, issue #3.
- No per-path restriction inside an exposed origin. Exposing `ollama` exposes
  every endpoint Ollama has, including the ones that delete models. Issue #10.
- No usage log. You cannot see who called what and when. Issue #11.
- No rate limiting. A paired peer can hammer your model as hard as it likes.

The first three are the honest cost of shipping this in an afternoon. They are
listed in the issue tracker rather than in a footnote because they matter.
