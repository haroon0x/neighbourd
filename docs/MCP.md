# MCP

`neighbourd mcp` is a Model Context Protocol server on stdio. It turns paired
machines into tools a model can call.

## Wiring it up

```sh
neighbourd mcp --print-config
```

That prints the block with this binary's absolute path filled in, so there is
nothing to edit:

```json
{
  "mcpServers": {
    "neighbourd": {
      "command": "/home/you/go/bin/neighbourd",
      "args": ["mcp"]
    }
  }
}
```

Hermes keeps the same thing under `mcp_servers:` in `config.yaml`. Claude Code,
Cursor and most other clients take the JSON block above verbatim.

Nothing else is needed: the server reads the same `~/.config/neighbourd/` state
as the CLI, so an agent inherits whatever you have already paired.

## Tools

### `list_peers`

No arguments. Returns two lists:

```json
{
  "me": {"id": "4cda9ed6...", "name": "laptop"},
  "paired": [{"id": "...", "name": "desktop", "can_call": true, "address": "http://192.168.29.93:7717"}],
  "network": [{"id": "...", "name": "desktop", "addr": "192.168.29.93", "port": 7717, "paired": true}]
}
```

`paired` is what you can call. `network` is what mDNS announced in the last two
seconds, including nodes you have never paired with. A node that appears in
`network` but not `paired` needs `neighbourd pair` before it can be called.

### `peer_card`

`{"id": "<peer id>"}`. Fetches `/.well-known/agent-card.json` unauthenticated and
returns it as text. The card is a claim the peer makes about itself; nothing in
it is verified, which is why the tool description says so.

### `call_peer`

`{"id": "<peer id>", "path": "/v1/ping"}`. Makes a signed request and returns the
response body.

Allowlisted paths, and nothing else:

| path           | returns                                    |
|----------------|--------------------------------------------|
| `/v1/ping`     | `{id,name,version,you,operator}`            |
| `/v1/identity` | `{id,name,public_key,version,protocol}`     |
| `/v1/peers`    | `{network:[...],paired:[...]}`              |

Extend with `--allow /v1/whatever` when starting the server, repeated per path.
Query strings are allowed if the base path is allowlisted; traversal is not.

Every call is signed with this machine's key, so the far side sees the request as
coming from a paired peer or refuses it.

### `my_identity`

No arguments. This machine's id, name, version and protocol. This is what the
other machine needs in order to pair with you.

## Failure messages the model will see

Tool failures come back as `isError: true` with text, not protocol errors, so the
model can act on them:

| message | what to do |
|---|---|
| `no paired peer named "x"` | run `list_peers`, or pair first |
| `not paired with desktop (...); run: neighbourd pair <host:port>` | pair, then retry |
| `/v1/x is not in the allowlist (allowed: ...)` | restart `mcp` with `--allow /v1/x` |
| `desktop (...) has no recorded address; pair again with a host:port` | the stored address is stale, re-pair |
| `... replied 401: token does not match...` | the peer revoked you, or state was copied between machines; re-pair |

## Security notes

- The MCP server holds the private key, so treat the client config as
  sensitive: anything that can start this process can act as this machine.
- `call_peer` is deliberately narrow. Widening `--allow` hands the model the
  ability to make signed requests to that path on every paired peer.
- The server speaks on stdout only. Diagnostics go to stderr, which clients
  usually show in their logs.
- Nothing here is encrypted in transit; signatures stop impersonation and replay,
  not interception. See [../SECURITY.md](../SECURITY.md).
