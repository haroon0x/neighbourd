# Security

## Scope

veranda runs on a network you control and assumes the neighbours are not
friendly. Discovery is public. Anything that returns data needs a token.

## What v0.1 actually guarantees

- the announcement is public, and is meant to be: any device on the LAN can see
  the name, id and version of every veranda node
- `/v1/*` returns nothing without a bearer token; the comparison is constant
  time
- the token and private key are stored `0600` in `~/.config/veranda/`

That is all. It is not authentication of identity.

## Known weaknesses

- No pairing yet. A token is just a shared secret; whoever holds it is trusted.
- Plain HTTP. An active attacker on the LAN can read and modify traffic between
  two peers, including the token.
- mDNS is unauthenticated. Anyone can announce any id or name.
- No rate limiting. Anything on the LAN can flood a node.

## Please never

- port-forward it
- bind it to a globally routable IPv6 address without a firewall rule in front
- put it on a network with devices you do not trust, expecting the token to save
  you

## Reporting

Open an issue for anything that fits the weaknesses above — they are known and
documented, not surprises. For something that breaks the token check, escapes
the bind address, or leaks state outside `~/.config/veranda/`, mail the address
on the GitHub profile instead of filing publicly.
