# Changelog

## Unreleased

First slice of the outbound checkpoint: observe and record (nothing is blocked).

- `aqt egress run [--project DIR] [--store excerpt|full] [--excerpt-chars N] -- COMMAND`: the command runs in
  a bubblewrap box (own user, network, PID and IPC namespaces, `--disable-userns`) whose only way out is the
  proxy. The proxy (mitmproxy in the launcher) opens its listeners inside the box's network namespace; no relay
  runs in the box. nftables in the box redirects every other TCP connection and every UDP DNS query, and drops
  the rest; without nftables those connections fail.
- Box resolver: every name is answered with the listener's address and recorded; names are resolved only by
  the proxy. Proxy-unaware clients reach ports 80/443 (destination from the TLS server name or Host header).
- Private CA (mitmproxy's files, 0600, hidden in the box) trusted through the usual variables and a combined
  bundle; per-session TLS pass-through for clients that reject it, and a `passthrough` host list.
- Attribution: the client socket in the box's `/proc/net/tcp`, its owner and the parent chain, with
  `chain_status` as in aqt-trail.
- Records (aqt-spec registry): `egress.session`, `egress.request`, `egress.lookup`, `egress.pruned`; through
  sink discovery to the trail writer. Credential headers only as keyed fingerprints; masked excerpts.
- `store = full`: masked headers and bodies in a content-addressed, gzip-compressed store; bodies stream through
  and are stored as they pass. `aqt egress prune` with a retention of 7 days to `forever` (default 90).
- `aqt egress report [--session] [--since] [--json]` and `aqt egress status`.
- The proxy refuses to connect to the host's own loopback for the box (recorded as `refused`, `host-loopback`).
