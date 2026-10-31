# aqt-egress

**The outbound checkpoint for AI coding agents: everything the agent sends leaves its box through one proxy, and every request is recorded with the process that sent it.**

Part of the [Agent Quality Toolkit](../) (AQT). Python ≥ 3.12, Linux, Apache-2.0. Optional: nothing changes for you unless you start a session with `aqt egress run`.

This is the first stage: **observe and record**. Nothing is blocked, held or changed. Checks against the task, scanners and holds come in later stages.

## The problem

A coding agent can send what it reads to any host it can reach: in a `curl` it writes itself, in a package script, or in a tool call it was talked into. Sandboxes of agent harnesses usually say at most *which host* was contacted. Afterwards nobody can show *which program* sent *what*, or whether it fitted the task.

`aqt-egress` runs the agent in a box whose only way out is a proxy you control. Each request goes into the AQT audit trail with:
- the process chain inside the box that sent it (for example `curl < bash < claude`);
- the destination as asked, the address it went to, the protocol and TLS mode;
- method, path, header names, sizes, body hashes and short masked excerpts (credentials only as fingerprints).

## 60-second quick start

```bash
uv pip install -e ../aqt-spec -e .        # Python 3.12+; needs bubblewrap (bwrap)
aqt egress run -- claude                   # any command: the agent, a shell, a build ...
aqt egress report                          # who talked to whom, per session
aqt egress status                          # box support, CA, last session
```

`aqt egress …` and `aqt-egress …` are the same command. With the umbrella package: `agent-quality-toolkit[egress]`.

Records go where all AQT records go (`aqt_evidence.open_sink()`): to the aqt-trail writer when it runs, otherwise to its spool or the fallback file. `aqt-trail verify` checks them like any other record.

## How it works

1. **The box.** bubblewrap with its own user, network, PID and IPC namespaces, `--disable-userns` (no `unshare` inside) and `--die-with-parent`. The command starts only after the network is ready (`--block-fd`).
2. **The listener.** The proxy on the host enters the box's network namespace (the user owns it, no privileges needed), opens its listening sockets there and leaves again. No relay process runs inside the box. mitmproxy serves these sockets in the `aqt egress run` process.
3. **What the agent sees.** `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (and the lower-case forms) point at `127.0.0.1:3128` inside the box. A private CA, created once, is trusted through `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `PIP_CERT`, `NODE_EXTRA_CA_CERTS` and a combined system bundle. Its key is not visible inside the box.
4. **Name lookups.** The box's resolver answers every name with the listener's address and records it. Names are resolved upstream only by the proxy. A client that ignores the proxy variables still reaches ports 80 and 443 this way; the proxy takes the destination from the TLS server name or the Host header.
5. **Everything else.** Where nftables works in the box's namespace (verified on Ubuntu, kernel 7.0), every other TCP connection is redirected to the proxy too (original destination from the kernel), UDP DNS queries to any server are answered by the box resolver, and all other traffic to outside addresses is dropped. Without nftables those connections fail. See [docs/box.md](docs/box.md).
6. **Attribution.** For each connection the proxy finds the client socket in the box's `/proc/net/tcp` and the box process holding it, then walks the parents up to the command you started. `chain_status` (`complete`, `partial`, `unavailable`) says how far that evidence goes, as in aqt-trail.
7. **Streaming.** Bodies stream through: hashed, counted and (in full mode) spooled as they pass. A streamed LLM response reaches the agent chunk by chunk.

**Files stay as they are**, so the agent keeps its configuration and your project. The exceptions:
- `/run` is empty: the host's service sockets (D-Bus, systemd, systemd-resolved, docker, libvirt, your runtime folder) are not reachable; the trail writer's socket is put back read-only.
- Hidden: the egress state (CA key, body store, fingerprint key), the quarantine state, the X11 and tmux socket folders in `/tmp`.
- Read-only: the AQT configuration and state folders (the spool folder stays writable).

## Records

| Type | Action | What it holds |
|---|---|---|
| `egress.session` | `started`, `ended` | session ID, command (masked), project and its `require`, mode `observe`, store, excerpt length, retention, CA fingerprint, box facts (bwrap version, kernel, network setup, hidden and read-only folders), policy version `none`; at the end the exit code, counts and duration |
| `egress.request` | `observed` | one per HTTP request, WebSocket or TCP connection: process chain, destination (`host` as asked, `ip`, `port`, `sni`, `via` = `proxy`, `redirect`, `direct80`, `direct443`), protocol, TLS mode (`intercepted`, `passthrough` with the reason, `none`), method, path (masked), query as a hash, header names, credential headers as fingerprints, sizes and body hashes, status, timing, masked excerpts, the lookups that led to it, `mode: observe`, `decision: allowed` (or `refused` with `reason_code: host-loopback`, see below), and in full mode the body-store references |
| `egress.lookup` | `observed` | names the box resolver answered without a request following: name, query types, count, process |
| `egress.pruned` | `pruned` | what `aqt egress prune` deleted: count, bytes, retention, cutoff |

Credential headers (`Authorization`, `Cookie`, API-key headers …) are never recorded with their value: only the scheme and an HMAC-SHA256 fingerprint keyed per installation, so the same key gives the same fingerprint across sessions without being guessable from the trail. Paths, excerpts, command lines and stored bodies go through a masking pass for common credential shapes (bearer tokens, provider API keys, JWTs, private keys, `password=` pairs). That pass is a guard for the record, not a leak detector.

## Storage modes and settings

`$XDG_CONFIG_HOME/aqt/egress.toml`; flags override for one session (`--store`, `--excerpt-chars`):

```toml
store = "excerpt"        # default; "full" also keeps headers and bodies
retention_days = 90      # full bodies: 7 or more, or "forever"
excerpt_chars = 512      # masked excerpt length in the records (0 to 4096)
passthrough = []         # hosts whose TLS is passed through unread (clients that pin certificates)
```

- **excerpt** keeps hashes, sizes and short masked excerpts in the records.
- **full** also keeps request and response headers and bodies in a content-addressed store under `$XDG_STATE_HOME/aqt/egress/bodies/` (folders 0700, files 0600, gzip). Text bodies are decoded and masked before they are stored. The record references each object by its hash, so a changed or deleted body is detected. Full mode keeps whole conversations with your LLM provider: turn it on deliberately.
- `aqt egress prune [--retention-days N|forever] [--dry-run]` deletes stored objects not used within the retention period and writes an `egress.pruned` record.

A project can commit `.aqt/egress.toml` with `require = true`. The session record carries it; a later `aqt project status` check will warn about agent sessions that ran outside the box.

A client that rejects the private CA (certificate pinning) fails once; the host is then passed through unread for the rest of the session and recorded as `passthrough` (`client-rejected-certificate`). List such hosts under `passthrough` to pass them through from the start.

## Threat model and limits

What it gives you:
- Every connection that leaves the box goes through the proxy and is recorded with the sending process; direct connections to IP addresses on any port and DNS queries to outside resolvers are caught as well (where nftables works).
- The box cannot create user namespaces, change its firewall, see or signal the proxy, or read the CA key and the body store.
- The proxy never connects to the host's own loopback addresses for the box (such requests are refused and recorded): the box's `localhost` is its own.

What it does **not** do:
- **Block anything.** This stage observes. Holding what the task does not explain is a later stage.
- **Make the LLM channel safe.** Your LLM provider receives the whole context by design; a record shows only that it went there, how much, and under which key.
- **Close allowed channels.** Data can ride on traffic that looks normal (a git push to your own remote, a request to a registry). Timing channels and data hidden inside normal requests are not reliably detectable.
- **Read pinned TLS.** Passed-through connections are recorded by host, size and time only.
- **Contain what is not network.** Files stay writable: something in the box can leave a script that runs later outside it (a shell profile, a git hook). Unix sockets outside `/run` and the hidden folders (for example an editor's IPC socket in `/tmp`, an agent socket in your home) stay reachable and may act outside the box. `--die-with-parent` ends the box with the proxy, but it does not undo what was written.
- **Watch agents that are not in the box.** It protects only what runs inside `aqt egress run`.
- **Attribute every byte.** Attribution is read from `/proc` when the connection arrives; a process that exits at once or hands its socket on can leave the chain `partial` or `unavailable`.

## Regulatory status

> Agent Quality Toolkit supports quality-management practices; it is not a validated system and does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.

## Licence

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Uses mitmproxy (MIT); runs bubblewrap, nftables and iproute2 as external programs.
