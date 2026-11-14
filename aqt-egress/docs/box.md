# The box: what was verified, and the fallbacks

Verified on Ubuntu 24.04 with Linux 7.0, bubblewrap 0.9.0 (not setuid), nftables and iproute2, with Ubuntu's
AppArmor restriction of unprivileged user namespaces switched on (`kernel.apparmor_restrict_unprivileged_userns = 1`).
Under that restriction bubblewrap needs an AppArmor profile that allows user namespaces; Ubuntu 24.04 ships none for
`/usr/bin/bwrap`, so without one the box fails with `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`.
The profile (two commands) is in the [manual, 6.4](../../docs/manual.md#64-sandbox-validation-and-capa). The box
tests in `tests/test_box.py` repeat these checks on every run and skip themselves where bubblewrap or user
namespaces are missing.

## How the box starts

1. `bwrap --unshare-user --unshare-net --unshare-pid --unshare-ipc --disable-userns --die-with-parent
   --info-fd N --block-fd M … -- COMMAND`. bubblewrap writes the box's first process to the info pipe and waits
   on the block pipe before it starts the command.
2. The launcher opens `/proc/<first process>/ns/net` and asks the kernel for the user namespace that owns it
   (`ioctl(NS_GET_USERNS)`).
3. A short-lived helper (`python -m aqt_egress.netns`) joins that user namespace and then the network namespace,
   sets the network up, creates the listening sockets, sends them to the launcher (`SCM_RIGHTS`) and exits.
4. The launcher serves the sockets with mitmproxy and writes to the block pipe: the command starts.

## Findings

| Question | Result |
|---|---|
| Can the host side enter the box's network namespace without privileges? | **Yes**, but not through the user namespace the box's processes are in. `--disable-userns` (which needs `--unshare-user`) puts them in a *nested* user namespace; the network namespace belongs to the outer one. Joining the inner one and then the network namespace fails with `EPERM`. Joining the owner found with `NS_GET_USERNS` works and gives full capabilities in that namespace only. `setns` into a user namespace needs a single-threaded process, hence the helper process. |
| Can mitmproxy serve a socket created elsewhere? | **Yes.** mitmproxy has no option for it, but its server instances' connection handlers serve any accepted stream: `asyncio.start_server(handler, sock=…)` with mitmproxy's own `regular` and `transparent` handlers (mitmproxy 12.3, pinned below 13 because this uses its internals). No relay process and no host port are needed. |
| Original destination of redirected connections? | **Yes**, `SO_ORIGINAL_DST` (IPv4 and IPv6) works on the accepted socket, read by mitmproxy's transparent mode. |
| nftables in the box's namespace? | **Yes**, from the helper (it has `CAP_NET_ADMIN` there; the box's processes do not: `nft flush ruleset` inside fails). |
| Does a redirect alone catch direct connections? | **No.** In a network namespace with only loopback, `connect()` to an outside address fails with "network unreachable" before netfilter sees it. The helper adds default routes over loopback. IPv4 also needs a source address with global scope (`192.0.2.1/32` on `lo`, a documentation address); otherwise redirected packets leave with source `0.0.0.0` and never connect. |
| UDP DNS to an outside resolver? | Redirected to the box resolver, answered and recorded. The resolver is bound to `127.0.0.1` and `::1` (not a wildcard address), so its answers leave from the redirect target and the kernel rewrites their source back to the server the client asked; clients with connected sockets accept them. |
| Other UDP (QUIC, NTP …)? | Dropped (`EPERM` at `sendto`); clients fall back to TCP. |
| Connection reuse | The proxy must not rewrite the destination address of a connection: mitmproxy reuses server connections by address, at most five per address, and a rewritten one is never reused (requests on a keep-alive connection then hang). The loopback check therefore resolves the name, checks every answer and leaves the address as it is; a connection that still lands on loopback (DNS rebinding) is closed in `server_connected`, before anything is sent. |
| Server-first protocols (SMTP, SSH banners) | Need eager server connections (mitmproxy's default); only the box's ports 80/443, whose destination comes from the TLS server name or Host header, connect lazily. |
| Terminal injection (`TIOCSTI`) | Not possible with `dev.tty.legacy_tiocsti = 0` (this kernel). Where it is 1 or unknown, the box gets `--new-session`. |

## Escape tests (all in `tests/test_box.py`)

| Attempt inside the box | Result |
|---|---|
| TLS to an IP address on 443 without proxy variables | redirected to the proxy, intercepted, recorded with the sending process |
| TCP to an IP address on another port (8080) | redirected to the proxy, recorded |
| UDP DNS query to `8.8.8.8` with a name carrying data | answered by the box resolver; the name is recorded as an `egress.lookup`; nothing leaves |
| UDP to an outside address on 443 | refused (`Operation not permitted`) |
| `unshare -n`, `unshare -rn` | refused (no capabilities; nested user namespaces disabled) |
| Read the CA key, list the body store | not there (the egress state is an empty folder in the box) |
| See or signal the proxy or the test runner | not visible (own PID namespace); `kill -0` fails |
| `nft flush ruleset` | refused |
| Write to the AQT state (trail folder) | read-only file system |
| `resolvectl query`, D-Bus, systemd user manager, docker | not reachable: `/run` is an empty tmpfs |

A real run through the box worked for curl, git (`ls-remote` and `clone` over HTTPS), pip (`download`), npm (`view`),
Python `urllib` and Node `fetch` (Node 22 honours the proxy variables with `NODE_USE_ENV_PROXY=1`; without it,
`fetch` reaches the box's port 443 through the resolver). Because of that variable, Node prints
`[UNDICI-EHPA] Warning: EnvHttpProxyAgent is experimental` once per process; the warning is harmless.

A Claude Code 2.1 session (`claude -p` running git, npm, pip and curl) worked through the box with its normal login.
The report showed its API calls to `api.anthropic.com` (structure only), its MCP connector calls, its telemetry
upload, and each tool's chain, for example `git-remote-http < git < git < bash < claude`. Measured on a desktop with
30 new HTTPS connections per host (each one a TLS handshake on both sides of the proxy), the proxy added 5–14 ms at
the median and 3–17 ms at the 95th percentile.

## Fallbacks

- **No nftables or iproute2** (or the table cannot be loaded): no default routes are added either. Proxy-aware
  clients work, proxy-unaware clients reach ports 80/443 through the resolver, and every other connection fails at
  once with "network unreachable". Only the name lookup is recorded. The session record says so
  (`box.network.redirect = false`) and `aqt egress run` prints a warning.
- **No IPv6 in the box:** the listeners fall back to IPv4 only.
- **No bubblewrap or no user namespaces:** `aqt egress run` refuses to start; `aqt egress status` and the `egress`
  line of `aqt status` say why.

## After the review (X2)

- **Starting the command.** bwrap's `--block-fd` starts the command on the end of the pipe too, and bwrap's first
  process outlives the outer bwrap until then (its parent-death signal is set only later), so a launcher killed
  before release used to let the command start (without any network). The box's first command is now a start
  gate (`/bin/sh`) that reads the pipe and starts the real command only on the exact random token the launcher
  writes; the end of the pipe makes it exit (`test_launcher_killed_before_release_never_starts_the_command`).
  A setup failure kills the first process by its pid, then bwrap, then closes the pipe (`test_x2_13`), and
  SIGTERM/SIGHUP handlers are installed when `run` starts, so a terminated launcher ends its box too.
- **cgroups.** `/sys/fs/cgroup` is bound read-only: the box shares the user's cgroups with the proxy and could
  otherwise freeze or kill it.
- **Tools and code.** bwrap, nft and ip come only from root-owned system folders; the interpreter, the packages
  and (for editable installs) the sources aqt-egress runs from are read-only in the box.
- **Host addresses.** Besides loopback, every address of the host's interfaces (from `ip -j addr`, refreshed every
  10 seconds) is refused, unless it is a configured local endpoint. A refresh only adds addresses: an empty or
  failed lookup never switches the refusal off.
- **What starts aqt-egress.** Its interpreter, packages and sources are read-only in the box, but not the command
  found through `PATH` (for example a shim in `~/.local/bin`), nor, with `pip install --user`, the other packages
  and `.pth` files in the user site folder. Install it into a virtual environment (as the install from a clone
  does) and start it by its full path.

## Side effects of the empty `/run`

Keyrings reached over the session D-Bus (`gh`, git's libsecret credential helper, other secret-service clients)
do not work in the box, and neither do aqt-sensei's bridge sockets in the runtime folder. Agents that keep their
credentials in files (Claude Code, Codex, pi) are not affected.

## Local inference endpoints and `--private-tmp`

- A configured local endpoint (`local_endpoints`, `--local-endpoint 127.0.0.1:8080`) gets a listener on the box's
  own loopback at that port (IPv4 and IPv6), opened by the helper like the others; the proxy forwards it to the
  host's endpoint and records each request (`via: local`, TLS mode `none`, structure only). Every other port on the
  host's loopback is still refused, and in the box nothing else listens there (verified in `tests/test_box.py`).
- `--private-tmp` adds `--tmpfs /tmp` and binds the project, the home folder and the AQT folders back where they
  live under `/tmp`; `TMPDIR` becomes `/tmp` when it pointed below the host's `/tmp`.

## What stays open

- Files are shared read-write by design; something in the box can leave a script that runs later outside it.
- Unix sockets outside `/run` and the hidden folders (for example an editor's IPC socket in `/tmp`, or an agent
  socket in the home folder) stay reachable and may act outside the box; `--private-tmp` closes those in `/tmp`. A
  filter on `AF_UNIX` connections (seccomp) is planned for the enforce stage. Abstract Unix sockets belong to the
  network namespace and are not reachable.
- Attribution is read from `/proc` when a connection or query arrives; a sender that already exited is recorded
  as `unavailable`.

## macOS: the Seatbelt box

On macOS, `aqt egress run` starts the command with `sandbox-exec` and a profile generated for the session
(`box.seatbelt_profile()`, kept as `box.sb` in the session folder; its SHA-256 is in the session record). The
approach follows Anthropic's sandbox-runtime and the Codex CLI: closed by default, then what a command-line program
needs. The proxy listens on a free port of the host's loopback, and the profile lets the box connect to that port and
nothing else. Verified on macOS 26.6 (Apple silicon) by `tests/test_box_macos.py`, which also runs on the macOS CI
runner, and by hand against the internet (`curl https://example.com` through the proxy: 200, recorded as
`curl < bash < bash`; the same with `--noproxy '*'`: no name lookup; to `https://1.1.1.1`: connection refused).

| | Linux (bubblewrap, own network namespace) | macOS (Seatbelt) |
|---|---|---|
| Way out | only the proxy; other TCP is redirected to it and recorded | only the proxy's port on `127.0.0.1`; other TCP and all UDP are refused (`EPERM`) and not recorded |
| Name lookups | the box resolver answers and records each one (`egress.lookup`) | none in the box (the system resolver's socket is closed); the proxy resolves the names it is asked for, so there are no `egress.lookup` records |
| Proxy-unaware programs | redirected (ports 80/443 through the resolver, the rest through nftables) | fail |
| Servers on loopback | the box's own loopback works | refused, the box's own too (loopback is the host's); configured local endpoints are reached through the proxy (`NO_PROXY` is removed) |
| Who reaches the proxy | only the box | any process on the host, during the session; its requests are recorded with `chain_status: unavailable` |
| Attribution | `/proc` of the box's namespace | libproc, over the box's process tree; a process that left the tree (reparented to launchd) is `unavailable` |
| Session CA | replaces the system bundle in the box | only through the variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, …); programs that check certificates only through the keychain (Go programs such as `gh`, Swift) do not trust it. `trustd` stays closed: it fetches URLs named in certificates itself, outside the proxy |
| Hidden folders (egress and quarantine state) | empty | refused |
| Read-only folders (AQT configuration and state, the installation) | read-only mounts | writes refused; renaming them or a folder above them refused; hard links to their files refused |
| Service sockets | `/run` is empty | refused: `/private/var/run` (mDNSResponder, syslog, Docker), launchd's per-user sockets in `/private/tmp` (ssh-agent, the X server), tmux, `~/.docker`, the user's socket folder except `aqt/` (the trail writer) |
| Processes | own PID namespace: the proxy is invisible | the proxy cannot be signalled or inspected; names and arguments of the user's processes stay readable through `sysctl`; setuid programs such as `ps` do not start |
| Jobs outside the box | the systemd user manager is unreachable | launchd refuses to create jobs (`launchctl submit`, `bootstrap`) |
| Keychain | D-Bus keyrings are unreachable | reachable (the files are shared anyway; agents such as Claude Code keep their login there on macOS) |
| Launcher killed with SIGKILL | the box ends with it (`--die-with-parent`) | the command keeps running; its only way out is the closed port, until something else listens on it |
| `--private-tmp` | yes | refused |

`aqt egress status` and the `egress` line of `aqt status` say this in one sentence (`box.MACOS_LIMITS`).
