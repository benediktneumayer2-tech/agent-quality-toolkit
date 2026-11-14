# The advisor sandbox

`aqt-sensei launch --pair ID` builds one bubblewrap command line from the pair and its profile, then replaces itself with it. `aqt-sensei doctor` runs a probe inside exactly that command line.

## Layout

| What | How it is mounted |
|---|---|
| `/usr`, `/etc`, `/opt`, `/bin`, `/lib*` | read-only |
| `/proc`, `/dev` | fresh |
| `/tmp`, `/run`, `/home` | empty tmpfs; `$HOME` is an empty folder |
| the project | read-only |
| the advisor CLI | its symlinks recreated; its install root read-only (the folder above `node_modules` for npm packages) |
| `profile.ro_binds`, `sandbox.extra_ro_binds` | read-only, if present |
| the platform's private home (`$XDG_STATE_HOME/aqt/sensei/homes/<platform>`) | read-write |
| the scratch folder `<project>/.sensei/<pair>` | read-write (over the read-only project) |
| this pair's runtime folder (`advisor.sock`, the `sensei` shim, the Herdr proxy) | read-only |

Namespaces: `--unshare-all --die-with-parent`, plus `--share-net` unless the pair uses `--network none`. The environment is cleared (`--clearenv`). Only `HOME`, `PATH`, `LANG`, `LC_ALL`, `TERM`, `COLORTERM`, `TZ`, the profile's variables, `sandbox.env_allow` and the bridge's own variables are set: `AQT_SENSEI_SOCKET`, `AQT_SENSEI_ROLE`, `AQT_SENSEI_PAIR`, and `AQT_AGENT_SESSION=1`, which shared AQT human checks recognise.

Not visible: the bridge state (`pairs.json`, message logs), other pairs, the owner token and config, `owner.sock`, `agent.sock`, other platforms' homes, the tmux socket, the real Herdr socket and your home.

## Profiles

Built-in profiles (overridable under `[profiles.NAME]` in the config):

| Profile | Command | Prompt | Private home variable |
|---|---|---|---|
| `claude` | `claude --append-system-prompt-file … --add-dir PROJECT --permission-mode bypassPermissions --strict-mcp-config --settings {"sandbox":{"enabled":false}}`, `--session-id`/`--resume` | `.sensei-prompt.md` | `CLAUDE_CONFIG_DIR` |
| `codex` | `codex --search -s danger-full-access -a never -C SCRATCH` | `AGENTS.md` in the scratch folder | `CODEX_HOME` |
| `pi` | `pi` | `AGENTS.md` in the scratch folder | `PI_CODING_AGENT_DIR` (check against your pi version) |
| any command | as given | `AGENTS.md` | `homes/custom-<name>` |

The CLIs' own permission prompts and nested sandboxes are switched off inside bwrap: the kernel enforces the limits, and prompts would stall a pane nobody watches. Placeholders in profile commands and env: `{prompt_file}`, `{scratch}`, `{project}`, `{home}`, `{model}`, `{session}`.

A pi advisor that needs an API key gets it only through `env_allow`. The advisor can then read that key, which is inherent to letting it run.

## Herdr

Herdr's socket would let any client type into any pane. Under the Herdr backend, the launcher forks a small proxy (`pairs/<id>/herdr.sock`), mounted at `HERDR_SOCKET_PATH` inside the sandbox. It forwards only `pane.report_agent`, `pane.report_agent_session` and `pane.release_agent` for the advisor's own pane, so Herdr's integrations still see the advisor's lifecycle. Everything else gets `forbidden`.

## Ubuntu and AppArmor

Ubuntu 24.04 and later restrict unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns`). Ubuntu 24.04 ships no AppArmor profile that lets `/usr/bin/bwrap` use them, so from a normal terminal `doctor` reports "bubblewrap can create namespaces: FAIL" (programs with their own profile, such as some desktop apps, are not affected). Remedies: the profile for `/usr/bin/bwrap` in the [manual, 6.4](../../docs/manual.md#64-sandbox-validation-and-capa) (two commands), or `sandbox.bwrap` pointing to a binary that has one. Do not disable the restriction system-wide just for this.

## doctor

```bash
aqt-sensei doctor --pair sp-1a2b3c4d          # the live pair's exact sandbox (result recorded as sensei.pair doctor)
aqt-sensei doctor --profile codex --project ~/code/app
```

Host checks:
- bwrap is installed and can create namespaces;
- tmux or Herdr is installed;
- the owner token exists.

Probe inside the sandbox:
- writing into the project fails;
- the scratch folder is writable;
- the owner's sensitive paths, token, config, state and sockets are not visible;
- only allowed environment names are set (bwrap adds `PWD`);
- other pairs are not visible;
- the advisor socket answers;
- for built-in profiles, the CLI starts (`--version`).

Exit 1 if any check fails.

## macOS: Seatbelt

On macOS, `aqt-sensei launch` replaces itself with `sandbox-exec -p PROFILE /usr/bin/env -i NAME=value … CLI`. The
profile is generated per pair (`sandbox.seatbelt_profile()`), closed by default, following Anthropic's sandbox-runtime
and the Codex CLI; `doctor` runs its probe inside the same command line. Verified on macOS 26.6 (Apple silicon) by
`tests/test_seatbelt_real.py` (also on the macOS CI runner) and by hand (`curl` to an HTTPS site works with
`--network share` and cannot even look the name up with `none`; the login keychain and the home folder are refused).

| | Linux (bubblewrap) | macOS (Seatbelt) |
|---|---|---|
| System | `/usr`, `/etc`, `/opt`, `/bin`, `/lib*` read-only; nothing else exists | everything outside the user folders readable, nothing writable |
| User folders | `/home`, `/tmp`, `/run` are empty | `/Users`, `/Volumes`, `/private/tmp`, `/private/var/folders` refused (not empty), except the project, the CLI, the private home, the scratch folder and the pair's runtime folder |
| `HOME` | an empty folder at your home's path | the private home itself |
| Temporary files | an empty `/tmp` | `/tmp` refused; `TMPDIR` is `.tmp` in the scratch folder |
| Writable | the private home, the scratch folder | the same |
| Unix sockets | only what is mounted: the pair's runtime folder | only the pair's runtime folder (advisor socket, Herdr proxy), the private home and the scratch folder; `HERDR_SOCKET_PATH` names the proxy, since it cannot be mounted over the real socket |
| `--network share` | the host's network | the IP network and the system resolver |
| `--network none` | own network namespace | no IP connections, no name lookups |
| Keychain | not involved (credential files are hidden) | not reachable (the login keychain file is refused, `securityd` closed): it would show the owner's own logins |
| Processes | own PID namespace | other processes cannot be signalled or inspected; their names and arguments stay readable through `sysctl` |
| Environment | `--clearenv` plus the allow-list | `env -i` plus the allow-list; macOS adds `__CF_USER_TEXT_ENCODING` itself |

Open: Claude Code keeps its login in the macOS keychain. In the sandbox the keychain is closed, so whether
`aqt-sensei login claude` works depends on Claude Code falling back to a file in `CLAUDE_CONFIG_DIR`; this has not been
tried with a real account yet. Codex and pi keep their logins in files.
