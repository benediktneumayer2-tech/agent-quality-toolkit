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

Ubuntu 24.04 and later can restrict unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns`). In some contexts this blocks `/usr/bin/bwrap`, for example inside certain terminal multiplexers. `doctor` reports "bubblewrap can create namespaces: FAIL" when that happens. Remedies: an AppArmor profile that allows `userns` for the bwrap binary you use, or `sandbox.bwrap` pointing to a binary that has one. Do not disable the restriction system-wide just for this.

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
