# Changelog

## 0.2.0 — unreleased

First version.

- `aqt status` (`--json`, `--verify`): one verdict for the setup of this machine, with a result,
  a one-line explanation and the fix for each check: packages, trail, systemd user service, writer,
  spool, where records go, signer, `signoff.toml`, `trail.toml`, the end of the trail, test vectors.
- `aqt setup` (`--yes`, `--id/--name/--role`): runs the same checks and applies the missing steps
  (`aqt-trail init`, the user service, `aqt-signoff init`, the two settings files); safe to rerun,
  never overwrites keys, the signer registry or existing files.
- `aqt <tool> ARGS...`: runs `aqt-trail`, `aqt-signoff`, `aqt-change`, `aqt-sensei`, `aqt-quarantine`,
  `aqt-validate`, `aqt-capa`, `aqt-ui` or `aqt-evidence` (as `spec` or `evidence`) with the same
  arguments and exit code.
