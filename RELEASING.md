# Releasing

All eleven packages and the desktop app are released together, under one version, by the workflow [`release.yml`](.github/workflows/release.yml). A tag `v<version>` starts it. It builds every package, installs the built files into a clean environment, builds and smoke-tests the desktop installers of every platform, and creates a GitHub release with the packages, the installers, a `SHA256SUMS` file and the CHANGELOG notes. [Zenodo](https://zenodo.org) archives each GitHub release and gives it a DOI, using the metadata in [`CITATION.cff`](CITATION.cff); it archives the source code of the tag, while the installers stay on GitHub.

The installers are not signed with an Apple or Windows certificate yet; the README tells users how to open them the first time. The desktop app can update itself from the GitHub release once the owner has set up the updater key ([Updates of the desktop app](#updates-of-the-desktop-app)); until then it never checks for updates.

PyPI is not used yet. The PyPI jobs are in the workflow, switched off until the repository variable `PUBLISH_PYPI` is `true` ([Later: PyPI](#later-pypi)).

## What the workflow does

| Job | What it does | Runs |
|---|---|---|
| `build` | checks out the tag; checks that every package has the same version and the tag is `v` + that version (`scripts/check_versions.py`); collects the CHANGELOG notes (`scripts/release_notes.py`); `scripts/build_dist.sh`: rewrites the package READMEs' relative links to GitHub URLs at the tag (`scripts/pypi_readmes.py`, for project pages on PyPI later), `uv build` of every package, `twine check` | always |
| `verify` | installs the built wheels into a fresh environment outside the checkout and runs every command, `aqt status` and the demo (`scripts/clean_install_check.sh --dist`) | always |
| `desktop` | calls [`desktop.yml`](.github/workflows/desktop.yml): every platform job there builds its installers and smoke-tests them, and uploads them as an artifact `aqt-desktop-<platform>`. Today: Linux (AppImage and .deb) and macOS (.dmg for Apple silicon and for Intel, each with the `.app.tar.gz` the app updates itself from); a new platform job, such as Windows, is picked up without a change to `release.yml` | always |
| `release-files` | puts the 22 Python files and every `aqt-desktop-*` artifact into one folder and runs `scripts/desktop_release.py`: with the updater key it signs the updates and writes `latest.json`; without it the `.app.tar.gz` files are left out; then `SHA256SUMS` of every file. A tag fails here when the app checks for updates but the key is missing. The only job that sees the key | always |
| `github-release` | a GitHub release for the tag with every file of `release-files` and the CHANGELOG notes; Zenodo archives it | tag only |
| `testpypi` | uploads to TestPyPI (environment `testpypi`) | only with `PUBLISH_PYPI` |
| `testpypi-smoke` | `uv tool install "agent-quality-toolkit[egress]"` from TestPyPI (the toolkit's packages from TestPyPI, everything else from PyPI), then `aqt --version`, `aqt-toolkit --version` and every command's `--help` | only with `PUBLISH_PYPI` |
| `pypi` | uploads the same files to PyPI (environment `pypi`, waits for the owner's approval) | tag only, only with `PUBLISH_PYPI` |

Started by hand (Actions → release → Run workflow), it is a dry run: it builds and verifies, builds the installers, and creates no release; every file that the release would get is in the run's artifact `release-files`. CI's `packaging` job runs `scripts/build_dist.sh` on every push, so a packaging problem shows up before a tag. Locally, `scripts/build_dist.sh /tmp/aqt-dist --tag v0.2.0` runs the build job (from a copy of the last commit) and `scripts/clean_install_check.sh --dist /tmp/aqt-dist` the verify job. `aqt-desktop/scripts/build-linux.sh` builds the Linux installers (in Docker), and `python3 scripts/desktop_release.py /tmp/aqt-dist --version X.Y.Z` writes `SHA256SUMS` into a folder of release files (and `latest.json` from `.sig` files there).

## One-time setup (owner): Zenodo

Zenodo archives only releases created after the repository was switched on, so do this before the first tag.

1. On [zenodo.org](https://zenodo.org), log in with GitHub and allow the Zenodo app access.
2. Profile menu → GitHub → Sync, then switch on `benediktneumayer2-tech/agent-quality-toolkit`.

Zenodo then reads `CITATION.cff` from each tagged commit: title, authors, abstract, keywords, licence and version. Each release gets its own DOI. A second DOI, the *concept DOI*, always points to the newest version; cite that one when the version does not matter.

## A release, step by step

1. **Version.** Set the same version in every `*/pyproject.toml` (`version = "X.Y.Z"`), in each package's `__version__`, in `CITATION.cff` and in the desktop app's `aqt-desktop/src-tauri/tauri.conf.json` and `aqt-desktop/src-tauri/Cargo.toml`; when the minor version changes, also the ranges of the dependencies between the packages (for example `aqt-spec>=0.2,<0.3`). `python3 scripts/check_versions.py` prints the version when all of them agree.
2. **Dates.** In every package's `CHANGELOG.md`, the section `## X.Y.Z — unreleased` becomes `## X.Y.Z — YYYY-MM-DD` with the release date; in `CITATION.cff`, set `date-released: YYYY-MM-DD`. `python3 scripts/release_notes.py X.Y.Z` must then succeed; on a tag the workflow refuses sections still marked unreleased.
3. **Docs.** Update version mentions (README badge and status line, the download names and the install commands' `--branch vX.Y.Z`, manual header) where needed.
4. **Commit and push to `main`**, and wait until CI is green (its `packaging` job builds the packages exactly as the release will, and the `desktop` workflow the installers).
5. **Optional dry run:** Actions → release → Run workflow on `main`.
6. **Tag and push the tag:**

   ```bash
   git tag -a vX.Y.Z -m "Agent Quality Toolkit X.Y.Z"
   git push origin vX.Y.Z
   ```

7. **Check.** The GitHub release lists the 22 Python files, the installers (`aqt-desktop_X.Y.Z_amd64.AppImage`, `_amd64.deb`, `_arm64.dmg`, `_x86_64.dmg`, and `_x64-setup.exe` once the Windows job is in `desktop.yml`), `SHA256SUMS` and the notes; with the updater key also `latest.json` and the two `.app.tar.gz`. A few minutes later, Zenodo (Profile menu → GitHub) shows the release with its DOI. Download one installer and check it with `sha256sum -c SHA256SUMS --ignore-missing`, then open it as the README describes. In a fresh terminal, the install from the README works with the new tag, and `aqt --version` prints X.Y.Z.
8. **First release only:** add the DOI badge that Zenodo offers to the README, and the concept DOI to `CITATION.cff` (`doi: 10.5281/zenodo.…`).

**If something fails before the GitHub release,** fix it, delete the tag (`git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`) and tag the fixed commit again. **Once the GitHub release exists,** Zenodo has archived it, and a DOI cannot be withdrawn: release the fix as X.Y.(Z+1), all packages together.

## Updates of the desktop app

The app can update itself from the GitHub release: it reads `latest.json` of the newest release, shows a dot at Settings when there is a newer version, and installs it only after the person agrees there, at the next start. Each update must carry a signature made with the **updater key**, a key pair that belongs to the owner: the app trusts only the public key built into it, so nobody else can hand it an update, not even through the GitHub release.

It is **off** until the owner sets it up. While `plugins.updater.pubkey` in [`aqt-desktop/src-tauri/tauri.conf.json`](aqt-desktop/src-tauri/tauri.conf.json) is empty, the app never asks for updates, and a release without the key has no `latest.json`.

### Switching it on (owner, once)

Do this on your own computer, never in CI or an agent session. Nobody else needs the private key or its password.

1. **Generate the key pair.** In a clone, `cd aqt-desktop && npm ci`, then:

   ```bash
   npx tauri signer generate -w ~/.tauri/aqt-updater.key
   ```

   It asks for a password (choose a long one). It writes the private key to `~/.tauri/aqt-updater.key` and the public key to `~/.tauri/aqt-updater.key.pub`.
2. **Keep a backup** of the private key file and its password where you keep other secrets (a password manager, an offline copy). Never commit them.
3. **Repository secrets.** On GitHub: Settings → Secrets and variables → Actions → New repository secret:

   | Name | Value |
   |---|---|
   | `TAURI_SIGNING_PRIVATE_KEY` | the content of `~/.tauri/aqt-updater.key` |
   | `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | its password |

4. **Public key into the app.** Put the content of `~/.tauri/aqt-updater.key.pub` (one line) into `plugins.updater.pubkey` in `aqt-desktop/src-tauri/tauri.conf.json` and commit it with the next release's changes. In the README's *Status and limits*, drop "the app does not update itself yet".
5. **Check with a dry run** (Actions → release → Run workflow): the artifact `release-files` now has `latest.json`, with one entry per platform. `scripts/desktop_release.py` refuses signatures that were not made with the key whose public key is in the config.

From the next release on, `release-files` signs every update file with `tauri signer sign --app-version X.Y.Z` (the signature also names the version, so an old release cannot be passed off as a new one), and the release has `latest.json`. A tag of a version whose app config has the public key fails when the secrets are missing, so that the apps that check never find a release without a manifest.

Versions released before the public key was in the config never check for updates. Their users install the first version that has the key by hand, as the README describes; later versions arrive through the app.

### If the key is lost or leaks

The installed apps trust only the public key they were built with. An update signed with another key is refused on every machine, and Settings shows that it could not be installed.

- **Lost** (file or password): generate a new key pair (steps 1 to 4) and release a new version with the new public key. The installed apps cannot take that version as an update; their users download and install it by hand once, as the first time. From then on, updates work again.
- **Leaked:** delete the two repository secrets at once, then do the same as for a lost key. A leaked key alone cannot reach the apps (they load `latest.json` only from this repository's newest release, which needs write access to the repository), but rotate it anyway. Say so in the release notes, so that users know why they install by hand.
- **Switching updates off again:** empty `pubkey` and release; that version and later ones stop checking.

## Later: PyPI

The packages are ready for PyPI (PEP 639 licence metadata, READMEs with links that work on PyPI, one version), but are not uploaded yet. To turn PyPI on:

### 1. Accounts

Create an account on [pypi.org](https://pypi.org/account/register/) and a separate one on [test.pypi.org](https://test.pypi.org/account/register/), and turn on two-factor authentication on both (both indexes require it for uploads).

### 2. GitHub environments and the switch

In the repository, Settings → Environments → New environment:

| Environment | Settings |
|---|---|
| `testpypi` | Deployment branches and tags: *Selected branches and tags*, add the branch `main` and the tag pattern `v*` |
| `pypi` | Required reviewers: `benediktneumayer2-tech`, with *Prevent self-review* off (you push the tag and approve it yourself); deployment branches and tags: only the tag pattern `v*` |

Then Settings → Secrets and variables → Actions → Variables → New repository variable: `PUBLISH_PYPI` = `true`. From then on, a tag also goes to TestPyPI and, after your approval of the `pypi` environment, to PyPI. A dry run by hand also uploads to TestPyPI, which keeps those files: it never accepts the same file twice, so the tagged run skips them there.

### 3. The first upload creates the projects

The eleven projects: `agent-quality-toolkit` (folder `aqt-cli`, the `aqt` and `aqt-toolkit` commands), `aqt-spec`, `aqt-trail`, `aqt-signoff`, `aqt-change`, `aqt-sensei`, `aqt-quarantine`, `aqt-validate`, `aqt-capa`, `aqt-ui` and `aqt-egress`.

Uploads use PyPI's [trusted publishing](https://docs.pypi.org/trusted-publishers/): GitHub proves to PyPI which workflow is running, so no password or token is stored. Trusted publishing needs a publisher registered on each project. For a project that does not exist yet, PyPI offers a *pending* publisher, but that does not work for eleven new projects at once: PyPI allows at most three pending publishers per account at a time, and one upload run turns only one of them into a project. So the first upload uses an API token, and the publishers are added afterwards:

1. Check that the names are still free (each prints 404): `for n in agent-quality-toolkit aqt-spec aqt-trail aqt-signoff aqt-change aqt-sensei aqt-quarantine aqt-validate aqt-capa aqt-ui aqt-egress; do curl -s -o /dev/null -w "%{http_code} $n\n" https://pypi.org/pypi/$n/json; done` (and the same with `test.pypi.org`). Nothing reserves a name before its first upload, so do the first upload soon after this check.
2. On test.pypi.org: Account settings → API tokens → Add API token, scope *Entire account*. Store it in GitHub as the secret `TESTPYPI_API_TOKEN` of the environment `testpypi` (Settings → Environments → testpypi → Add environment secret).
3. On pypi.org the same, stored as the secret `PYPI_API_TOKEN` of the environment `pypi`. Only jobs of that environment can read it, and the `pypi` job runs only after your approval.
4. Release as described above. The upload creates the eleven projects on each index, and you are their owner. Without trusted publishing, PyPI shows no attestations for this first version.
5. Add the trusted publisher to every project, on both indexes (22 forms): Your projects → *project* → Manage → Publishing → Add a new publisher → GitHub:

   | Field | Value |
   |---|---|
   | Owner | `benediktneumayer2-tech` |
   | Repository name | `agent-quality-toolkit` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` on pypi.org, `testpypi` on test.pypi.org |

6. Delete the two secrets in GitHub and the two tokens on the indexes. From now on the workflow uses trusted publishing: without the secrets, the publish action asks GitHub for proof of the workflow instead.
7. Switch the docs' install commands to PyPI (`uv tool install agent-quality-toolkit`).

With PyPI on, step 7 of a release also waits for the approval: when `build`, `verify`, `testpypi` and `testpypi-smoke` are green, the run waits at `pypi` (Review deployments → `pypi` → Approve and deploy). Check <https://pypi.org/project/agent-quality-toolkit/> afterwards. Once anything has reached PyPI, that version is spent there too: PyPI never accepts the same file name again, even after deleting it.
