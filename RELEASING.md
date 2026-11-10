# Releasing

All eleven packages are released together, under one version, by the workflow [`release.yml`](.github/workflows/release.yml). A tag `v<version>` starts it. Every release goes to TestPyPI first and is installed from there; PyPI waits until the owner approves it. Uploads use PyPI's [trusted publishing](https://docs.pypi.org/trusted-publishers/): GitHub proves to PyPI which workflow is running, so no password or token is stored. The only exception is the very first release, which has to create the projects (below).

The eleven PyPI projects: `agent-quality-toolkit` (folder `aqt-cli`, the `aqt` and `aqt-toolkit` commands), `aqt-spec`, `aqt-trail`, `aqt-signoff`, `aqt-change`, `aqt-sensei`, `aqt-quarantine`, `aqt-validate`, `aqt-capa`, `aqt-ui` and `aqt-egress`.

## What the workflow does

| Job | What it does | Runs |
|---|---|---|
| `build` | checks out the tag; checks that every package has the same version and the tag is `v` + that version (`scripts/check_versions.py`); collects the CHANGELOG notes (`scripts/release_notes.py`); `scripts/build_dist.sh`: rewrites the package READMEs' relative links to GitHub URLs at the tag (`scripts/pypi_readmes.py`, for the project pages on PyPI), `uv build` of every package, `twine check` | always |
| `verify` | installs the built wheels into a fresh environment outside the checkout and runs every command, `aqt status` and the demo (`scripts/clean_install_check.sh --dist`) | always |
| `testpypi` | uploads to TestPyPI (environment `testpypi`) | always |
| `testpypi-smoke` | `uv tool install "agent-quality-toolkit[egress]"` from TestPyPI (the toolkit's packages from TestPyPI, everything else from PyPI), then `aqt --version`, `aqt-toolkit --version` and every command's `--help` | always |
| `pypi` | uploads the same files to PyPI (environment `pypi`, waits for the owner's approval) | tag only |
| `github-release` | a GitHub release for the tag with the 22 built files and the CHANGELOG notes | tag only |

Started by hand (Actions → release → Run workflow), it is a dry run: it stops after `testpypi-smoke` and never reaches PyPI. CI's `packaging` job runs `scripts/build_dist.sh` on every push, so a packaging problem shows up before a tag. Locally, `scripts/build_dist.sh /tmp/aqt-dist --tag v0.2.0` runs the build job (from a copy of the last commit) and `scripts/clean_install_check.sh --dist /tmp/aqt-dist` the verify job.

## One-time setup (owner)

### 1. Accounts

Create an account on [pypi.org](https://pypi.org/account/register/) and a separate one on [test.pypi.org](https://test.pypi.org/account/register/), and turn on two-factor authentication on both (both indexes require it for uploads).

### 2. GitHub environments

In the repository, Settings → Environments → New environment:

| Environment | Settings |
|---|---|
| `testpypi` | Deployment branches and tags: *Selected branches and tags*, add the branch `main` and the tag pattern `v*` |
| `pypi` | Required reviewers: `benediktneumayer2-tech`, with *Prevent self-review* off (you push the tag and approve it yourself); deployment branches and tags: only the tag pattern `v*` |

### 3. The first release creates the projects

Trusted publishing needs a publisher registered on each project. For a project that does not exist yet, PyPI offers a *pending* publisher, but that does not work for eleven new projects at once: PyPI allows at most three pending publishers per account at a time, and one upload run turns only one of them into a project. So the first release uploads with an API token, and the publishers are added afterwards:

1. Check that the names are still free (each prints 404): `for n in agent-quality-toolkit aqt-spec aqt-trail aqt-signoff aqt-change aqt-sensei aqt-quarantine aqt-validate aqt-capa aqt-ui aqt-egress; do curl -s -o /dev/null -w "%{http_code} $n\n" https://pypi.org/pypi/$n/json; done` (and the same with `test.pypi.org`). Nothing reserves a name before its first upload, so do the first release soon after this check.
2. On test.pypi.org: Account settings → API tokens → Add API token, scope *Entire account*. Store it in GitHub as the secret `TESTPYPI_API_TOKEN` of the environment `testpypi` (Settings → Environments → testpypi → Add environment secret).
3. On pypi.org the same, stored as the secret `PYPI_API_TOKEN` of the environment `pypi`. Only jobs of that environment can read it, and the `pypi` job runs only after your approval.
4. Release as described below. The upload creates the eleven projects on each index, and you are their owner. Without trusted publishing, PyPI shows no attestations for this first version.
5. Add the trusted publisher to every project, on both indexes (22 forms): Your projects → *project* → Manage → Publishing → Add a new publisher → GitHub:

   | Field | Value |
   |---|---|
   | Owner | `benediktneumayer2-tech` |
   | Repository name | `agent-quality-toolkit` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` on pypi.org, `testpypi` on test.pypi.org |

6. Delete the two secrets in GitHub and the two tokens on the indexes. From now on the workflow uses trusted publishing: without the secrets, the publish action asks GitHub for proof of the workflow instead.

## A release, step by step

1. **Version.** Set the same version in every `*/pyproject.toml` (`version = "X.Y.Z"`) and in each package's `__version__`; when the minor version changes, also the ranges of the dependencies between the packages (for example `aqt-spec>=0.2,<0.3`). `python3 scripts/check_versions.py` prints the version when all agree.
2. **CHANGELOGs.** In every package's `CHANGELOG.md`, the section `## X.Y.Z — unreleased` becomes `## X.Y.Z — YYYY-MM-DD` with the release date. `python3 scripts/release_notes.py X.Y.Z` must then succeed; on a tag the workflow refuses sections still marked unreleased.
3. **Docs.** Update version mentions (README badge and status line, manual header) where needed.
4. **Commit and push to `main`**, and wait until CI is green (its `packaging` job builds exactly as the release will).
5. **Optional dry run:** Actions → release → Run workflow on `main`. TestPyPI then keeps these files: it never accepts the same file twice, so the tagged run skips them on TestPyPI (the verify job still checks the tag's own files).
6. **Tag and push the tag:**

   ```bash
   git tag -a vX.Y.Z -m "Agent Quality Toolkit X.Y.Z"
   git push origin vX.Y.Z
   ```

7. **Approve.** When `build`, `verify`, `testpypi` and `testpypi-smoke` are green, the run waits at `pypi`: Review deployments → `pypi` → Approve and deploy.
8. **Check.** <https://pypi.org/project/agent-quality-toolkit/> shows X.Y.Z, and the links and screenshots on the package pages work. In a fresh terminal: `uv tool install agent-quality-toolkit` and `aqt --version`. The GitHub release lists 22 files and the notes.

**If something fails before PyPI,** fix it, delete the tag (`git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`) and tag the fixed commit again. **Once anything has reached PyPI,** that version is spent: PyPI never accepts the same file name again, even after deleting it. Release the fix as X.Y.(Z+1), all packages together.
