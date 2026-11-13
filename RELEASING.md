# Releasing

All eleven packages are released together, under one version, by the workflow [`release.yml`](.github/workflows/release.yml). A tag `v<version>` starts it. It builds every package, installs the built files into a clean environment, and creates a GitHub release with those files and the CHANGELOG notes. [Zenodo](https://zenodo.org) archives each GitHub release and gives it a DOI, using the metadata in [`CITATION.cff`](CITATION.cff).

PyPI is not used yet. The PyPI jobs are in the workflow, switched off until the repository variable `PUBLISH_PYPI` is `true` ([Later: PyPI](#later-pypi)).

## What the workflow does

| Job | What it does | Runs |
|---|---|---|
| `build` | checks out the tag; checks that every package has the same version and the tag is `v` + that version (`scripts/check_versions.py`); collects the CHANGELOG notes (`scripts/release_notes.py`); `scripts/build_dist.sh`: rewrites the package READMEs' relative links to GitHub URLs at the tag (`scripts/pypi_readmes.py`, for project pages on PyPI later), `uv build` of every package, `twine check` | always |
| `verify` | installs the built wheels into a fresh environment outside the checkout and runs every command, `aqt status` and the demo (`scripts/clean_install_check.sh --dist`) | always |
| `github-release` | a GitHub release for the tag with the 22 built files and the CHANGELOG notes; Zenodo archives it | tag only |
| `testpypi` | uploads to TestPyPI (environment `testpypi`) | only with `PUBLISH_PYPI` |
| `testpypi-smoke` | `uv tool install "agent-quality-toolkit[egress]"` from TestPyPI (the toolkit's packages from TestPyPI, everything else from PyPI), then `aqt --version`, `aqt-toolkit --version` and every command's `--help` | only with `PUBLISH_PYPI` |
| `pypi` | uploads the same files to PyPI (environment `pypi`, waits for the owner's approval) | tag only, only with `PUBLISH_PYPI` |

Started by hand (Actions → release → Run workflow), it is a dry run: it builds and verifies, and creates no release. CI's `packaging` job runs `scripts/build_dist.sh` on every push, so a packaging problem shows up before a tag. Locally, `scripts/build_dist.sh /tmp/aqt-dist --tag v0.2.0` runs the build job (from a copy of the last commit) and `scripts/clean_install_check.sh --dist /tmp/aqt-dist` the verify job.

## One-time setup (owner): Zenodo

Zenodo archives only releases created after the repository was switched on, so do this before the first tag.

1. On [zenodo.org](https://zenodo.org), log in with GitHub and allow the Zenodo app access.
2. Profile menu → GitHub → Sync, then switch on `benediktneumayer2-tech/agent-quality-toolkit`.

Zenodo then reads `CITATION.cff` from each tagged commit: title, authors, abstract, keywords, licence and version. Each release gets its own DOI. A second DOI, the *concept DOI*, always points to the newest version; cite that one when the version does not matter.

## A release, step by step

1. **Version.** Set the same version in every `*/pyproject.toml` (`version = "X.Y.Z"`), in each package's `__version__` and in `CITATION.cff`; when the minor version changes, also the ranges of the dependencies between the packages (for example `aqt-spec>=0.2,<0.3`). `python3 scripts/check_versions.py` prints the version when all packages agree.
2. **Dates.** In every package's `CHANGELOG.md`, the section `## X.Y.Z — unreleased` becomes `## X.Y.Z — YYYY-MM-DD` with the release date; in `CITATION.cff`, set `date-released: YYYY-MM-DD`. `python3 scripts/release_notes.py X.Y.Z` must then succeed; on a tag the workflow refuses sections still marked unreleased.
3. **Docs.** Update version mentions (README badge and status line, the install commands' `--branch vX.Y.Z`, manual header) where needed.
4. **Commit and push to `main`**, and wait until CI is green (its `packaging` job builds exactly as the release will).
5. **Optional dry run:** Actions → release → Run workflow on `main`.
6. **Tag and push the tag:**

   ```bash
   git tag -a vX.Y.Z -m "Agent Quality Toolkit X.Y.Z"
   git push origin vX.Y.Z
   ```

7. **Check.** The GitHub release lists 22 files and the notes. A few minutes later, Zenodo (Profile menu → GitHub) shows the release with its DOI. In a fresh terminal, the install from the README works with the new tag, and `aqt --version` prints X.Y.Z.
8. **First release only:** add the DOI badge that Zenodo offers to the README, and the concept DOI to `CITATION.cff` (`doi: 10.5281/zenodo.…`).

**If something fails before the GitHub release,** fix it, delete the tag (`git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`) and tag the fixed commit again. **Once the GitHub release exists,** Zenodo has archived it, and a DOI cannot be withdrawn: release the fix as X.Y.(Z+1), all packages together.

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
