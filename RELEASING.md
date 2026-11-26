# Releasing

The package is published to PyPI as **`mcp-rbac-gateway`**. The name `mcp-sentinel` and
names PyPI treats as too similar to it, such as `mcpsentinel-gateway`, belong to other
projects. The import name `mcp_sentinel` and the `mcp-sentinel`
command are unchanged.

Publishing uses [trusted publishing](https://docs.pypi.org/trusted-publishers/): GitHub
Actions proves who it is to PyPI with OIDC, so no API token is stored anywhere.

## Checking a name before you register it

PyPI rejects a new name when, after normalization, it equals an existing project's
name. Normalization removes `.`, `_` and `-`, lowercases, and treats `l`/`i`/`1` and
`o`/`0` as the same character. The JSON API alone won't catch this, because the
colliding project can be spelled differently. Run:

```bash
python scripts/check_pypi_name.py mcp-rbac-gateway
```

## One-time setup

Do these once, as the repository owner.

1. **Create accounts** on [pypi.org](https://pypi.org/account/register/) and
   [test.pypi.org](https://test.pypi.org/account/register/). They are separate sites, so
   you need an account on each. Turn on two-factor authentication on both, because PyPI
   requires it to publish.
2. **Add a pending publisher on PyPI.** Go to
   [pypi.org/manage/account/publishing](https://pypi.org/manage/account/publishing/) and
   fill in:
   - PyPI project name: `mcp-rbac-gateway`
   - Owner: `pavankalyan-Maturi`
   - Repository name: `mcp-sentinel`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. *(Optional)* **Do the same on TestPyPI** at
   [test.pypi.org/manage/account/publishing](https://test.pypi.org/manage/account/publishing/),
   with environment name `testpypi`. You only need this for the dry run below.
4. **Create the GitHub environment** `pypi` (and `testpypi` if you set up step 3) under the repository's
   *Settings → Environments*. For `pypi`, it's worth adding
   yourself as a *required reviewer*. Every real release then waits for one click from
   you before it uploads.

"Pending" means the project doesn't exist on PyPI yet. The first successful upload
creates it and claims the name for you.

## Dry run (optional)

Open the *Actions* tab, choose **Release**, then **Run workflow** on `main`. This runs the
tests, builds, and uploads to TestPyPI only. Then check the install:

```bash
pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ mcp-rbac-gateway
mcp-sentinel --version
```

## Each release

1. Bump `__version__` in `src/mcp_sentinel/__init__.py`. That is the only place the
   version is set; `pyproject.toml` reads it from there.
2. Add a section to `CHANGELOG.md`.
3. Merge that to `main`, then tag the merge commit and push the tag:

   ```bash
   git checkout main && git pull
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. The **Release** workflow then runs the tests, checks that the tag matches
   `__version__`, builds, uploads to PyPI (after your approval if you
   set a reviewer), and creates a GitHub release with the files attached.

PyPI never lets you re-upload the same version, even after deleting it. If something is
wrong after a release, bump to the next patch version (`0.1.1`) and release again.

## If a release run fails

Fix the cause first. If the fix is a change to the repository, merge it, then point the tag
at the new commit and push it again (only safe while that version is not yet on PyPI):

```bash
git checkout main && git pull
git tag -d v0.1.0 && git push --delete origin v0.1.0
git tag v0.1.0 && git push origin v0.1.0
```

If the fix was only on the PyPI side (for example a publisher setting), use
**Re-run failed jobs** on the run instead.
