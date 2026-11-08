# Publish checklist for redbg (for Dan - nothing here has been run)

**Version to release: 0.3.0.** PyPI has 0.1.1 only (0.2.0 was never
uploaded), so users jump 0.1.1 -> 0.3.0. It is not a drop-in upgrade: `check`
is stricter (it now fails empty or unfinished traces, and matches tool names
like `mcp__files__Delete_File`), and redaction catches more. Round 5 only
adds things (new options `--sarif`, `--paths`, `--also`, new commands `otel`
and `digest`) and fixes crashes, so it does not need another number. All of it
is in CHANGELOG.md. The version is already set everywhere (`pyproject.toml`,
`redbg.__version__`, CHANGELOG, and a test pins it); nothing to bump.

The package author is **Calas Automations Inc.** (a test pins that too). The
PyPI page will show it after the upload.

## Check first (10 minutes)

1. The work is on branch `expert-2` (delivered as a git bundle; nothing was
   pushed, so push it yourself). Decide whether to merge it into `main` first:
   GitHub's `main` still holds the very first version, and the PyPI page links
   to `main`.
2. Read `docs/ROUND5.md` "What could not be tested". Windows and macOS were
   never run. Push the branch and look at the **tests** workflow on GitHub
   (Linux, Windows, macOS). If a Windows job is red, fix before releasing.
   Windows has one extra risk this round: the golden-file tests compare exact
   text, and `.gitattributes` is there to keep line endings as LF.
3. In CHANGELOG.md change "0.3.0 - unreleased" to "0.3.0 - " plus the release
   date.
4. The package page will link to github.com/calasdan-sketch/redbg. If that
   repository is private, delete the `Repository`, `Issues` and `Changelog`
   lines under `[project.urls]` in `pyproject.toml` first (this could not be
   checked from the build machine).
5. Make sure the PyPI project `redbg` is yours and that you have a PyPI API
   token. Keep the token out of chats and files.
6. Optional: after the push, upload one SARIF file from
   `redbg check ... --sarif out.sarif` to a test repository's code-scanning
   page. This has not been tried; if GitHub refuses it, tell the next round.

## Build and test the real files (from a fresh copy, not this folder)

```bash
git clone https://github.com/calasdan-sketch/redbg redbg-release
cd redbg-release
git checkout expert-2            # or main, once merged
python -m pip install build twine
python -m build                  # makes dist/redbg-0.3.0*.whl and .tar.gz
twine check dist/*               # both must say PASSED
python -m venv /tmp/clean && /tmp/clean/bin/pip install dist/*.whl
cd "$(mktemp -d)" && /tmp/clean/bin/redbg --version     # redbg 0.3.0
/tmp/clean/bin/redbg demo && /tmp/clean/bin/redbg diff redbg-demo/sample-a.jsonl redbg-demo/sample-b.jsonl
/tmp/clean/bin/redbg digest redbg-demo/sample-a.jsonl   # prints a sha256 line
unzip -p /path/to/redbg-release/dist/redbg-0.3.0-py3-none-any.whl 'redbg-0.3.0.dist-info/METADATA' | grep -E '^(Author|Maintainer)'
```

The last line must show `Calas Automations Inc.` twice. (On Windows use
`py -m venv` and `Scripts\redbg.exe`.) Building from a fresh clone matters:
the old checkout holds a stale `build/` folder that can leak old files into a
wheel.

## Upload (costs nothing; cannot be undone - PyPI never lets you reuse a version)

```bash
twine upload dist/*              # asks for username __token__ and your token
git tag v0.3.0 && git push origin v0.3.0
```

Optional dry run first: `twine upload --repository testpypi dist/*` needs a
separate TestPyPI account and token.

## After release

- In a clean folder: `pip install redbg`, `redbg --version`, `redbg demo`,
  then run the README "Try it" lines and the "Reports for other tools" lines.
  Compare with the README.
- Later (your call): switch to PyPI "trusted publishing" so no token has to
  exist at all (setting on pypi.org plus a GitHub workflow).
