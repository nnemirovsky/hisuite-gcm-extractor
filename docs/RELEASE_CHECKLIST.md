# Release checklist

Run every step from a clean checkout. Nothing here publishes anything; the
final step is a deliberate, human decision.

## 1. Decisions that need a human first

- [ ] **GitHub account/organisation.** Replace every `OWNER` placeholder in
      `pyproject.toml`, `README.md`, and `CHANGELOG.md`.
      Check with `grep -rn "OWNER" --exclude-dir=.git .`
- [ ] **Private vulnerability reporting.** `SECURITY.md` points at GitHub's
      advisory form. Turn the feature on in Settings → Security, or the link is
      dead. No email address is published anywhere in this repository.
- [ ] **PyPI name.** `hisuite-gcm` must be free, or the project renamed.
- [ ] **Version.** Confirm `src/hisuite_gcm/_version.py`, the `CHANGELOG.md`
      heading, and the intended git tag agree.

## 2. Quality gates

```sh
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/python tools/privacy_scan.py
```

## 3. Build and inspect the artifacts

```sh
rm -rf dist build
.venv/bin/python -m build
.venv/bin/python -m zipfile -l dist/*.whl
tar -tzf dist/*.tar.gz
```

Read both listings. They must contain no backup data, no `info.xml`, no
`.db`/`.tar` payloads, no absolute paths, and nothing proprietary. The wheel
should carry only `hisuite_gcm/` (including `py.typed`) and metadata.

## 4. Install-from-artifact smoke test

```sh
python3 -m venv /tmp/hisuite-check
/tmp/hisuite-check/bin/pip install dist/*.whl
/tmp/hisuite-check/bin/hisuite-gcm --version
/tmp/hisuite-check/bin/hisuite-gcm --help
```

## 5. Publish (human decision)

Only after everything above:

- [ ] Tag `v<version>` and push the tag.
- [ ] Create the GitHub release with the `CHANGELOG.md` section as its body.
- [ ] Upload to PyPI, if that is wanted, with a scoped API token.

## Repository settings, once the repository exists

These are inert until you run them, and they apply to this repository only.
Everything here is read-only-by-default hygiene: nothing rewrites history or
changes existing content.

```sh
REPO=nnemirovsky/hisuite-gcm-extractor

# Discoverability
gh repo edit "$REPO" \
  --description "Recover authenticated AES-GCM payloads from recent Huawei HiSuite backups" \
  --add-topic huawei --add-topic hisuite --add-topic kobackup \
  --add-topic backup-recovery --add-topic aes-gcm --add-topic forensics --add-topic python

# Merge hygiene: squash only, delete the branch afterwards
gh repo edit "$REPO" --enable-squash-merge --enable-merge-commit=false \
  --enable-rebase-merge=false --delete-branch-on-merge

# Surfaces that are not used yet
gh repo edit "$REPO" --enable-wiki=false --enable-projects=false --enable-issues

# Supply-chain and secret hygiene
gh api -X PUT "repos/$REPO/vulnerability-alerts"
gh api -X PUT "repos/$REPO/automated-security-fixes"
gh api -X PATCH "repos/$REPO" --input - <<'JSON'
{"security_and_analysis": {
  "secret_scanning": {"status": "enabled"},
  "secret_scanning_push_protection": {"status": "enabled"}}}
JSON

# Protect main: pull requests only, no force pushes, CI must pass
gh api -X POST "repos/$REPO/rulesets" --input - <<'JSON'
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
  "rules": [
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 0,
      "dismiss_stale_reviews_on_push": false,
      "require_code_owner_review": false,
      "require_last_push_approval": false,
      "required_review_thread_resolution": false}},
    {"type": "non_fast_forward"},
    {"type": "deletion"},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": true,
      "required_status_checks": [
        {"context": "test (ubuntu-latest, python 3.10)"},
        {"context": "test (ubuntu-latest, python 3.11)"},
        {"context": "test (ubuntu-latest, python 3.12)"},
        {"context": "test (ubuntu-latest, python 3.13)"},
        {"context": "test (macos-latest, python 3.12)"},
        {"context": "test (windows-latest, python 3.12)"},
        {"context": "privacy scan"},
        {"context": "build and inspect artifacts"}]}}
  ]
}
JSON
```

Add the required status checks only after CI has run once on the default
branch, so the context names above are known to GitHub.

Private vulnerability reporting has no API flag; enable it once in
Settings → Security → "Private vulnerability reporting". `SECURITY.md` already
links to the form.
