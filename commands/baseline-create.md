---
description: Create or extend the keygate baseline (preserves existing entries)
---

Run `keygate baseline create` in the current repository. This records currently-detected findings into `.keygate.baseline.json` so they are no longer reported on subsequent scans.

Behavior:

- If `.keygate.baseline.json` does not exist, it is created from current findings.
- If it already exists, existing entries are preserved and any new findings are appended (deduplicated by SHA256 fingerprint of `file:line:matched_text`).
- The stored fingerprint never includes the secret value itself, so committing the baseline to Git is safe.

After running, suggest the user `git add .keygate.baseline.json` so the team shares the same set of accepted findings.

If `keygate` is not installed, instruct the user to install it via `pipx install keygate`, `uv tool install keygate`, or `pip install --user keygate`.
