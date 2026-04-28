---
description: Append only newly-detected findings to the keygate baseline
---

Run `keygate baseline update` in the current repository. This appends only findings that are not already recorded in `.keygate.baseline.json` (deduplicated by fingerprint).

Use this when new findings have appeared (e.g., new code introduced known false positives) and the user has decided to accept them.

The displayed count of added entries equals the number of newly-appended fingerprints. Existing entries are never removed.

After running, suggest the user `git add .keygate.baseline.json` to share the update with the team.

If `keygate` is not installed, instruct the user to install it via `pipx install keygate`, `uv tool install keygate`, or `pip install --user keygate`.
