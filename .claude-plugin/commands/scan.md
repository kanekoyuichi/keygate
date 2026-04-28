---
description: Scan staged Git changes for leaked secrets via keygate
---

Use the `keygate-secret-scan` skill to scan staged Git changes (`git diff --cached`) for leaked secrets and report findings.

The skill will:

1. Verify `keygate` is installed (and guide installation if not)
2. Run `keygate scan --profile agent` to get JSON output
3. Interpret the result (`status: pass | warn | block`)
4. Report findings with masked snippets

Trust the skill's output verbatim — `snippet` fields are pre-masked by keygate.
