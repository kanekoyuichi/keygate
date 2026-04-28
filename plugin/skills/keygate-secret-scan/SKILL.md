---
name: keygate-secret-scan
description: Scan staged Git changes for leaked secrets (API keys, tokens, passwords) before commit. Use when the user is about to commit code, after staging changes, when files contain values that look like credentials, or when the user explicitly asks to check for secrets.
---

# keygate-secret-scan

Detects accidental secret leaks in staged Git changes (`git diff --cached`) before they enter the repository history. Wraps the `keygate` CLI.

## When to use this skill

Trigger this skill in any of these situations:

- The user is about to run `git commit` or has indicated commit intent.
- The user has just staged changes (`git add`) that may contain secrets.
- A code edit just introduced strings that look like API keys, tokens, or passwords (e.g., `sk_live_...`, `AKIA...`, long base64-like values assigned to `api_key` / `password` / `secret` / `token`).
- The user explicitly asks to scan for secrets or run keygate.

Do NOT trigger for:

- General code review unrelated to secrets.
- Unstaged changes (keygate scans the staged diff only).
- Non-Git directories.

## Step 1: Verify keygate is installed

Run:

```bash
keygate --version
```

If it succeeds, proceed to Step 2.

If `keygate` is not found, present these installation options to the user and STOP. Do not attempt to install automatically; let the user choose.

```
keygate is not installed. Install it with one of:

  pipx install keygate         # recommended for pipx users
  uv tool install keygate      # recommended for uv users
  pip install --user keygate   # fallback

Then re-run the scan.
```

## Step 2: Run the scan

Always request JSON output via the agent profile:

```bash
keygate scan --profile agent
```

Output is a fixed-schema JSON document (`schema_version: "1"`).

## Step 3: Interpret the result

Exit codes:

- `0` — `status: "pass"` or `status: "warn"` (commit not blocked).
- `1` — `status: "block"` (commit must be stopped).
- `2` — usage error. Do not retry without fixing arguments.

For each entry in `findings[]`, the relevant fields are:

- `rule_id` — which detection rule fired (e.g., `aws-access-key`).
- `policy` — `must_block`, `should_block`, etc.
- `score` — numeric severity.
- `verdict` — `block` or `warn`.
- `file`, `line` — location.
- `message` — human-readable reason.
- `recommended_action` — e.g., `move_to_secret_manager`.
- `snippet` — pre-masked excerpt (already redacted as `XXXX***YY`, safe to display verbatim).

## Step 4: Report to the user

Format depends on `status`:

- `pass` — One line: "No secrets detected in staged changes."
- `warn` — List each warning as `rule_id` at `file:line` — message. Suggest the user review.
- `block` — Strongly warn:
  1. List every blocked finding with `rule_id`, `file:line`, `message`, and the masked `snippet`.
  2. State that the commit will be blocked by the pre-commit hook (or that the user should not commit).
  3. Recommend rotating the credential if it is a real secret — local files / editor history / clipboard may still hold the unredacted value.
  4. Point at remediation paths (see below).

Never display unmasked secret values. The `snippet` field is already masked by keygate; do not attempt to reconstruct the original.

## Remediation guidance

Recommend in this order:

1. Remove the value from the code; use environment variables, a secret manager, or KMS.
2. For a confirmed false positive on a single line, add `# keygate: ignore reason="..."` on that line.
3. For broader exclusions, edit `keygate.toml`:
   ```toml
   [allowlist]
   paths = ["vendor/*"]
   patterns = ["dummy", "example"]
   ```
4. To accept all currently-detected findings as a starting baseline, run `/keygate:baseline-create`. To extend an existing baseline with newly-detected entries, run `/keygate:baseline-update`.

Never recommend `git commit --no-verify` as a workaround — it defeats the safety net and bypasses every other pre-commit check too.
