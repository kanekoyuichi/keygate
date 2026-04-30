# keygate

[![PyPI version](https://img.shields.io/pypi/v/keygate.svg)](https://pypi.org/project/keygate/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

A Git pre-commit hook that **prevents accidental commits of API keys and passwords**.

[日本語](https://github.com/kanekoyuichi/keygate/blob/main/README.ja.md) | [中文](https://github.com/kanekoyuichi/keygate/blob/main/README.zh.md)

---

## Why you need this

During development, it's easy to write API keys or passwords directly in code. Once committed with `git commit`, they become permanently embedded in the repository history.

Even if you delete them later, they remain accessible from past commits — and once exposed on GitHub or similar platforms, they can be exploited almost immediately. There are countless cases of AWS key leaks resulting in massive unexpected bills.

`keygate` **automatically checks before every commit** and blocks anything that looks dangerous.

---

## What it detects

- AWS Access Keys
- OpenAI API Keys
- GitHub Tokens
- Slack Tokens
- Private Keys (PEM format)
- JWT Tokens
- Long random-looking strings (high-entropy detection)
- Variable names like `api_key`, `password`, `secret` paired with values

---

## Getting started

### Step 1: Install

`keygate` is a Python CLI tool. The easiest way to install it is via `pipx`.

```bash
pipx install keygate
```

> If you don't have `pipx`, install it with `pip install pipx`.
> Using `pipx` makes the `keygate` command available from any project directory.

### Step 2: Enable the hook

A "hook" is a script Git runs automatically at certain points. Running `keygate install-hook` makes `keygate` run automatically on every `git commit`.

```bash
cd path/to/your-project
keygate install-hook
```

`install-hook` writes to the hooks directory Git actually uses. If your repo has `core.hooksPath` configured, keygate installs the hook there instead of forcing `.git/hooks`.

The generated hook prefers the current Python environment (`python -m keygate.cli scan`) and falls back to `keygate scan`, which makes it more reliable on systems where the hook PATH is limited.

That's all the setup you need.

### Step 3: Use it

Just run `git add` and `git commit` as usual. If nothing dangerous is found, nothing happens.

If a secret is detected, the commit is blocked like this:

```text
[BLOCK] High confidence secret detected

File: config.py:12
Rule: aws-access-key
Score: 100

Reason:
AWS Access Key detected; sensitive context detected

Remediation:
  - Remove the key from the code
  - Rotate the AWS credentials immediately
  - Use environment variables or AWS IAM roles instead

To ignore:
  Add comment: # keygate: ignore reason="..."
```

**How to read the output:**
- `File: config.py:12` — the file and line number where the issue was found
- `Rule: aws-access-key` — what was detected
- `Score: 100` — severity (70+ blocks the commit; 40–69 warns only)
- `Reason` — why it was flagged
- `Remediation` — suggested fixes

### Step 4: Update

If you installed `keygate` with `pipx`, upgrade it like this:

```bash
pipx upgrade keygate
```

If you installed it with `pip`, use:

```bash
python -m pip install -U keygate
```

---

## Use with Claude Code (plugin)

`keygate` is also available as a [Claude Code](https://docs.claude.com/en/docs/claude-code) plugin. With it installed, Claude can scan staged changes for secrets automatically before you commit, and you can run keygate operations from Claude Code as slash commands.

### Step 1: Install the keygate CLI

The plugin wraps the CLI, so the CLI must be installed first. Pick one:

```bash
pipx install keygate          # if you use pipx
uv tool install keygate       # if you use uv
pip install --user keygate    # fallback
```

### Step 2: Add the marketplace and install the plugin

In Claude Code:

```
/plugin marketplace add kanekoyuichi/keygate
/plugin install keygate
```

### What you get

- **Skill `keygate-secret-scan`** — Claude triggers this automatically before commits or when staged changes contain credential-like values. It runs `keygate scan --profile agent`, parses the JSON output, and reports findings with masked snippets.
- **Slash commands**:
  - `/keygate:scan` — scan staged changes on demand
  - `/keygate:install-hook` — install the Git pre-commit hook
  - `/keygate:baseline-create` — record current findings as accepted
  - `/keygate:baseline-update` — append newly-detected findings

The plugin uses keygate's agent JSON profile (`schema_version: "1"`) internally, so detection logic and policies are identical to the CLI.

---

## Manual scan

You can also scan without using the hook.

```bash
git add .
keygate scan
```

This scans `git diff --cached` (staged changes only).

### JSON output for AI agents and automation

By default, `keygate scan` prints human-readable text. For AI agents or scripts that need to parse the result, use JSON output:

```bash
keygate scan --format json    # JSON only on stdout
keygate scan --json           # alias for --format json
keygate scan --profile agent  # forces JSON, no human prose
```

Default text output starts with a machine-readable summary line so simple tools can also pick up the status:

```text
[KEYGATE] status=block findings=1
```

When a commit is blocked, the text output also points to the JSON command so an agent can re-run and parse the result. The JSON payload follows a fixed schema (`schema_version: "1"`) with `status`, `summary`, and `findings[]` (including `rule_id`, `policy`, `score`, `verdict`, `file`, `line`, `message`, and a masked `snippet` when available).

Exit codes are unchanged: `0` for pass/warn, `1` for block, `2` for usage errors (such as combining `--format text` with `--json`).

---

## Handling false positives

`keygate` errs on the side of caution, so it may occasionally flag things that aren't real secrets. There are three ways to deal with this.

### Option 1: Inline ignore comment

Suppresses detection for that specific line. A reason is required.

```python
api_key = "dummy-key-for-testing"  # keygate: ignore reason="test data"
```

### Option 2: Allowlist paths or patterns

Create a `keygate.toml` file in your project root and specify paths or patterns to exclude.

```toml
[allowlist]
paths = ["vendor/*", "third_party/*"]  # ignore code you don't own
patterns = ["dummy", "example"]         # regex patterns for lines to ignore
keywords = ["fixture"]                  # case-insensitive keywords for lines to ignore
```

> Note: Adding `tests/*` to the allowlist globally will cause keygate to miss real secrets embedded in test code. Use option 1 (inline ignore) or option 3 (baseline) for false positives in tests.

### Option 3: Baseline — register existing findings to ignore

Useful when you only want to catch newly added secrets, not existing ones.

```bash
keygate baseline create
```

The current findings are saved to `.keygate.baseline.json`. From that point on, the same findings are ignored. The file looks like this:

```json
{
  "version": 1,
  "entries": [
    {
      "fingerprint": "e5282a7860678bc768d280eb3e77d2ca8a44286357c743dd024d74fe0605fe09",
      "file_path": "src/app/config.py",
      "line_number": 42,
      "rule_id": "url-credentials",
      "created_at": "2026-04-22T09:30:00+00:00"
    }
  ]
}
```

The `fingerprint` is a SHA256 hash of `file_path` + `line_number` + matched string. The actual secret value is never stored, so committing the baseline file to Git is safe.

If `.keygate.baseline.json` already exists, `keygate baseline create` preserves existing entries and adds newly detected findings on top. Re-running it will not silently discard your current baseline.

To add newly discovered findings to the baseline:

```bash
keygate baseline update
```

#### Sharing with your team

We recommend committing `.keygate.baseline.json` to Git so the whole team uses the same ignore list.

```bash
git add .keygate.baseline.json
git commit -m "Add keygate baseline"
```

New team members only need to run `pipx install keygate` and `keygate install-hook` — the shared baseline is picked up automatically.

---

## Configuration (optional)

The defaults work well out of the box, but you can customize behavior by creating `keygate.toml` in your project root.

```toml
[scan]
entropy_threshold = 4.2    # threshold for random-looking strings (lower = stricter)
block_score = 70           # commits are blocked at this score or above

[allowlist]
paths = ["vendor/*"]
patterns = ["dummy", "example"]
keywords = ["fixture"]

[baseline]
path = ".keygate.baseline.json"
```

If no config file is present, defaults are used.

---

## FAQ

**Q. I accidentally committed a secret. What should I do?**

A. Revoke (rotate) the key immediately. Removing it from Git history is not enough. Assume any leaked key has already reached an attacker.

**Q. How do I temporarily disable the hook?**

A. Use `git commit --no-verify` to skip all hooks including keygate. Not recommended for regular use.

**Q. How do we share this across a team?**

A. Commit `keygate.toml` and `.keygate.baseline.json` to Git. Each team member needs to run `keygate install-hook` individually.

**Q. How do I update keygate?**

A. If you installed it with `pipx`, run `pipx upgrade keygate`. If you installed it with `pip`, run `python -m pip install -U keygate`.

---

## Detection accuracy

Measured against a labeled corpus of 100 samples (50 known secrets, 50 benign strings).

| Metric    | Value |
|-----------|-------|
| Recall    | 100.0% |
| Precision | 80.6%  |
| F1        | 89.3%  |
| True Positive | 50 |
| False Negative | 0 |
| False Positive | 12 |
| True Negative | 38 |

**Recall 100.0%** means every known secret in the corpus was detected (BLOCK or WARN). In other words, the benchmark had zero missed secrets.

**Precision 80.6%** reflects 12 false positives. These include masked URL credentials, placeholders, Stripe publishable keys, and empty values such as `API_KEY=`. They are not always real secrets, but they look close enough to secret-like values that `keygate` reports them before commit so you can review them.

The corpus and thresholds are enforced as a regression test. To re-run:

```bash
python -m tests.benchmark.benchmark
```

---

## Disclaimer

`keygate` is a best-effort detection tool. Please understand the following before use.

- **Detection is not guaranteed**: Unknown secret formats, obfuscated values, or custom formats may not be detected (false negatives).
- **False positives can occur**: Non-secret strings may be flagged. Use allowlist / baseline / inline ignore to address them.
- **Not a replacement for proper secret management**: This tool is an additional safeguard at commit time. Secrets should be managed via environment variables, secret managers, or KMS — never stored in the repository.
- **Hooks can be bypassed**: `git commit --no-verify` skips all hooks. For organizational enforcement, combine with server-side checks (pre-receive hooks, CI scanning, etc.).
- **You are responsible for any leaks caused by missed detections**: The authors and contributors accept no liability for damages arising from use of this tool (see [LICENSE](LICENSE) for details).
- **If a secret is detected, rotate the key promptly**: Even if the commit was blocked, the value may remain in local files, editor history, clipboard, or other devices.

This tool is designed as a last-resort safety net to catch human mistakes — not as a substitute for doing secret management correctly.

---

## License

Distributed under the [MIT License](LICENSE). Free to use, modify, and redistribute, including for commercial use. See [LICENSE](LICENSE) for details.
