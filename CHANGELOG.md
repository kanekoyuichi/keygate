# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] - 2026-05-16

### Improvements

- Use neutral "enabled/disabled" wording for hook installation messages
- Improve README with Why keygate, How it works, and comparison with Gitleaks/TruffleHog sections
- Update package description to better reflect the tool's focus

## [0.2.0] - 2026-05-16

### Features

- Add `keygate activate` command as the primary user-facing way to install the Git pre-commit hook
- Add `keygate deactivate` command to remove the installed hook
- Add `keygate uninstall-hook` command as the explicit technical alias for deactivate
- Keep `keygate install-hook` as a backward-compatible alias for activate

### Improvements

- Refactor hook path resolution into a shared `_resolve_hooks_dir()` helper
- Use `try/except FileNotFoundError` in `uninstall()` to eliminate TOCTOU race
- Update README (en/ja/zh) to use `keygate activate` as the primary onboarding command
- Update `docs/SPEC.md` and `docs/SPEC.ja.md` to document the new commands

## [0.1.12] - 2026-04-30

### Fixes

- Restrict GitHub Actions token permissions for CI and PyPI publishing workflows
- Resolve repository root through Git so subdirectory runs use the root config and baseline
- Detect multiple secrets from the same rule on one added line
- Let baselines record and suppress entropy/context-only findings without storing raw secret values
- Require all rule matches on a line to be baselined before suppressing the finding

### Improvements

- Treat allowlist patterns as regular expressions and add case-insensitive keyword allowlists
- Add regression coverage for workflow-reviewed scanner, baseline, allowlist, and repo-root behavior

## [0.1.11] - 2026-04-28

### Fixes

- Move the marketplace description to `metadata.description` so `claude plugin validate .` passes with Claude Code 2.1.116

## [0.1.10] - 2026-04-28

### Improvements

- Consolidate `skills/` and `commands/` under a `plugin/` directory at the repository root, keeping the project root tidy
- Declare the new locations explicitly in `.claude-plugin/plugin.json` via the official `skills` / `commands` custom-path fields

## [0.1.9] - 2026-04-28

### Improvements

- Align Claude Code plugin layout with the official spec: move `skills/` and `commands/` to the plugin root (out of `.claude-plugin/`) so they are auto-discovered without custom path declarations
- Drop the now-unnecessary `skills` and `commands` fields from `.claude-plugin/plugin.json`
- Promote `description` to the top level in `.claude-plugin/marketplace.json` (the `metadata.description` form was a backward-compat fallback)

## [0.1.8] - 2026-04-28

### Features

- Add Claude Code plugin support: install via `/plugin marketplace add kanekoyuichi/keygate` followed by `/plugin install keygate`
- Bundle `keygate-secret-scan` skill that triggers automatically before commits and runs the agent JSON profile
- Add slash commands `/keygate:scan`, `/keygate:install-hook`, `/keygate:baseline-create`, `/keygate:baseline-update`

### Docs

- Document Claude Code plugin usage in all README languages (English / 日本語 / 中文)
- Document `uv tool install keygate` as an installation option alongside `pipx` and `pip --user`

## [0.1.7] - 2026-04-24

### Improvements

- Return a clear user-facing error when `git` is not installed instead of surfacing `FileNotFoundError`
- Add regression coverage for `scan` and `install-hook` behavior when `git` is missing

## [0.1.6] - 2026-04-24

### Features

- Add `keygate --version` to report the current CLI version

### Improvements

- Keep top-level and subcommand help text aligned with the current JSON, baseline, and hook behavior

## [0.1.5] - 2026-04-24

### Features

- Improve CLI help text with clearer command descriptions, JSON output guidance, exit codes, and examples

### Improvements

- Make `baseline create` preserve existing entries and report total/new counts correctly
- Make `baseline update` report only newly added fingerprints
- Install hooks into the Git hooks path actually in use, including `core.hooksPath`
- Generate hooks that prefer the current Python environment and fall back to `keygate scan`
- Add regression coverage for baseline retention, hook installation behavior, and expanded help output

### Docs

- Document `core.hooksPath` support and baseline preservation in the README set
- Consolidate technical docs under `docs/SPEC.md` and add `docs/SPEC.ja.md`

## [0.1.4] - 2026-04-24

### Improvements

- Update package metadata to use SPDX-style `license = "MIT"`
- Remove the deprecated license classifier from `pyproject.toml`
- Eliminate setuptools license deprecation warnings during package builds

## [0.1.3] - 2026-04-24

### Features

- Add structured JSON output for automation with `keygate scan --format json`, `--json`, and `--profile agent`
- Add machine-readable text summary lines and JSON rerun guidance on blocked commits
- Separate scan execution from text and JSON formatters
- Include `Rule.policy` in structured output
- Support `python -m keygate.cli --help`

### Improvements

- Downgrade strong rule matches in placeholder and documentation contexts from `block` to `warn`
- Add regression coverage for placeholder-path and sample-context negatives
- Expand benchmark corpus and document detection metrics in the README set

## [0.1.0] - 2026-04-22

Initial public release on PyPI.

### Features

- Pre-commit hook for detecting secrets in staged diff
- Rule-based detection for AWS / OpenAI / GitHub / Slack / Stripe / SendGrid / JWT / PEM / URL credentials
- Entropy-based detection (Shannon entropy) for high-entropy strings
- Context-based scoring with keyword tiers (HIGH/MID), assignment detection, and sensitive path recognition
- Combo bonus scoring for multi-signal detection
- Rule policy classification (`must_block` / `public_exposable`)
- Exception handling: inline ignore (with required reason), path/pattern allowlist, baseline fingerprinting
- Commands: `keygate scan`, `keygate install-hook`, `keygate baseline create|update`
