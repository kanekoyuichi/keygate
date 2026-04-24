# Changelog

All notable changes to this project will be documented in this file.

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
