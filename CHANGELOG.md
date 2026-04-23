# Changelog

All notable changes to this project will be documented in this file.

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
