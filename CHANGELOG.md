# Changelog

All notable changes to this project will be documented in this file.

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
