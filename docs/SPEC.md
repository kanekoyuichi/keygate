# KeyGate Technical Guide

This document consolidates the previous `SPEC.md`, `DETECTION_RULES.md`, and `ARCHITECTURE.md` into a single technical reference.

## Product scope

`keygate` is a local Git pre-commit scanner focused on catching newly added secrets before they land in repository history.

Use `keygate` when you want a fast, offline check that runs at commit time and focuses on staged additions only.

`keygate` is designed to:

- block likely secrets before commit
- keep false positives manageable for day-to-day development
- support practical exceptions through inline ignores, allowlists, and baselines

## Non-goals

`keygate` is intentionally narrow in scope. By default it does not:

- scan the entire repository history
- scan unstaged files
- call external APIs to validate credentials
- use an LLM to decide whether a value is secret
- ship as an IDE plugin (e.g., VS Code extension)

> Note: the Claude Code plugin under `.claude-plugin/` (added in 0.1.8) is a thin wrapper around the existing CLI, exposed as a Skill and slash commands. It calls `keygate scan --profile agent` internally and does not introduce LLM-based detection or a new IDE integration. The detection logic, policies, and exit codes remain identical to the CLI.

## Scan target

The default scan target is:

- added lines from `git diff --cached`

That means `keygate` focuses on what is about to be committed, not everything already present in the repository.

## Commands

```bash
keygate scan
keygate scan --format json
keygate scan --json
keygate scan --profile agent
keygate activate
keygate deactivate
keygate install-hook
keygate uninstall-hook
keygate baseline create
keygate baseline update
```

## Exit codes

- `0`: pass or warn
- `1`: block
- `2`: usage error

## Output modes

The default output is human-readable text. It starts with a summary line:

```text
[KEYGATE] status=block findings=1
```

For automation, use JSON output:

```bash
keygate scan --format json
```

The JSON payload contains a fixed schema version, overall status, a summary object, and structured findings.

## Configuration file

Optional configuration lives in `keygate.toml` at the repository root.

```toml
[scan]
entropy_threshold = 4.2
block_score = 70

[allowlist]
paths = ["vendor/*"]
patterns = ["dummy", "example"]
keywords = ["fixture"]

[baseline]
path = ".keygate.baseline.json"
```

## Detection rules

`keygate` combines multiple signals instead of relying on a single regex. This keeps the default hook fast while avoiding some common false positives.

### Rule-based detections

`keygate` includes dedicated rules for common credential formats:

- AWS access keys
- OpenAI API keys
- GitHub tokens
- Slack tokens
- private keys in PEM format
- JWTs
- Stripe live secret keys
- Stripe live publishable keys
- SendGrid API keys
- URLs with embedded credentials such as `postgres://user:password@host` <!-- keygate: ignore reason="documentation example" -->

Each rule has:

- a stable `rule_id`
- a score
- a `policy`

### Policies

There are two user-visible policy classes:

| Policy | Meaning |
| --- | --- |
| `must_block` | Sensitive by default. A strong match usually reaches block level on its own. |
| `public_exposable` | Public by design or commonly shown in masked examples. Reported as warn-level instead of block-level. |

Examples of `public_exposable` behavior:

- Stripe publishable keys
- masked URL credentials such as `postgres://user:***@host/db` <!-- keygate: ignore reason="documentation example" -->

### Entropy detection

For values that do not match a known rule, `keygate` also looks for random-looking strings using Shannon entropy.

High entropy alone is not enough in many cases. It becomes more useful when paired with context such as:

- variable names like `api_key` or `password`
- assignment syntax such as `NAME=...`
- sensitive file paths such as `.env`

### Context signals

High-level context signals include:

- secret-related keywords
- sensitive file paths
- assignment syntax

These signals help `keygate` distinguish between ordinary text and values that look like secrets being assigned in code or config.

### Scoring and verdicts

All signals are combined into a final score.

- `70+`: `block`
- `40-69`: `warn`
- `<40`: ignored

Some findings are intentionally downgraded in placeholder or documentation-style contexts so examples in files such as `README.md`, `docs/*`, `*.env.example`, or `tests/fixtures/*` do not block commits as aggressively.

### False-positive controls

`keygate` supports three main ways to suppress expected findings:

- inline ignore comments with a required reason
- allowlist path and pattern configuration in `keygate.toml`
- baseline files for existing findings

### Privacy model

`keygate` is designed for local, offline use.

- staged lines are scanned locally
- no external API is used to validate credentials
- baseline entries store fingerprints rather than raw secret values

## Architecture and flow

This section explains the user-visible scanning flow at a high level.

### Scan flow

When you run `keygate scan`, or when the installed Git hook runs it during `git commit`, the flow is:

1. Read staged changes from `git diff --cached`
2. Extract added lines only
3. Apply inline-ignore and allowlist rules
4. Run rule, entropy, and context detection
5. Score each finding as `block`, `warn`, or ignore
6. Filter out findings already covered by the baseline
7. Format the result as text or JSON

### Git hook behavior

`keygate activate` installs a pre-commit hook into the hooks directory Git actually uses. `keygate install-hook` is kept as a compatibility alias.

`keygate deactivate` removes hooks installed by keygate. If the existing hook was not installed by keygate, it asks for confirmation before removal. `keygate uninstall-hook` is kept as a compatibility alias.

The hook runs locally and is intended to be:

- fast enough for normal commit workflows
- offline-friendly
- deterministic for repeated runs on the same staged diff

The generated hook prefers the current Python environment and falls back to `keygate scan` when needed.

### Data files

The main user-facing files are:

- `keygate.toml`: optional configuration
- `.keygate.baseline.json`: stored fingerprints for accepted existing findings

### Output design

Text output is optimized for humans:

- summary line first
- finding details
- remediation guidance
- a JSON rerun hint when a commit is blocked

JSON output is optimized for tools:

- JSON only on stdout
- fixed schema version
- structured summary and findings

### Code layout

If you are navigating the repository, the main implementation lives under `src/keygate/` and tests live under `tests/`.

Important areas include:

- CLI entry points
- diff parsing
- scanner modules for rules, entropy, context, and scoring
- policy modules for allowlist, baseline, and inline ignore
- output formatters for text and JSON

## Public docs

- [`README.md`](../README.md): installation, examples, and day-to-day usage
