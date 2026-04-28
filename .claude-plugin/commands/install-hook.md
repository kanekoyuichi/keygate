---
description: Install keygate as a Git pre-commit hook in the current repository
---

Run `keygate install-hook` in the current repository. This installs a pre-commit hook that runs `keygate scan` on every `git commit`.

Hook behavior:

- Installs into the hooks directory Git actually uses (respects `core.hooksPath` if configured; does not force `.git/hooks`).
- The generated hook embeds the absolute path of the current Python interpreter as a shebang fallback. This means it works correctly when keygate is installed via `pipx`, `uv tool`, or any other isolated environment.
- Falls back to `keygate` on `PATH` if the embedded interpreter is unavailable.

If a `pre-commit` hook already exists, keygate will prompt for overwrite confirmation. Inform the user before running so they can decide.

If `keygate` is not installed, instruct the user to install it via `pipx install keygate`, `uv tool install keygate`, or `pip install --user keygate`.
