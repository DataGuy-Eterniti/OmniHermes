# Changelog

## 1.1.0

Addresses the Hermes plugin-catalog review of 1.0.0 (`fbeeabf`).

- **Gate state is off-limits to the model.** Any tool call naming the plugin data directory or its state files (`unlock_state.json`, `config.json`, `presence_state.json`, `profile.enc`, `.secret_key`) is blocked outright, locked or unlocked, whatever the cwd. The unlock state is HMAC-SHA256-signed with a key derived from the local secret; unsigned, mis-signed, future-dated or over-long states read as locked.
- **Tighter read-only allowlist.** Removed `env`, `printenv`, `time`, `date`, `hostname`. Rejects `$(`, backticks, `<(`, `>(`, redirects, inline `VAR=` prefixes and `&` chaining. Rejects `git -c`, `--config-env`, `--exec-path`, `--output`, `--ext-diff`; `git branch`/`git remote` only when listing.
- **Unlock length comes from config.** `omnihermes_unlock` takes no arguments; the window is `unlock_window_seconds` (clamped 10–3600), read in code from Hermes settings or `config.json`. The success message reports the real duration.
- **Desktop half removed.** `desktop/plugin.js` used APIs Hermes Desktop doesn't provide; removed along with the `desktop:` manifest entry.
- **Owner-only file modes.** Data dir `0700`; `.secret_key`, `profile.enc`, `profile_backup_*.enc`, unlock/presence state and `config.json` written atomically with `0600`.
- **No hard-coded owner.** Names come from the enrolled profile, the `/omnihermes enroll [name]` argument, or the OS user name.
- Model URLs for opencv_zoo pinned to commit `48b10fa505aeb51fbd127fc60a5c660040e823b7` (same SHA-256 checksums).
- Data directory follows the active Hermes profile (`get_hermes_home()`, or `HERMES_HOME`, or the default Hermes home when run from the CLIs), with a one-time copy of a 1.0.0 enrollment.
- Only the two registered tools (`omnihermes_status`, `omnihermes_unlock`) bypass the hook, by exact name.
- New regression suite `tests/test_review_fixes.py` (25 tests; 20 fail on 1.0.0).
