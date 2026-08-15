# gatekeep — the agent control surface

A pre-execution gate that sits between an AI agent's proposed command and its
execution. Solves the 2026 agent-production gap: agents are hard to supervise,
hard to roll back, and hard to correct mid-run — because the control surface is
missing.

## Why

- **Rollback checkpoints the agent cannot delete**: every destructive action
  (rm/mv/cp --hard reset, forced push) snapshots its targets into a vault that
  lives *outside* the agent's directory envelope. If the backup fails, the
  action is blocked. The agent has no path to the vault.
- **Pre-execution rules with block authority**: denylist patterns, allowlist
  overrides, envelope enforcement (targets outside the envelope are denied).
- **Executable lifecycle hooks**: any script in `~/.gatekeep/hooks/` receives
  the proposed command and answers `{"action": "allow"|"deny"|"modify"}`.
- **Circuit breaker** (CLOSED/OPEN/HALF_OPEN): after N consecutive command
  failures the agent is restricted to read-only commands — loop containment.
- **Append-only, human-readable audit log**: every proposal, denial, snapshot,
  failure and rollback, timestamped.

## Usage

```bash
./gatekeep init --envelope ~/workspace        # one-time setup
./gatekeep run -- rm -rf ./cache              # snapshot + execute
./gatekeep run -- git push --force origin main  # denied by default rules
./gatekeep snapshots                          # list vault snapshots
./gatekeep rollback 20260815T100000           # restore from snapshot
./gatekeep breaker status                     # CLOSED/OPEN/HALF_OPEN
./gatekeep audit -- 50                        # human-readable log tail
```

### Hooks

```bash
cp example_hook.py ~/.gatekeep/hooks/protect-secrets
chmod +x ~/.gatekeep/hooks/protect-secrets
```

Hooks receive `{"command": "..."}` on stdin and return a typed JSON decision.

## Design notes

- Vault defaults to `~/.gatekeep/vault`, mode 0700, outside any envelope.
- Deny decisions are also written to the audit log, so a human operator can
  review every intervention the agent did and did not make.
- The breaker's HALF_OPEN state auto-closes after 60s, letting a recovered
  agent resume — but only after it has cleared read-only mode.