#!/usr/bin/env python3
"""gatekeep — the agent control surface.

Sits between an AI agent's proposed command and its execution:

  * Vault-backed rollback checkpoints the agent cannot delete (vault lives
    outside the agent's directory envelope by construction).
  * Pre-execution rules: denylist/allowlist patterns, destructive-command
    detection with automatic pre-snapshot of every target.
  * Executable hooks with typed decisions (allow / deny / modify).
  * A three-state circuit breaker (CLOSED / OPEN / HALF_OPEN) that restricts
    the agent to read-only commands after repeated failure.
  * Append-only, human-readable audit log.

Zero dependencies, Python 3.8+, stdlib only.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

VERSION = "0.1.0"

GATE_DIR = os.path.join(os.path.expanduser("~"), ".gatekeep")
CONFIG_PATH = os.path.join(GATE_DIR, "config.json")
VAULT_DIR = os.path.join(GATE_DIR, "vault")
AUDIT_PATH = os.path.join(GATE_DIR, "audit.jsonl")
BREAKER_PATH = os.path.join(GATE_DIR, "breaker.json")
HOOKS_DIR = os.path.join(GATE_DIR, "hooks")

DEFAULT_CONFIG = {
    "envelope": [os.path.expanduser("~")],
    "vault": VAULT_DIR,
    "allowlist": [],
    "denylist": [
        r"rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)+.*/",
        r"rm\s+-rf\s+/",
        r"git\s+push\s+(-f|--force)",
        r"git\s+reset\s+--hard\s+[^@]",
        r"shutdown\s+.*-h\s+now",
        r"reboot",
        r"mkfs\.", r"dd\s+.*of=/dev/",
        r":\s*>.*/dev/sd",
        r"curl\s+.*\|.*(sh|bash)",
        r"chmod\s+-R\s+777\s+[/~]",
    ],
    "destructive_patterns": [
        r"rm\s+(-[a-zA-Z]*[fr][a-zA-Z]*\s+)+(\S+)",
        r"mv\s+(\S+)\s+(\S+)",
        r"cp\s+(\S+)\s+(\S+)",
        r"git\s+reset\s+--hard",
        r"git\s+clean\s+(-[a-zA-Z]*[fd][a-zA-Z]*\s+)*",
        r"git\s+push\s+(-f|--force)",
    ],
    "breaker": {"max_failures": 3, "state": "CLOSED", "failures": 0, "since": 0.0},
    "read_only_allowlist": [
        r"^(ls|cat|head|tail|grep|find|git\s+status|git\s+log|git\s+diff|git\s+show|pwd|echo|wc|stat|file|which|python3?\s+[\w./-]+\s+--\S+)",
    ],
}

DESTRUCTIVE_TARGETS = {
    "rm": 1, "unlink": 1, "mv": 2, "cp": 2, "truncate": 1,
    "git": 0, "dd": 0, "shred": 1,
}

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def log(msg):
    print("[gatekeep] %s" % msg, file=sys.stderr)

def fail(msg, code=1):
    log("DENIED: %s" % msg)
    sys.exit(code)

def load_config():
    if not os.path.exists(CONFIG_PATH):
        cfg = dict(DEFAULT_CONFIG)
        cfg["breaker"] = dict(DEFAULT_CONFIG["breaker"])
        save_config(cfg)
        return cfg
    with open(CONFIG_PATH) as fh:
        cfg = json.load(fh)
    for key, val in DEFAULT_CONFIG.items():
        cfg.setdefault(key, val)
    return cfg

def save_config(cfg):
    os.makedirs(GATE_DIR, exist_ok=True)
    os.chmod(GATE_DIR, 0o700)
    with open(CONFIG_PATH, "w") as fh:
        json.dump(cfg, fh, indent=2)

def ensure_dirs(cfg):
    for d in (cfg["vault"], HOOKS_DIR, os.path.join(cfg["vault"], "snapshots"),
              os.path.join(cfg["vault"], "audit")):
        os.makedirs(d, exist_ok=True)
    os.chmod(cfg["vault"], 0o700)

def audit(cfg, entry):
    ensure_dirs(cfg)
    entry.setdefault("ts", now_iso())
    entry.setdefault("pid", os.getpid())
    with open(AUDIT_PATH, "a") as fh:
        fh.write(json.dumps(entry) + "\n")

def load_breaker(cfg):
    if os.path.exists(BREAKER_PATH):
        with open(BREAKER_PATH) as fh:
            return json.load(fh)
    return dict(cfg["breaker"])

def save_breaker(cfg, b):
    with open(BREAKER_PATH, "w") as fh:
        json.dump(b, fh, indent=2)

def cmd_matches(cmd, patterns):
    for pat in patterns:
        if re.search(pat, cmd):
            return pat
    return None

def classify_targets(cmd):
    """Return absolute file paths a command will destroy/overwrite."""
    parts = cmd.split()
    if not parts:
        return []
    base = os.path.basename(parts[0])
    targets = []
    if base in ("rm", "unlink", "shred", "truncate"):
        i = 1
        while i < len(parts) and parts[i].startswith("-"):
            i += 1
        targets = parts[i:]
    elif base in ("mv", "cp") and "--" not in parts[1:2]:
        i = 1
        while i < len(parts) and parts[i].startswith("-"):
            i += 1
        rest = parts[i:]
        if len(rest) >= 2:
            targets = rest[:-1] + [rest[-1]]
    elif base == "git":
        if "reset" in parts and "--hard" in parts:
            targets = ["."]
        elif "clean" in parts and any(p.startswith("-") and "f" in p for p in parts[1:3]):
            targets = ["."]
        elif "push" in parts and any(p in ("-f", "--force") for p in parts):
            targets = [".git"]
    return [os.path.realpath(t) for t in targets if t and not t.startswith("-")]

def snapshot_paths(cfg, paths):
    """Copy every target into the vault before destruction. Agent-unreachable."""
    ts = time.strftime("%Y%m%dT%H%M%S")
    snap_dir = os.path.join(cfg["vault"], "snapshots", ts)
    os.makedirs(snap_dir, exist_ok=True)
    manifest = []
    for p in paths:
        real = os.path.realpath(p)
        if not os.path.exists(real):
            continue
        if os.path.isdir(real):
            shutil.copytree(real, os.path.join(snap_dir, "dir_" + re.sub(r"[^A-Za-z0-9_.-]", "_", real[1:])),
                            symlinks=True)
        else:
            shutil.copy2(real, os.path.join(snap_dir, "file_" + re.sub(r"[^A-Za-z0-9_.-]", "_", real[1:])))
        h = sha256_file(real) if os.path.isfile(real) else None
        manifest.append({"path": real, "sha256": h})
    os.chmod(snap_dir, 0o700)
    with open(os.path.join(snap_dir, "manifest.json"), "w") as fh:
        json.dump({"created": now_iso(), "files": manifest}, fh, indent=2)
    return ts, snap_dir

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def run_hooks(cfg, cmd):
    """Executable hooks: each receives {command} on stdin, returns a JSON
    decision: {"action": "allow"|"deny"|"modify", "command": "...", "reason": "..."}."""
    if not os.path.isdir(HOOKS_DIR):
        return cmd
    for entry in sorted(os.listdir(HOOKS_DIR)):
        path = os.path.join(HOOKS_DIR, entry)
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        try:
            proc = subprocess.run([path], input=json.dumps({"command": cmd}),
                                  capture_output=True, text=True, timeout=10)
            decision = json.loads(proc.stdout.strip().splitlines()[-1]) if proc.stdout.strip() else {}
        except Exception as exc:
            audit(cfg, {"event": "hook_error", "hook": entry, "error": str(exc)})
            continue
        action = decision.get("action")
        if action == "deny":
            audit(cfg, {"event": "hook_deny", "hook": entry, "command": cmd,
                        "reason": decision.get("reason", "")})
            fail("hook %s: %s" % (entry, decision.get("reason", "no reason")))
        elif action == "modify" and decision.get("command"):
            log("hook %s modified command" % entry)
            audit(cfg, {"event": "hook_modify", "hook": entry, "command": cmd,
                        "modified": decision["command"]})
            cmd = decision["command"]
    return cmd

def breaker_state(cfg):
    b = load_breaker(cfg)
    if b["state"] == "HALF_OPEN" and time.time() - b.get("since", 0) > 60:
        b["state"] = "CLOSED"
        b["failures"] = 0
        save_breaker(cfg, b)
    return b

def record_failure(cfg, b, cmd, exitcode):
    b["failures"] += 1
    if b["failures"] >= cfg["breaker"]["max_failures"]:
        b["state"] = "OPEN"
        b["since"] = time.time()
    save_breaker(cfg, b)
    audit(cfg, {"event": "cmd_failed", "command": cmd, "exit": exitcode,
                "breaker": b["state"], "failures": b["failures"]})

def record_success(cfg, b, cmd):
    if b["failures"] > 0:
        b["failures"] = 0
        save_breaker(cfg, b)
    audit(cfg, {"event": "cmd_ok", "command": cmd, "breaker": b["state"]})

def in_envelope(cfg, path):
    real = os.path.realpath(path)
    return any(real.startswith(os.path.realpath(e)) for e in cfg["envelope"])

def cmd_gatekeep(argv):
    if len(argv) < 1:
        print(__doc__)
        sys.exit(0)
    cmd = " ".join(argv)
    cfg = load_config()
    ensure_dirs(cfg)

    audit(cfg, {"event": "cmd_proposed", "command": cmd})

    denied = cmd_matches(cmd, cfg["denylist"])
    if denied:
        audit(cfg, {"event": "rule_deny", "command": cmd, "rule": denied})
        fail("matches denylist rule %r" % denied)

    allowed = cmd_matches(cmd, cfg["allowlist"])
    if not allowed:
        b = breaker_state(cfg)
        if b["state"] == "OPEN":
            read_only = cmd_matches(cmd, cfg["read_only_allowlist"])
            if not read_only:
                audit(cfg, {"event": "breaker_deny", "command": cmd})
                fail("circuit breaker OPEN (read-only mode) — run "
                     "'gatekeep breaker close' to reset")
            log("circuit breaker OPEN: read-only command permitted")

    cmd = run_hooks(cfg, cmd)

    targets = [t for t in classify_targets(cmd) if os.path.exists(t)]
    snap_id = None
    if targets:
        outside = [t for t in targets if not in_envelope(cfg, t)]
        if outside:
            audit(cfg, {"event": "envelope_deny", "command": cmd, "targets": outside})
            fail("targets outside envelope: %s" % ", ".join(outside))
        snap_id, snap_dir = snapshot_paths(cfg, targets)
        audit(cfg, {"event": "snapshot", "snapshot": snap_id,
                    "files": [os.path.basename(t) for t in targets]})
        log("snapshot %s created (%d target%s) in vault" %
            (snap_id, len(targets), "s" if len(targets) != 1 else ""))

    log("executing: %s" % cmd)
    proc = subprocess.run(cmd, shell=True)
    if proc.returncode != 0:
        b = load_breaker(cfg)
        record_failure(cfg, b, cmd, proc.returncode)
        log("command failed (exit %d); snapshot %s kept for rollback" %
            (proc.returncode, snap_id or "-"))
    else:
        b = load_breaker(cfg)
        record_success(cfg, b, cmd)
    sys.exit(proc.returncode)

def cmd_rollback(snap_id):
    cfg = load_config()
    snap_dir = os.path.join(cfg["vault"], "snapshots", snap_id)
    if not os.path.isdir(snap_dir):
        fail("no snapshot %r" % snap_id)
    manifest_path = os.path.join(snap_dir, "manifest.json")
    with open(manifest_path) as fh:
        manifest = json.load(fh)
    restored = 0
    for entry in manifest["files"]:
        p = entry["path"]
        name = os.path.basename(p)
        candidates = [os.path.join(snap_dir, c) for c in os.listdir(snap_dir)
                      if c.startswith(("file_", "dir_")) and name in c]
        if not candidates:
            continue
        src = candidates[0]
        if os.path.isdir(src):
            shutil.copytree(src, p, dirs_exist_ok=True, symlinks=True)
        else:
            shutil.copy2(src, p)
        restored += 1
    audit(cfg, {"event": "rollback", "snapshot": snap_id, "restored": restored})
    log("restored %d path(s) from snapshot %s" % (restored, snap_id))

def cmd_snapshots():
    cfg = load_config()
    base = os.path.join(cfg["vault"], "snapshots")
    if not os.path.isdir(base):
        return
    for name in sorted(os.listdir(base), reverse=True):
        mp = os.path.join(base, name, "manifest.json")
        if os.path.exists(mp):
            with open(mp) as fh:
                m = json.load(fh)
            print("%s  %s  %d file(s)" % (name, m.get("created", "?"),
                                          len(m.get("files", []))))

def cmd_breaker(action):
    cfg = load_config()
    b = load_breaker(cfg)
    if action == "status":
        print(json.dumps(b, indent=2))
    elif action == "trip":
        b["state"] = "OPEN"
        b["since"] = time.time()
        save_breaker(cfg, b)
        print("breaker OPEN")
    elif action == "close":
        b["state"] = "CLOSED"
        b["failures"] = 0
        save_breaker(cfg, b)
        print("breaker CLOSED")
    elif action == "half":
        b["state"] = "HALF_OPEN"
        b["since"] = time.time()
        save_breaker(cfg, b)
        print("breaker HALF_OPEN")
    else:
        print("usage: gatekeep breaker status|trip|close|half")

def cmd_audit(tail=20):
    if not os.path.exists(AUDIT_PATH):
        print("no audit log yet")
        return
    with open(AUDIT_PATH) as fh:
        lines = fh.readlines()
    for line in lines[-tail:]:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        print("%s  %-14s %s" % (entry.get("ts", "?"), entry.get("event", "?"),
                                entry.get("command", entry.get("reason", ""))))

def cmd_init(extra):
    cfg = load_config()
    envelope = None
    i = 0
    while i < len(extra):
        if extra[i] in ("--envelope", "-e"):
            envelope = os.path.realpath(extra[i + 1]); i += 2
        else:
            i += 1
    if envelope:
        cfg["envelope"] = [envelope]
        save_config(cfg)
    ensure_dirs(cfg)
    os.makedirs(HOOKS_DIR, exist_ok=True)
    print("gatekeep initialized")
    print("  config   : %s" % CONFIG_PATH)
    print("  envelope : %s" % ", ".join(cfg["envelope"]))
    print("  vault    : %s   (agent-unreachable by envelope policy)" % cfg["vault"])
    print("  hooks    : %s" % HOOKS_DIR)
    print("  breaker  : %s (max %d failures)" % (cfg["breaker"]["state"],
                                                 cfg["breaker"]["max_failures"]))

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    sub = sys.argv[1]
    rest = sys.argv[2:]
    if sub == "init":
        cmd_init(rest)
    elif sub == "run":
        if not rest:
            fail("gatekeep run -- <command>")
        if rest[0] == "--":
            rest = rest[1:]
        if not rest:
            fail("gatekeep run -- <command>")
        cmd_gatekeep(rest)
    elif sub == "rollback":
        if not rest:
            fail("usage: gatekeep rollback <snapshot-id>")
        cmd_rollback(rest[0])
    elif sub == "snapshots":
        cmd_snapshots()
    elif sub == "breaker":
        cmd_breaker(rest[0] if rest else "status")
    elif sub == "audit":
        cmd_audit(int(rest[0]) if rest and rest[0].isdigit() else 20)
    elif sub in ("--version", "-V"):
        print("gatekeep %s" % VERSION)
    else:
        fail("unknown subcommand %r" % sub)

if __name__ == "__main__":
    main()