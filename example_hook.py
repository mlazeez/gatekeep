#!/usr/bin/env python3
"""Example gatekeep hook: block any command touching a protected path list.

Reads a JSON object {"command": "..."} on stdin; writes a JSON decision:
{"action": "allow"|"deny"|"modify", "reason": "..."}

Copy to ~/.gatekeep/hooks/ and chmod +x.
"""
import json
import os
import sys

PROTECTED = [os.path.expanduser("~/.ssh"), os.path.expanduser("~/.claude")]


def main():
    payload = json.loads(sys.stdin.read())
    cmd = payload.get("command", "")
    for path in PROTECTED:
        if path in cmd:
            print(json.dumps({"action": "deny",
                              "reason": "protected path %s" % path}))
            return
    print(json.dumps({"action": "allow"}))


if __name__ == "__main__":
    main()