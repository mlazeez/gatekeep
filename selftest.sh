#!/usr/bin/env bash
# gatekeep self-test: exercises denylist, envelope, snapshot+rollback, breaker.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GK="$DIR/gatekeep"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

echo "== init with test envelope =="
"$GK" init --envelope "$WORK" >/dev/null || bad "init"

echo "== denylist blocks forced push =="
if "$GK" run -- git push --force origin main >/dev/null 2>&1; then
    bad "forced push not denied"
else
    ok "forced push denied"
fi

echo "== envelope blocks outside paths =="
printf 'secret' > /tmp/gk_outside_target.txt
if "$GK" run -- rm -f /tmp/gk_outside_target.txt >/dev/null 2>&1; then
    bad "outside-envelope rm not denied"
else
    ok "outside-envelope rm denied"
fi
rm -f /tmp/gk_outside_target.txt

echo "== destructive command snapshots then rollbacks =="
mkdir -p "$WORK/data"
echo "important" > "$WORK/data/notes.txt"
"$GK" run -- rm "$WORK/data/notes.txt" >/dev/null 2>&1 || bad "rm failed"
[ -f "$WORK/data/notes.txt" ] && bad "file still exists after rm" || ok "file removed"
SNAP=$("$GK" snapshots | awk '{print $1}' | head -1)
[ -n "$SNAP" ] && ok "snapshot exists ($SNAP)" || bad "no snapshot"
"$GK" rollback "$SNAP" >/dev/null 2>&1 || bad "rollback failed"
[ "$(cat "$WORK/data/notes.txt")" = "important" ] && ok "content restored" \
    || bad "content not restored"

echo "== circuit breaker opens after repeated failures =="
"$GK" breaker close >/dev/null
for i in 1 2 3; do
    "$GK" run -- false >/dev/null 2>&1
done
STATE=$("$GK" breaker status | python3 -c "import sys,json;print(json.load(sys.stdin)['state'])")
[ "$STATE" = "OPEN" ] && ok "breaker OPEN after 3 failures" || bad "breaker state=$STATE"
if "$GK" run -- touch "$WORK/newfile" >/dev/null 2>&1; then
    bad "write allowed while breaker OPEN"
else
    ok "write denied while breaker OPEN"
fi
"$GK" run -- ls "$WORK" >/dev/null 2>&1 && ok "read-only allowed while OPEN" || bad "read-only blocked"
"$GK" breaker close >/dev/null
"$GK" run -- touch "$WORK/newfile" >/dev/null 2>&1 && ok "write allowed after close" || bad "write still blocked"

echo
echo "gatekeep self-test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]