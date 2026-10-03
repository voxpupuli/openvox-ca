#!/bin/bash
# Regression suite for test/failure-log.sh.
#
# The helper exists so that a container-suite failure leaves behind the
# evidence needed to explain it (issue #281).  Before it, both compose
# harnesses dumped a *tail*, and the services that matter -- the CA replicas
# with `restart: on-failure` -- restart-loop, so their log is several
# concatenated start attempts and the tail holds only the last futile ones.
# Twice in one day a CI failure was reported as 200 identical lines of a
# replica waiting for Redis, with the Go process's own error nowhere in it.
#
# That is what this suite pins, and the first assertion below is the whole
# point: a fixture whose reason appears *only* in the first attempt, in a log
# longer than the tail depth, so no tail can reach it.  Revert
# failure_log_dump to `logs --tail "$FAILURE_LOG_TAIL"` and that assertion
# fails because the marker is absent -- which is the only way to tell a dump
# that fixed the bug from one that merely prints more.
#
# The compose command is a stub, not a container: what is under test is shell
# and awk text handling.  The stub honours `--tail` faithfully, so an
# implementation that reintroduced a bounded fetch would truncate its own
# fixture and fail here rather than passing on a stub that ignored the flag.
#
# Usage (from project root):
#   bash test/failure-log-test.sh
#
# Output: TAP.  Exit 0 when all pass, 1 if any fail.

set -uo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=test/failure-log.sh
. "$_here/failure-log.sh"

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/failure-log-test.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT

# -- TAP helpers (same shape as migration-test.sh) ----------------------------
T=0
FAILURES=0

pass() {
    T=$(( T + 1 ))
    printf 'ok %d - %s\n' "$T" "$1"
}

fail() {
    T=$(( T + 1 ))
    FAILURES=$(( FAILURES + 1 ))
    printf 'not ok %d - %s\n' "$T" "$1"
    [ -n "${2:-}" ] && printf '  # %s\n' "$2"
    return 0
}

# ok_eq DESC EXPECTED ACTUAL
ok_eq() {
    [ "$2" = "$3" ] && pass "$1" || fail "$1" "expected [$2], got [$3]"
}

# ok_contains DESC NEEDLE HAYSTACK
ok_contains() {
    case "$3" in
        *"$2"*) pass "$1" ;;
        *)      fail "$1" "output does not contain [$2]" ;;
    esac
}

# ok_lacks DESC NEEDLE HAYSTACK
ok_lacks() {
    case "$3" in
        *"$2"*) fail "$1" "output unexpectedly contains [$2]" ;;
        *)      pass "$1" ;;
    esac
}

# -- The stub compose command -------------------------------------------------
# Emulates the one invocation failure_log_dump makes:
#
#   <cmd> -f <file> logs [--tail N] <service>
#
# It serves $WORK_DIR/logs/<service>.log, honours --tail exactly as `compose
# logs` does (newest N lines), records its own argv for inspection, and
# optionally writes a line on *stderr* -- which is where podman replays a
# container's own stderr, and therefore where a Go service's abort
# diagnostics arrive.
COMPOSE_STUB="$WORK_DIR/fake-compose"
mkdir -p "$WORK_DIR/logs"

cat > "$COMPOSE_STUB" <<'STUB'
#!/bin/bash
# Stub `compose`; see the header of test/failure-log-test.sh.
set -u
printf '%s\n' "$*" >> "$FAKE_COMPOSE_ARGV"

_tail=''
_svc=''
_seen_logs=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        logs)   _seen_logs=true ;;
        --tail) shift; _tail="$1" ;;
        -f)     shift ;;
        -*)     ;;
        *)      $_seen_logs && _svc="$1" ;;
    esac
    shift
done

[ -n "${FAKE_COMPOSE_STDERR:-}" ] && printf '%s\n' "$FAKE_COMPOSE_STDERR" >&2

_log="$FAKE_COMPOSE_LOGS/$_svc.log"
[ -r "$_log" ] || exit 0
if [ -n "$_tail" ]; then
    tail -n "$_tail" "$_log"
else
    cat "$_log"
fi
STUB
chmod +x "$COMPOSE_STUB"

export FAKE_COMPOSE_LOGS="$WORK_DIR/logs"
export FAKE_COMPOSE_ARGV="$WORK_DIR/argv"
export FAKE_COMPOSE_STDERR=''

# dump SERVICE -- run the real helper against the stub, capturing both streams
# the way a harness's `>&2` redirection would present them to an operator.
dump() {
    : > "$FAKE_COMPOSE_ARGV"
    failure_log_dump "$1" "$COMPOSE_STUB" -f test/compose-backends-redis.yml 2>&1
}

# -- Fixture: a CA replica in a restart loop ----------------------------------
# Shaped after the real thing.  The reason the replica died appears in the
# first attempt and nowhere else; every later attempt is the same three lines
# of a replica waiting on dependencies it will never get past.  81 attempts,
# 244 lines: comfortably longer than FAILURE_LOG_TAIL, so the marker sits far
# outside any tail's reach.
REASON='FATAL: bootstrap aborted: acquiring CA lock: redis: connection pool timeout'
RESTART_ATTEMPTS=81

{
    printf 'openvox-ca-1  | Waiting for Redis at redis:6379...\n'
    printf 'openvox-ca-1  | Redis is reachable.\n'
    printf 'openvox-ca-1  | Phase 1: bootstrapping CA on loopback to generate TLS cert...\n'
    printf 'openvox-ca-1  | %s\n' "$REASON"
    for _i in $(seq 2 "$RESTART_ATTEMPTS"); do
        printf 'openvox-ca-1  | Waiting for Redis at redis:6379...\n'
        printf 'openvox-ca-1  | Redis is reachable.\n'
        printf 'openvox-ca-1  | Waiting for loopback CA...\n'
    done
} > "$WORK_DIR/logs/openvox-ca.log"

LOOP_LINES=$(awk 'END { print NR }' "$WORK_DIR/logs/openvox-ca.log")

# The fixture is only worth anything if a tail genuinely cannot reach the
# reason.  Assert that against the fixture itself before asserting anything
# about the helper: if these two ever coincided, every test below would pass
# whether or not the helper worked.
_reason_line=$(grep -n -F -- "$REASON" "$WORK_DIR/logs/openvox-ca.log" | cut -d: -f1)
if [ "$_reason_line" -le $(( LOOP_LINES - FAILURE_LOG_TAIL )) ]; then
    pass "fixture: the reason is out of reach of a ${FAILURE_LOG_TAIL}-line tail (line $_reason_line of $LOOP_LINES)"
else
    fail "fixture: the reason is out of reach of a ${FAILURE_LOG_TAIL}-line tail" \
        "reason at line $_reason_line of $LOOP_LINES; a tail of $FAILURE_LOG_TAIL reaches it, so this suite would prove nothing"
fi

# ═════════════════════════════════════════════════════════════════════════════
# The restart loop: what issue #281 is about
# ═════════════════════════════════════════════════════════════════════════════
OUT=$(dump openvox-ca)

# THE assertion.  Reverting failure_log_dump to a plain tail fails here, and
# fails for this reason: the marker is absent from the output.
ok_contains "the first attempt's reason survives a restart loop" "$REASON" "$OUT"

ok_contains "the dump says which attempt it is showing, and how many there are" \
    "(start attempt 1 of $RESTART_ATTEMPTS)" "$OUT"

# The first-attempt view must stop at the attempt boundary rather than running
# on into the identical attempts behind it -- otherwise "first attempt" is
# just a differently-worded head.
_first_block=$(printf '%s\n' "$OUT" | sed -n '/^# ---- first /,/^# ---- last /p' | sed '1d;$d')
ok_eq "the first-attempt view stops at the second attempt's first line" \
    "4" "$(printf '%s\n' "$_first_block" | awk 'END { print NR }')"
# Positive, not "does not contain a line from attempt 2": an empty block would
# satisfy that and satisfy it most convincingly when the view is missing
# altogether, which is the failure this suite exists to catch.
ok_contains "the first-attempt view ends on the line that explains the failure" \
    "$REASON" "$(printf '%s\n' "$_first_block" | tail -n 1)"

# The tail is still shown: a service that failed late without restarting keeps
# its reason at the end, and dropping the tail would trade one blind spot for
# another.
ok_contains "a tail is still shown beneath the first attempt" \
    "# ---- last $FAILURE_LOG_TAIL of $LOOP_LINES log lines from openvox-ca ----" "$OUT"

# The fetch must be unbounded.  The stub honours --tail, so a bounded fetch
# would already have failed the assertions above; this says so directly, and
# names the flag, so the failure is self-explaining rather than mysterious.
ok_lacks "the log is fetched unbounded, not through --tail" \
    "--tail" "$(cat "$FAKE_COMPOSE_ARGV")"

# ═════════════════════════════════════════════════════════════════════════════
# The other shape of failure: one attempt, dying late
# ═════════════════════════════════════════════════════════════════════════════
LATE_REASON='FATAL: signing CSR for puppet-master: certificate already revoked'
{
    printf 'puppet-master-1  | OpenVox Server starting up\n'
    for _i in $(seq 2 150); do
        printf 'puppet-master-1  | serving catalog request %d\n' "$_i"
    done
    printf 'puppet-master-1  | %s\n' "$LATE_REASON"
} > "$WORK_DIR/logs/puppet-master.log"

LATE_LINES=$(awk 'END { print NR }' "$WORK_DIR/logs/puppet-master.log")

OUT=$(dump puppet-master)
ok_contains "a single-attempt log is reported as one attempt" \
    "(start attempt 1 of 1)" "$OUT"
ok_contains "a late failure's reason is still reachable through the tail" \
    "$LATE_REASON" "$OUT"

# This log is longer than FAILURE_LOG_HEAD, so the head view is clamped.  Pin
# the headcount and the truncation banner, not just their presence: an
# operator triaging a restart loop reads those two numbers to know how much
# was cut, and clamp arithmetic that drifted would still print a plausible
# line.  Derived from the constant rather than written out, so the assertion
# says what the relationship is and survives a change of depth.
ok_contains "a clamped head view reports how much of the log it is showing" \
    "# ---- first $FAILURE_LOG_HEAD of $LATE_LINES log lines from puppet-master (start attempt 1 of 1) ----" \
    "$OUT"
ok_contains "a clamped head view says how much of the attempt it cut" \
    "# ---- ($(( LATE_LINES - FAILURE_LOG_HEAD )) more lines of attempt 1 not shown) ----" \
    "$OUT"

# ═════════════════════════════════════════════════════════════════════════════
# A restart loop whose first attempt is itself longer than the clamp
# ═════════════════════════════════════════════════════════════════════════════
# Both bounds bite at once here, which is what separates them: the remainder
# must be counted against the end of *attempt 1*, not the end of the log.  In
# the fixture above the two coincide, so `last - shown` and `NR - shown` would
# both look right; here they differ, and only one of them is.
SLOW_BANNER='openvox-ca-1  | Waiting for Redis at redis:6379...'
SLOW_ATTEMPT_LINES=130
{
    printf '%s\n' "$SLOW_BANNER"
    for _i in $(seq 2 "$SLOW_ATTEMPT_LINES"); do
        printf 'openvox-ca-1  | bootstrap step %d of a slow first attempt\n' "$_i"
    done
    for _a in 2 3; do
        printf '%s\n' "$SLOW_BANNER"
        printf 'openvox-ca-1  | Redis is reachable.\n'
        printf 'openvox-ca-1  | Waiting for loopback CA...\n'
    done
} > "$WORK_DIR/logs/slow-ca.log"

SLOW_LINES=$(awk 'END { print NR }' "$WORK_DIR/logs/slow-ca.log")

OUT=$(dump slow-ca)
ok_contains "a clamped first attempt still reports the attempt count" \
    "# ---- first $FAILURE_LOG_HEAD of $SLOW_LINES log lines from slow-ca (start attempt 1 of 3) ----" \
    "$OUT"
ok_contains "the remainder is counted to the end of attempt 1, not the end of the log" \
    "# ---- ($(( SLOW_ATTEMPT_LINES - FAILURE_LOG_HEAD )) more lines of attempt 1 not shown) ----" \
    "$OUT"
ok_lacks "the remainder is not counted to the end of the log" \
    "($(( SLOW_LINES - FAILURE_LOG_HEAD )) more lines of attempt 1 not shown)" "$OUT"

# ═════════════════════════════════════════════════════════════════════════════
# The exact point where the tail starts earning its place
# ═════════════════════════════════════════════════════════════════════════════
# The head/tail split turns on `_lines > FAILURE_LOG_HEAD`, and an off-by-one
# lives on that comparison rather than on either side of it.  The fixtures
# above straddle it; these two sit on it, one line apart, so a `-ge` and a
# `-gt HEAD+1` are each caught by one of them.
#
# write_lines FILE COUNT PREFIX -- a single-attempt log of exactly COUNT lines,
# first line distinct so it cannot recur and be read as a restart banner.
write_lines() {
    local _file="$1" _count="$2" _prefix="$3" _i
    {
        printf '%s  | starting up\n' "$_prefix"
        for _i in $(seq 2 "$_count"); do
            printf '%s  | line %d\n' "$_prefix" "$_i"
        done
    } > "$_file"
}

write_lines "$WORK_DIR/logs/exact-head.log" "$FAILURE_LOG_HEAD" exact-head-1
OUT=$(dump exact-head)
ok_contains "a log of exactly the head depth is shown whole" \
    "# ---- first $FAILURE_LOG_HEAD of $FAILURE_LOG_HEAD log lines from exact-head (start attempt 1 of 1) ----" \
    "$OUT"
ok_lacks "a log of exactly the head depth is not then repeated as a tail" \
    "# ---- last " "$OUT"
ok_lacks "a log of exactly the head depth reports nothing cut" \
    "not shown" "$OUT"

write_lines "$WORK_DIR/logs/over-head.log" "$(( FAILURE_LOG_HEAD + 1 ))" over-head-1
OUT=$(dump over-head)
ok_contains "one line past the head depth brings the tail back" \
    "# ---- last $(( FAILURE_LOG_HEAD + 1 )) of $(( FAILURE_LOG_HEAD + 1 )) log lines from over-head ----" \
    "$OUT"
# Also the singular: the one place the count can be 1, and "1 more lines"
# would be the only ungrammatical line the dump can emit.
ok_contains "one line past the head depth reports exactly that one line cut" \
    "# ---- (1 more line of attempt 1 not shown) ----" "$OUT"

# The tail header's count comes from `_lines < FAILURE_LOG_TAIL ? _lines :
# FAILURE_LOG_TAIL`.  The restart-loop fixture above pins the FAILURE_LOG_TAIL
# arm; this pins the other one.  `tail -n` does not complain when N exceeds
# what it is given, so an arm chosen wrongly prints the right lines under a
# wrong count -- visible only in the header, and only if something reads it.
OUT=$(dump puppet-master)
ok_contains "a log shorter than the tail depth reports its own length" \
    "# ---- last $LATE_LINES of $LATE_LINES log lines from puppet-master ----" "$OUT"

# ═════════════════════════════════════════════════════════════════════════════
# Degenerate logs
# ═════════════════════════════════════════════════════════════════════════════
{
    printf 'redis-1  | Ready to accept connections\n'
    printf 'redis-1  | Background saving started\n'
    printf 'redis-1  | Background saving terminated with success\n'
} > "$WORK_DIR/logs/redis.log"

OUT=$(dump redis)
ok_contains "a short log is shown whole" "Background saving terminated with success" "$OUT"
ok_lacks "a short log is not then repeated as a tail" "# ---- last " "$OUT"

# A blank first line says nothing about where an attempt starts.  Treating it
# as the banner would count every blank line in the log as a restart, and
# truncate the view at the first one.
{
    printf '\n'
    printf 'openvoxdb-1  | OpenVoxDB starting\n'
    printf '\n'
    printf 'openvoxdb-1  | FATAL: could not connect to postgres\n'
} > "$WORK_DIR/logs/openvoxdb.log"

OUT=$(dump openvoxdb)
ok_contains "a blank first line is not mistaken for a restart banner" \
    "(start attempt 1 of 1)" "$OUT"
ok_contains "a log with blank lines is not truncated at the first one" \
    "could not connect to postgres" "$OUT"

: > "$WORK_DIR/logs/silent.log"
OUT=$(dump silent)
ok_contains "a service that wrote nothing says so" "silent wrote no log" "$OUT"

# Compose's stderr is the channel podman replays a container's own stderr on,
# which is where a Go service writes the diagnostics this whole helper exists
# to surface.  Capturing it is deliberate, so pin it.
FAKE_COMPOSE_STDERR='FATAL: tls: private key does not match public key'
OUT=$(dump redis)
ok_contains "the command's stderr reaches the dump" \
    "private key does not match public key" "$OUT"
FAKE_COMPOSE_STDERR=''

# ═════════════════════════════════════════════════════════════════════════════
# Every harness, not just one
# ═════════════════════════════════════════════════════════════════════════════
# Issue #281 existed in two copies and a fix to one would have left the other.
# These check the fix reached every call site, the round trip's included, and
# that none kept a private tail-only dump alongside the shared one.
for _harness in test/backends/redis-stack.sh test/puppet/puppet-stack.sh \
        test/roundtrip/roundtrip.sh; do
    if grep -q 'failure_log_dump' "$_here/../$_harness"; then
        pass "$_harness dumps through the shared helper"
    else
        fail "$_harness dumps through the shared helper" "no call to failure_log_dump"
    fi

    if grep -q 'logs --tail' "$_here/../$_harness"; then
        fail "$_harness has no tail-only log dump left" \
            "still calls \`logs --tail\`, which cannot reach a first start attempt"
    else
        pass "$_harness has no tail-only log dump left"
    fi
done

# ═════════════════════════════════════════════════════════════════════════════
# Results
# ═════════════════════════════════════════════════════════════════════════════
printf '\n1..%d\n' "$T"
printf '# Results: %d passed, %d failed out of %d\n' \
    $(( T - FAILURES )) "$FAILURES" "$T"

[ "$FAILURES" -eq 0 ]
