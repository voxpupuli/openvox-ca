#!/bin/bash
# Regression suite for test/migration/http-helpers.sh.
#
# The helpers exist so that a failed request in the migration suite leaves
# behind the evidence needed to explain it (issue #208).  That claim is only
# worth anything if it holds for the failures that actually happen, so this
# suite drives the helpers against a real curl talking to a real socket that
# fails in the specific ways the migration suite has seen: a transfer
# truncated mid-flight, a connection refused, a 5xx, a 404, an empty body, a
# hangup before the response line, a stall after the headers, and a failed TLS
# handshake -- including all three classes #208 named as indistinguishable.
#
# It also pins the half of the change that is logic rather than reporting:
# http_get_retry must retry a transport failure, must retry a 200 whose body
# is not what was asked for, must stop on the first success, and must not
# retry past its bound.  A retry loop that quietly never retried would look
# identical to a working one on a green run.
#
# Runs on the CI host rather than inside the test-runner container -- what is
# under test is the shell logic, and the container image carries no Python to
# host the fake server with.  Requires bash, curl and python3.
#
# Usage (from project root):
#   bash test/migration/http-helpers-test.sh
#
# Output: TAP.  Exit 0 when all pass, 1 if any fail.

set -uo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=test/migration/http-helpers.sh
. "$_here/http-helpers.sh"

# Fast where the migration suite is patient: this suite asserts on retry
# counts, not on giving a slow server time, so a long delay would only make
# the run slower without testing anything more.
HTTP_RETRY_ATTEMPTS=3
HTTP_RETRY_DELAY=0

command -v python3 >/dev/null 2>&1 || {
    printf 'Bail out! python3 not found; it hosts the fake server this suite drives\n'
    exit 1
}

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/http-helpers-test.XXXXXX")
SERVER_PID=''

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK_DIR" "$_HTTP_TMPDIR"
}
trap cleanup EXIT

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

# ok_eq DESC EXPECTED ACTUAL -- assert equality, reporting both on mismatch.
ok_eq() {
    [ "$2" = "$3" ] && pass "$1" || fail "$1" "expected [$2], got [$3]"
}

# ok_contains DESC NEEDLE HAYSTACK
ok_contains() {
    case "$3" in
        *"$2"*) pass "$1" ;;
        *)      fail "$1" "[$3] does not contain [$2]" ;;
    esac
}

# ok_curl_err DESC RC -- assert _HTTP_ERR is curl's own message for exit RC.
# Keyed on the "curl: (RC) " prefix curl puts on every error it prints, never
# on the prose after it: curl rewords that between releases (exit 18 went from
# "transfer closed with N bytes remaining to read" to "end of response with N
# bytes missing", #606), and a case pinned to the wording fails on whichever
# runner image moves first.
ok_curl_err() {
    case "$_HTTP_ERR" in
        "curl: ($2) "*) pass "$1" ;;
        *)              fail "$1" "[$_HTTP_ERR] does not start with [curl: ($2) ]" ;;
    esac
}

# -- Fake server lifecycle ----------------------------------------------------
# start_server BEHAVIOUR... -- (re)start flaky-server.py and set URL.
start_server() {
    stop_server
    local _portfile="$WORK_DIR/port"
    rm -f "$_portfile"
    python3 "$_here/flaky-server.py" "$_portfile" "$@" &
    SERVER_PID=$!

    local _i
    for _i in $(seq 1 100); do
        [ -s "$_portfile" ] && break
        sleep 0.1
    done
    if [ ! -s "$_portfile" ]; then
        printf 'Bail out! fake server did not start\n'
        exit 1
    fi
    URL="http://127.0.0.1:$(cat "$_portfile")/cert"
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
        SERVER_PID=''
    fi
}

# closed_port -- a port with nothing listening, for the refused-connection
# case.  Bind and immediately release.  Call it immediately before the probe
# that uses it and never cache the result: this suite starts a fake server on
# an ephemeral port between probes, and one of those could otherwise be handed
# the very port a stale _dead_url names -- turning the refused case into a live
# one and false-failing the distinctness assertion below.
closed_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]
s.close()
print(port)
PY
}

# ═════════════════════════════════════════════════════════════════════════════
# Phase 1 -- http_get records a successful request
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 1 -- http_get on a healthy server\n'

start_server ok
http_get "$URL"
_rc=$?

ok_eq   "http_get: returns curl's exit status (0)"      "0"   "$_rc"
ok_eq   "http_get: _HTTP_RC is 0"                       "0"   "$_HTTP_RC"
ok_eq   "http_get: _HTTP_CODE is 200"                   "200" "$_HTTP_CODE"
ok_eq   "http_get: _HTTP_ATTEMPTS is 1"                 "1"   "$_HTTP_ATTEMPTS"
ok_contains "http_get: body survives intact"            "-----END CERTIFICATE-----" "$_HTTP_BODY"
# Not "${#_HTTP_BODY}", which is the expression _http_do assigned from and so
# could never disagree: fetch the same URL through a plain curl that shares
# none of the write-out parsing, and compare against that.
# Counted with wc, not "${#_independent}" from a command substitution: $( )
# strips trailing newlines, and _HTTP_BODY deliberately keeps the one a PEM
# ends with -- the write-out marker follows it, so the split preserves it.
# Comparing against a stripped measurement would have made this assertion
# demand that the helper lose a byte it is right to keep.
_independent=$(curl -s "$URL" | wc -c | tr -d '[:space:]')
ok_eq   "http_get: _HTTP_BYTES matches an independent fetch" \
        "$_independent" "$_HTTP_BYTES"
_full_bytes=$_HTTP_BYTES
ok_contains "http_get: _HTTP_INFO reports the status"   "http=200" "$_HTTP_INFO"

# The status code must not be left in the body.  A regression here would be
# invisible to a grep-for-PEM assertion and would corrupt every fingerprint
# comparison downstream, so pin it directly.
case "$_HTTP_BODY" in
    *200) fail "http_get: write-out marker is stripped from the body" \
               "body still ends with the status code" ;;
    *)    pass "http_get: write-out marker is stripped from the body" ;;
esac

# ═════════════════════════════════════════════════════════════════════════════
# Phase 2 -- the failure modes the old assertions could not tell apart
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 2 -- distinguishable failure modes\n'

# 2a: truncated transfer.  This is the hypothesis #208 could not confirm: the
# server logs a clean 200, curl exits 18, and the body that arrives is short.
start_server truncate
http_get "$URL"
ok_eq   "truncate: curl reports exit 18 (partial transfer)" "18" "$_HTTP_RC"
ok_eq   "truncate: status code still recorded as 200"       "200" "$_HTTP_CODE"
ok_curl_err "truncate: curl's error text is captured"       18
ok_contains "truncate: diagnostic names the exit status"    "rc=18" "$_HTTP_INFO"
ok_contains "truncate: diagnostic names the byte count"     "bytes=$_HTTP_BYTES" "$_HTTP_INFO"
_trunc_bytes=$_HTTP_BYTES

# The byte count is the evidence that separates "truncated" from "empty", so
# it has to be non-zero and short of a complete PEM.
if [ "$_trunc_bytes" -gt 0 ] && [ "$_trunc_bytes" -lt "$_full_bytes" ]; then
    pass "truncate: partial body, neither empty nor complete (${_trunc_bytes}/${_full_bytes} bytes)"
else
    fail "truncate: partial body, neither empty nor complete" \
         "got ${_trunc_bytes} bytes; complete body is ${_full_bytes}"
fi

# 2b: 5xx.  Different rc, different code, different body from 2a -- which is
# the whole point: the old `curl -sfk ... 2>/dev/null || true` rendered these
# two identical (empty capture, discarded status, no diagnostic).
start_server 500
http_get "$URL"
ok_eq   "500: status code is recorded"              "500" "$_HTTP_CODE"
ok_eq   "500: curl exits 0 without -f"              "0"   "$_HTTP_RC"
ok_contains "500: the error body is kept as evidence" "internal server error" "$_HTTP_BODY"
ok_contains "500: diagnostic names the status"      "http=500" "$_HTTP_INFO"

# 2c: connection refused -- nothing listening at all.
stop_server
_dead_url="http://127.0.0.1:$(closed_port)/cert"
http_get "$_dead_url"
ok_eq   "refused: curl exits 7 (couldn't connect)"  "7"   "$_HTTP_RC"
ok_eq   "refused: no status code, reported as 000"  "000" "$_HTTP_CODE"
ok_eq   "refused: body is empty"                    "0"   "$_HTTP_BYTES"
ok_curl_err "refused: curl's error text is captured" 7

# 2d: empty 200.  Distinguishable from all of the above.
start_server empty
http_get "$URL"
ok_eq   "empty: status code is 200"                 "200" "$_HTTP_CODE"
ok_eq   "empty: zero bytes reported"                "0"   "$_HTTP_BYTES"

# 2e: the server hangs up before writing a response line.  Distinct from 2a:
# there the status line arrived and the body did not.  curl still emits its
# write-out here, so the '000' is curl's own %{http_code} for "no response",
# not the parser's no-newline fallback -- that fallback is defensive and no
# real curl invocation is known to reach it.
start_server hangup
http_get "$URL"
ok_eq   "hangup: no response line, reported as 000" "000" "$_HTTP_CODE"
ok_contains "hangup: diagnostic names the status"   "http=000" "$_HTTP_INFO"
if [ "$_HTTP_RC" -ne 0 ]; then
    pass "hangup: curl reports a transport failure (rc=$_HTTP_RC)"
else
    fail "hangup: curl reports a transport failure" "rc=$_HTTP_RC, expected non-zero"
fi

# 2f: 404.  Recorded like any other status, and -- unlike under curl -f -- its
# body survives, which is what let the in-situ fault injection for #208 read
# "Could not find certificate ..." straight off the TAP diagnostic.
start_server notfound
http_get "$URL"
ok_eq   "404: status code is recorded"              "404" "$_HTTP_CODE"
ok_contains "404: the error body is kept as evidence" "Not Found" "$_HTTP_BODY"

# 2h: a server that sends headers and then stalls.  This is the case the
# --max-time bound exists for, and the only one that reaches curl's exit 28:
# without the bound the request never returns and the retry never reaches its
# second attempt, so the whole suite would hang rather than fail.
# HTTP_MAX_TIME is overridden to keep the case sub-second; the fixture stalls
# for far longer than that.
start_server stall
_saved_max_time=$HTTP_MAX_TIME
HTTP_MAX_TIME=1
http_get "$URL"
HTTP_MAX_TIME=$_saved_max_time
ok_eq   "stall: curl reports exit 28 (timeout)"     "28"  "$_HTTP_RC"
ok_contains "stall: diagnostic names the timeout"   "rc=28" "$_HTTP_INFO"
ok_curl_err "stall: curl's error text is captured"  28

# 2i: a TLS handshake failure -- the third of the three failure classes #208
# names as having been indistinguishable ("a transfer truncated mid-flight
# (curl exit 18), a TLS handshake failure (35, 60) and a 500"), and the only
# one the suite did not exercise.  It is not hypothetical: the migration
# suite's pre-flight fetches go to https://old-puppet:8140.
#
# Produced by speaking https to the plain-HTTP fixture, which is enough to
# fail the handshake.  The assertion pins the exit status and that the error
# text was captured, NOT the text itself: verified as rc=35 under both
# LibreSSL 3.3.6 and the runner image's OpenSSL 3.5.7, whose messages share
# not one word ("tlsv1 alert protocol version" vs "wrong version number").
start_server ok
_tls_url="https://127.0.0.1:$(printf '%s' "$URL" | sed -e 's|^http://127.0.0.1:||' -e 's|/cert$||')/cert"
http_get "$_tls_url" -k
if [ "$_HTTP_RC" = "35" ] || [ "$_HTTP_RC" = "60" ]; then
    pass "tls: curl reports a handshake failure (rc=$_HTTP_RC)"
else
    fail "tls: curl reports a handshake failure" \
         "expected rc 35 or 60, got $_HTTP_RC; $_HTTP_INFO"
fi
ok_eq   "tls: no response line, reported as 000"    "000" "$_HTTP_CODE"
ok_curl_err "tls: curl's error text is captured" "$_HTTP_RC"
_info_tls=$_HTTP_INFO

# 2g: every one of the eight produced a distinct diagnostic.  Asserting they
# differ is what pins the property the issue asked for -- reporting each
# individually would still pass if they all collapsed to the same string,
# which is exactly the state `curl -sfk ... 2>/dev/null || true` left them in.
start_server truncate
http_get "$URL"; _info_trunc=$_HTTP_INFO
start_server 500
http_get "$URL"; _info_500=$_HTTP_INFO
stop_server
_dead_url="http://127.0.0.1:$(closed_port)/cert"
http_get "$_dead_url"; _info_refused=$_HTTP_INFO
start_server empty
http_get "$URL"; _info_empty=$_HTTP_INFO
start_server hangup
http_get "$URL"; _info_hangup=$_HTTP_INFO
start_server notfound
http_get "$URL"; _info_404=$_HTTP_INFO
start_server stall
_saved_max_time=$HTTP_MAX_TIME; HTTP_MAX_TIME=1
http_get "$URL"; _info_stall=$_HTTP_INFO
HTTP_MAX_TIME=$_saved_max_time

_distinct=$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
    "$_info_trunc" "$_info_500" "$_info_refused" "$_info_empty" \
    "$_info_hangup" "$_info_404" "$_info_stall" "$_info_tls" |
    sort -u | wc -l | tr -d '[:space:]')
ok_eq "eight failure modes yield eight distinct diagnostics" "8" "$_distinct"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 3 -- http_get_retry
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 3 -- http_get_retry\n'

# 3a: a transport failure followed by a good response is retried through.
start_server truncate ok
http_get_retry "BEGIN CERTIFICATE" "$URL"
_rc=$?
ok_eq   "retry: succeeds once the server recovers"   "0" "$_rc"
ok_eq   "retry: took two attempts"                   "2" "$_HTTP_ATTEMPTS"
ok_contains "retry: returns the good body"           "-----END CERTIFICATE-----" "$_HTTP_BODY"

# 3b: a non-2xx, and a 2xx whose body is not what was asked for, are both
# retried.  The second is the case a retry keyed only on curl's exit status
# would wave through, and it is the case #208 could not rule out.
start_server 500 ok
http_get_retry "BEGIN CERTIFICATE" "$URL"
ok_eq   "retry: a 500 is retried"                    "0" "$?"
ok_eq   "retry: took two attempts after the 500"     "2" "$_HTTP_ATTEMPTS"

start_server notfound ok
http_get_retry "BEGIN CERTIFICATE" "$URL"
ok_eq   "retry: a 404 is retried"                    "0" "$?"
ok_eq   "retry: took two attempts after the 404"     "2" "$_HTTP_ATTEMPTS"

start_server empty ok
http_get_retry "BEGIN CERTIFICATE" "$URL"
ok_eq   "retry: a 200 with the wrong body is retried" "0" "$?"
ok_eq   "retry: took two attempts after the empty 200" "2" "$_HTTP_ATTEMPTS"
ok_contains "retry: and returns the body that satisfied EXPECT" \
            "BEGIN CERTIFICATE" "$_HTTP_BODY"

# 3c: a healthy server costs exactly one request.  Without this, a retry loop
# that always burned its full budget would pass every other assertion here.
start_server ok
http_get_retry "BEGIN CERTIFICATE" "$URL"
ok_eq   "retry: a healthy server takes one attempt"  "1" "$_HTTP_ATTEMPTS"

# 3d: persistent failure gives up at the bound and reports failure, keeping
# the last attempt's evidence.
start_server truncate
http_get_retry "BEGIN CERTIFICATE" "$URL"
_rc=$?
ok_eq   "retry: gives up and returns 1"              "1" "$_rc"
ok_eq   "retry: stopped at HTTP_RETRY_ATTEMPTS"      "$HTTP_RETRY_ATTEMPTS" "$_HTTP_ATTEMPTS"
ok_contains "retry: last attempt's evidence survives" "rc=18" "$_HTTP_INFO"
ok_contains "retry: diagnostic reports the attempt count" \
            "attempts=$HTTP_RETRY_ATTEMPTS" "$_HTTP_INFO"

# 3e: an empty EXPECT requires only a 2xx, so a 200 with any body passes.
start_server empty
http_get_retry "" "$URL"
ok_eq   "retry: empty EXPECT accepts any 2xx body"   "0" "$?"
ok_eq   "retry: and does so on the first attempt"    "1" "$_HTTP_ATTEMPTS"

# 3f: an empty EXPECT still requires a 2xx.  This is the only case that pins
# the status clause of the success test: everywhere else the non-2xx responses
# also fail the EXPECT test, so deleting `[ "${_HTTP_CODE#2}" != "$_HTTP_CODE" ]`
# from http_ok would leave every other assertion here green.
start_server notfound ok
http_get_retry "" "$URL"
ok_eq   "retry: empty EXPECT rejects a 404"          "0" "$?"
ok_eq   "retry: and retried past it"                 "2" "$_HTTP_ATTEMPTS"

start_server notfound
http_get_retry "" "$URL"
ok_eq   "retry: empty EXPECT gives up on a persistent 404" "1" "$?"
ok_eq   "retry: having spent its full budget"        "$HTTP_RETRY_ATTEMPTS" "$_HTTP_ATTEMPTS"

# 3g: HTTP_RETRY_DELAY is what turns 2b in the migration suite from a blind
# `sleep 2` into an adaptive wait, so the sleep has to be observable.  With
# the delay pinned at 0 everywhere else in this file, `sleep "$HTTP_RETRY_DELAY"`
# could be deleted and every other assertion would still pass.
HTTP_RETRY_DELAY=1
start_server truncate ok
# Milliseconds via python3, not $SECONDS: $SECONDS counts second boundaries
# crossed rather than elapsed time, so with the sleep deleted it still reads 1
# whenever the start lands just before a boundary -- a guard that passes a few
# per cent of the time on broken code is not a guard.
_now_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
_t0=$(_now_ms)
http_get_retry "BEGIN CERTIFICATE" "$URL"
_elapsed_ms=$(( $(_now_ms) - _t0 ))
HTTP_RETRY_DELAY=0
ok_eq   "delay: two attempts, as set up"             "2" "$_HTTP_ATTEMPTS"
if [ "$_elapsed_ms" -ge 900 ]; then
    pass "delay: the retry actually slept between attempts (${_elapsed_ms}ms)"
else
    fail "delay: the retry actually slept between attempts" \
         "elapsed ${_elapsed_ms}ms with HTTP_RETRY_DELAY=1; the sleep did not happen"
fi

# 3h: the per-attempt `# retry N/M` line is the only per-attempt evidence that
# ever reaches CI -- _HTTP_INFO afterwards describes the last attempt alone.
# It is the change's actual output, so assert on the output and not just on
# the state behind it.  Redirected to a file rather than captured with $( ),
# so http_get_retry still runs in this shell and its _HTTP_* assignments survive.
start_server truncate
http_get_retry "BEGIN CERTIFICATE" "$URL" > "$WORK_DIR/retry.out"
_retry_lines=$(grep -c '^# retry ' "$WORK_DIR/retry.out" | tr -d '[:space:]')
ok_eq   "retry line: one per attempt except the last" \
        "$(( HTTP_RETRY_ATTEMPTS - 1 ))" "$_retry_lines"
if grep -q '^# retry 1/'"$HTTP_RETRY_ATTEMPTS"' .*rc=18 .*curl=\[curl: (18) ' "$WORK_DIR/retry.out"; then
    pass "retry line: carries that attempt's own evidence"
else
    fail "retry line: carries that attempt's own evidence" \
         "first line was: $(head -1 "$WORK_DIR/retry.out" | diag_oneline)"
fi
# TAP consumers read a leading '#' as a comment; anything else here would
# corrupt the stream the migration suite emits.
if grep -q -v '^# ' "$WORK_DIR/retry.out"; then
    fail "retry line: every line is a TAP comment" \
         "non-comment output: $(grep -v '^# ' "$WORK_DIR/retry.out" | diag_oneline)"
else
    pass "retry line: every line is a TAP comment"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Phase 4 -- diagnostics stay TAP-safe
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 4 -- diagnostics are one line and bounded\n'

start_server ok
http_get "$URL"

# A PEM is multi-line and ~1 kB; a diagnostic that carried either property
# through would corrupt the TAP stream a CI consumer parses.
_lines=$(printf '%s' "$_HTTP_INFO" | wc -l | tr -d '[:space:]')
ok_eq "diagnostic contains no newline" "0" "$_lines"

if [ "${#_HTTP_INFO}" -le $(( HTTP_DIAG_BODY_CHARS + 200 )) ]; then
    pass "diagnostic is bounded in length (${#_HTTP_INFO} chars)"
else
    fail "diagnostic is bounded in length" "${#_HTTP_INFO} chars"
fi

ok_contains "diagnostic excerpts the body" "BEGIN CERTIFICATE" "$_HTTP_INFO"

# ═════════════════════════════════════════════════════════════════════════════
# Results
# ═════════════════════════════════════════════════════════════════════════════
printf '\n1..%d\n' "$T"
printf '# Results: %d passed, %d failed out of %d\n' \
    $(( T - FAILURES )) "$FAILURES" "$T"

[ "$FAILURES" -eq 0 ]
