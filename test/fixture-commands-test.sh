#!/bin/bash
# Regression suite for test/fixture-commands.sh.
#
# That helper is the fixture image's command contract: it asserts, before either
# in-container suite does any work, that every command the suites invoke is
# actually present. It exists because on 2026-09-10 the rolling stream10 base
# dropped diffutils, nothing had ever declared the suite's one `diff` call, and
# the assertion that broke reported *a certificate-content mismatch on files
# that were byte for byte identical*. A missing binary was indistinguishable
# from a defect in the code under test.
#
# Every branch that makes the helper useful is a failing branch, and CI only
# ever takes the passing one. A guard that has silently stopped failing is
# indistinguishable from one that passes -- which would reinstate exactly the
# dishonesty above, one layer up. So each failing branch is exercised here.
#
# Two things this suite is careful about, both learnt the hard way:
#
#   - To prove a command is absent, the stub directory has to BE the whole PATH.
#     Prepending a directory proves nothing, because `command -v` still finds
#     the real binary further along.
#   - The contract's own size check must be able to fail. A lower bound chosen
#     to be comfortably safe is also comfortably large enough to let entries go:
#     at a floor of 25 this 28-entry contract can lose `diff` and two more
#     entries and still pass.
#
# No container runtime and no network: what is under test is shell logic, so
# this runs on the host in well under a second. The mutations that need a real
# image are in docs/development/testing.md, "Fixture image command contract".
#
# Requires a bash that invokes command_not_found_handle, i.e. bash 4+. macOS
# ships 3.2, where the hook is silently ignored -- the specs that exercise it
# would then fail reporting that the recorder caught nothing, which accuses the
# helper of the very defect it was written to prevent. So the shell is probed
# below and an unsupported one says so instead.
#
# Usage (from project root):
#   bash test/fixture-commands-test.sh
#
# Output: TAP.  Exit 0 when all pass, 1 if any fail.

set -uo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HELPER="$_here/fixture-commands.sh"

# Neither inherited nor inheritable. An exported FIXTURE_MISSING_LOG would be
# adopted by require_fixture_commands below, which truncates the path it is
# given and later removes it -- so a value left set in the invoking shell would
# be destroyed by running this suite. Unset here, and again inside every
# subshell, so the specs neither touch the ambient environment nor are steered
# by it.
unset FIXTURE_MISSING_LOG FIXTURE_MISSING_BROKEN

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fixture-commands-test.XXXXXX")
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

# run_helper runs a snippet in a fresh bash with the helper sourced, under the
# same `set -uo pipefail` both real suites use. stdout and stderr are merged:
# the diagnostics under test go to stderr and the TAP tokens to stdout, and an
# assertion here cares about both.
# TMPDIR is pointed at WORK_DIR so the recorder files the helper mktemps land
# inside the directory the EXIT trap sweeps. Setting FIXTURE_MISSING_LOG instead
# would switch the specs onto the caller-supplied branch rather than the mktemp
# branch the real suites take.
run_helper() {
    bash -c "set -uo pipefail; unset FIXTURE_MISSING_LOG FIXTURE_MISSING_BROKEN; export TMPDIR='$WORK_DIR'; . '$HELPER'; $1" 2>&1
}

# The probe has to go through the same interpreter the specs use: run_helper
# resolves bash from PATH, so checking this shell's own BASH_VERSINFO would pass
# on a host where the outer bash is 3.2 and PATH bash is 5.x, and vice versa.
if ! run_helper 'command_not_found_handle() { printf HOOK; }; absent-probe-xyz 2>/dev/null' | grep -q HOOK; then
    printf 'Bail out! this suite needs a bash that invokes command_not_found_handle (bash 4+)\n' >&2
    printf '  # PATH bash is %s\n' "$(bash --version 2>/dev/null | head -1)" >&2
    printf '  # macOS ships bash 3.2, which ignores the hook; install a newer bash and put it first.\n' >&2
    exit 1
fi

# Commands that have to be the REAL thing inside a stub PATH, because the helper
# or this suite executes them rather than merely looking for them: bash runs the
# snippet under test, mktemp opens the recorder, and sort/tr/sed render the
# missing list. Stubbing bash in particular makes every spec silently pass
# nothing, which is how this list was found. They are POSIX basics present on any
# host that can run this suite at all.
HELPER_NEEDS="bash sh mktemp sort tr sed rm"

# A PATH containing every contract command EXCEPT those named. The directory is
# the whole PATH, never a prefix -- prepending proves nothing about a command
# that is supposed to be absent, because command -v finds the real one further
# along.
#
# Everything the helper only *checks for* is a generated stub rather than a
# symlink to a host binary. That is deliberate: what is under test is the
# helper's logic, not this machine's inventory. Symlinking real binaries made
# these specs assert that the HOST has curl, openssl and python3 -- which a
# GitHub runner happens to satisfy and a bare container does not, so the suite
# passed by luck on one host and failed for an unrelated reason on another.
stub_path_without() {
    local skip=" $* " d="$WORK_DIR/stub.$$.$RANDOM" c t
    mkdir -p "$d"
    # shellcheck disable=SC1090
    local cmds; cmds=$(bash -c ". '$HELPER'; printf '%s\n' \"\${FIXTURE_COMMANDS[@]}\" \"\${FIXTURE_BINARIES[@]}\"")
    while read -r c; do
        [ -n "$c" ] || continue
        case "$skip" in *" $c "*) continue ;; esac
        case " $HELPER_NEEDS " in
            *" $c "*)
                t=$(command -v "$c" 2>/dev/null) && ln -sf "$t" "$d/$c" 2>/dev/null
                continue ;;
        esac
        printf '#!/bin/sh\nexit 0\n' > "$d/$c" && chmod +x "$d/$c"
    done <<< "$cmds"
    printf '%s' "$d"
}

printf '# test/fixture-commands.sh regression suite\n\n'

# -- 1: the contract is satisfied by this host (sanity: the rest means nothing
#       if the baseline cannot pass) --------------------------------------------
# The product binaries are not installed on a dev host, so they are stubbed in
# alongside everything else rather than skipped -- a baseline that tolerated
# their absence would also tolerate the check being broken.
_base=$(stub_path_without "")
_out=$(PATH="$_base" run_helper 'require_fixture_commands && echo PREFLIGHT_OK')
case "$_out" in
    *PREFLIGHT_OK*) pass "preflight passes when every contract command resolves" ;;
    *) fail "preflight passes when every contract command resolves" "$_out" ;;
esac

# -- 2: a declared command absent from the image --------------------------------
# This is the 2026-09-10 failure. It must name the command.
_nodiff=$(stub_path_without "diff")
_out=$(PATH="$_nodiff" run_helper 'require_fixture_commands && echo SHOULD_NOT_PASS')
case "$_out" in
    *SHOULD_NOT_PASS*) fail "preflight fails when a contract command is absent" "it passed: $_out" ;;
    *"absent from PATH: diff"*) pass "preflight fails when a contract command is absent" ;;
    *) fail "preflight fails when a contract command is absent" "wrong message: $_out" ;;
esac

# -- 3: a missing product binary is reported on its own line --------------------
# Separate from the base commands because the remedy differs: a packaging fault
# rather than an undeclared dependency.
_noctl=$(stub_path_without "openvox-ca-ctl")
_out=$(PATH="$_noctl" run_helper 'require_fixture_commands || true')
case "$_out" in
    *"product binaries absent: openvox-ca-ctl"*)
        pass "a missing product binary is reported separately from base commands" ;;
    *) fail "a missing product binary is reported separately from base commands" "$_out" ;;
esac

# -- 4: the size check catches a deletion ---------------------------------------
# The entry removed is `diff` deliberately: it is the command whose silent
# absence produced the dishonest assertion, and the one a lower-bound floor
# would have let go.
sed '/^    diff$/d' "$HELPER" > "$WORK_DIR/short.sh"
_out=$(bash -c "set -uo pipefail; . '$WORK_DIR/short.sh'; require_fixture_commands && echo SHOULD_NOT_PASS" 2>&1)
case "$_out" in
    *SHOULD_NOT_PASS*) fail "the size check catches a deleted entry" "it passed: $_out" ;;
    *"lists 27 commands, expected 28"*) pass "the size check catches a deleted entry" ;;
    *) fail "the size check catches a deleted entry" "wrong message: $_out" ;;
esac

# -- 5: an undefined contract is reported, not an unbound-variable crash --------
# Both suites run `set -u`, so expanding an undefined FIXTURE_COMMANDS would
# abort before the diagnostic. The helper probes with `declare -p` instead.
_out=$(bash -c "set -uo pipefail; . '$HELPER'; unset FIXTURE_COMMANDS; require_fixture_commands" 2>&1)
case "$_out" in
    *"FIXTURE_COMMANDS is not defined"*) pass "an undefined contract is reported by name" ;;
    *"unbound variable"*) fail "an undefined contract is reported by name" \
        "aborted on set -u instead of reporting: $_out" ;;
    *) fail "an undefined contract is reported by name" "$_out" ;;
esac

# -- 6: a dead recorder fails, rather than reporting "nothing was missing" ------
# The whole point: with no recorder, fixture_missing_list would return empty and
# the final assertion would state a positive fact about the image with the
# mechanism behind it dead.
_out=$(bash -c "set -uo pipefail; FIXTURE_MISSING_LOG=/proc/nonexistent-fixture-log; . '$HELPER'; require_fixture_commands && echo SHOULD_NOT_PASS" 2>&1)
case "$_out" in
    *SHOULD_NOT_PASS*) fail "an unwritable recorder path fails the preflight" "it passed: $_out" ;;
    *"cannot write the supplied FIXTURE_MISSING_LOG"*) pass "an unwritable recorder path fails the preflight" ;;
    *) fail "an unwritable recorder path fails the preflight" "$_out" ;;
esac

# /dev/null: writable, and discards everything written to it. It is caught by the
# type gate rather than by the round trip -- the spec below covers the round trip
# on its own -- so this asserts exactly that message and no other. An alternation
# accepting either would have let the type gate stand in for a retention check
# that was never reached.
_out=$(bash -c "set -uo pipefail; FIXTURE_MISSING_LOG=/dev/null; . '$HELPER'; require_fixture_commands && echo SHOULD_NOT_PASS" 2>&1)
case "$_out" in
    *SHOULD_NOT_PASS*) fail "a character-device recorder path is refused" "it passed: $_out" ;;
    *"is not a plain file"*) pass "a character-device recorder path is refused" ;;
    *) fail "a character-device recorder path is refused" "$_out" ;;
esac

# The retention check, exercised on its own. The plain-file check above catches
# /dev/null first, which would otherwise leave this branch with no spec at all --
# and a guard nothing exercises is indistinguishable from one that has stopped
# working. So this builds a variant with the shadowing check neutered, the same
# way the mutation recipes in docs/development/testing.md do, and asserts the
# round trip catches what an open-for-writing probe cannot: a path that accepts
# writes and keeps nothing. /dev/null stands in for the realistic instance, which
# is a full filesystem.
awk '/if \[ -L "\$FIXTURE_MISSING_LOG" \] \|\|/ {print "        if false; then"; skip=1; next}
     skip && /! -f "\$FIXTURE_MISSING_LOG"/ {skip=0; next}
     {print}' "$HELPER" > "$WORK_DIR/noplainfile.sh"
_out=$(bash -c "set -uo pipefail; FIXTURE_MISSING_LOG=/dev/null; . '$WORK_DIR/noplainfile.sh'; require_fixture_commands && echo SHOULD_NOT_PASS" 2>&1)
case "$_out" in
    *SHOULD_NOT_PASS*) fail "the retention round trip catches a path that keeps nothing" "it passed: $_out" ;;
    *"does not retain what is written to it"*) pass "the retention round trip catches a path that keeps nothing" ;;
    *) fail "the retention round trip catches a path that keeps nothing" "$_out" ;;
esac

# An adopted path is truncated and later removed, so a symlink must be refused
# rather than followed: otherwise the link's target is destroyed.
_sym_target="$WORK_DIR/symlink-target"
_sym_link="$WORK_DIR/symlink-to-it"
printf 'content that must survive\n' > "$_sym_target"
ln -s "$_sym_target" "$_sym_link"
_out=$(bash -c "set -uo pipefail; FIXTURE_MISSING_LOG='$_sym_link'; . '$HELPER'; require_fixture_commands" 2>&1)
if [ -s "$_sym_target" ] && printf '%s' "$_out" | grep -q "is not a plain file"; then
    pass "a symlinked recorder path is refused, leaving its target intact"
else
    fail "a symlinked recorder path is refused, leaving its target intact" \
         "target is $(wc -c < "$_sym_target" | tr -d ' ') bytes; said: $_out"
fi

_out=$(bash -c "set -uo pipefail; . '$HELPER'; FIXTURE_MISSING_BROKEN='mktemp failed'; fixture_missing_list" 2>&1)
case "$_out" in
    *"recorder unavailable"*) pass "a broken recorder reports itself instead of reporting nothing" ;;
    *) fail "a broken recorder reports itself instead of reporting nothing" "got: [$_out]" ;;
esac

_out=$(bash -c "set -uo pipefail; . '$HELPER'; fixture_missing_list" 2>&1)
case "$_out" in
    *"recorder never opened"*) pass "an unopened recorder reports itself" ;;
    *) fail "an unopened recorder reports itself" "got: [$_out]" ;;
esac

# -- 7: the handler records a miss from inside a command substitution -----------
# The `hostname` case. An increment would have been discarded with the subshell,
# which is why the recorder is a file.
_out=$(run_helper 'require_fixture_commands >/dev/null 2>&1
_v="$(definitely-absent-command-xyz 2>/dev/null)"
printf "captured=[%s] list=[%s]\n" "$_v" "$(fixture_missing_list)"')
case "$_out" in
    *"list=[definitely-absent-command-xyz]"*)
        pass "the handler records a miss that happens inside a command substitution" ;;
    *) fail "the handler records a miss that happens inside a command substitution" "$_out" ;;
esac

# -- 8: misses are deduplicated and the list is empty when there are none -------
_out=$(run_helper 'require_fixture_commands >/dev/null 2>&1
absent-one 2>/dev/null; absent-one 2>/dev/null; absent-two 2>/dev/null
printf "list=[%s]\n" "$(fixture_missing_list)"')
case "$_out" in
    *"list=[absent-one absent-two]"*) pass "recorded misses are deduplicated and sorted" ;;
    *) fail "recorded misses are deduplicated and sorted" "$_out" ;;
esac

_out=$(run_helper 'require_fixture_commands >/dev/null 2>&1
printf "list=[%s]\n" "$(fixture_missing_list)"')
case "$_out" in
    *"list=[]"*) pass "the list is empty when nothing was missing" ;;
    *) fail "the list is empty when nothing was missing" "$_out" ;;
esac

# -- 9: fixture_missing_assert turns the record into one TAP assertion ----------
_out=$(run_helper 'T=0; FAILURES=0
pass() { T=$((T+1)); printf "ok %d - %s\n" "$T" "$1"; }
fail() { T=$((T+1)); FAILURES=$((FAILURES+1)); printf "not ok %d - %s\n" "$T" "$1"
         [ -n "${2:-}" ] && printf "  # %s\n" "$2"; return 0; }
require_fixture_commands >/dev/null 2>&1
fixture_missing_assert
echo "FAILURES=$FAILURES"')
case "$_out" in
    *"not ok 1 - fixture image provided"*)
        fail "fixture_missing_assert passes when nothing was missing" "it reported a failure: $_out" ;;
    *"ok 1 - fixture image provided every command the suite invoked"*FAILURES=0*)
        pass "fixture_missing_assert passes when nothing was missing" ;;
    *) fail "fixture_missing_assert passes when nothing was missing" "$_out" ;;
esac

_out=$(run_helper 'T=0; FAILURES=0
pass() { T=$((T+1)); printf "ok %d - %s\n" "$T" "$1"; }
fail() { T=$((T+1)); FAILURES=$((FAILURES+1)); printf "not ok %d - %s\n" "$T" "$1"
         [ -n "${2:-}" ] && printf "  # %s\n" "$2"; return 0; }
require_fixture_commands >/dev/null 2>&1
absent-three 2>/dev/null
fixture_missing_assert
echo "FAILURES=$FAILURES"')
case "$_out" in
    *"not ok 1 - fixture image provided every command the suite invoked"*FAILURES=1*)
        pass "fixture_missing_assert fails, counting one failure, when a command was missing" ;;
    *) fail "fixture_missing_assert fails, counting one failure, when a command was missing" "$_out" ;;
esac

# -- 10: the commands that must never leave the contract ------------------------
# The size check alone cannot catch a deliberate symmetric edit -- deleting an
# entry and decrementing FIXTURE_COMMANDS_EXPECTED together passes it. These are
# the entries whose loss would retire a known failure, asserted by name so that
# removing one means editing this suite and saying why.
# shellcheck disable=SC1090
_missing_required=$(bash -c ". '$HELPER'
for c in diff curl openssl python3 find sed grep bash sh mktemp; do
    case \" \${FIXTURE_COMMANDS[*]} \" in *\" \$c \"*) ;; *) printf '%s ' \"\$c\" ;; esac
done")
if [ -z "$_missing_required" ]; then
    pass "the contract still names every command a known failure depends on"
else
    fail "the contract still names every command a known failure depends on" \
         "absent from FIXTURE_COMMANDS: $_missing_required"
fi

# -- 11: the handler's message cannot satisfy any of the suite's output greps ---
# The handler writes to stderr, and assertions in integration-compose.sh capture
# stderr (`2>&1`) and grep it for words that mean failure. A handler line landing
# in one of those captures would satisfy the assertion and turn a missing command
# into a green result -- the dishonesty this whole change exists to remove.
#
# The alternation is DERIVED from the suite rather than copied into this file. A
# hand-written copy covered five of the twelve assertions and would have stayed
# green while the handler's wording drifted into one of the other seven.
_patterns=$(grep -oE "grep -q[i]*E '[^']+'" "$_here/integration-compose.sh" \
    | sed "s/.*E '//; s/'$//" | tr '|' '\n' | sort -u | paste -sd '|' -)
_npat=$(grep -cE "grep -q[i]*E '" "$_here/integration-compose.sh")
# Proved usable, not merely non-empty: a pattern set that grep refuses would make
# every comparison below vacuous.
if [ -z "$_patterns" ] || ! printf 'error\n' | grep -qiE -e "$_patterns"; then
    fail "the handler's message matches none of the suite's output greps" \
         "extracted pattern set is empty or unusable by grep: [$_patterns]"
else
    _msg=$(run_helper 'command_not_found_handle some-absent-tool 2>&1 >/dev/null')
    # -e is load-bearing: the derived alternation begins with `--all` (from the
    # assertion at integration-compose.sh:1496), which grep otherwise parses as
    # an option. It then exits non-zero with a usage error, the `if` takes its
    # else branch, and this spec passes because its own tool failed -- which is
    # the dishonesty this file exists to catch, committed by the catcher.
    if printf '%s' "$_msg" | grep -qiE -e "$_patterns"; then
        fail "the handler's message matches none of the suite's output greps" \
             "matches one of the $_npat assertions' patterns: $_msg"
    else
        pass "the handler's message matches none of the suite's output greps"
    fi
fi

# -- Results ------------------------------------------------------------------
printf '\n1..%d\n' "$T"
printf '# Results: %d passed, %d failed out of %d\n' \
    $(( T - FAILURES )) "$FAILURES" "$T"

[ "$FAILURES" -eq 0 ]
