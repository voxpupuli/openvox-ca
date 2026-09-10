#!/bin/bash
# The fixture image's command contract, asserted before any suite does work.
#
# Sourced by the suites that run INSIDE the image built from
# test/Dockerfile.run: test/integration-compose.sh and
# test/migration/migration-test.sh (which in turn sources
# test/migration/http-helpers.sh). All of them mount the whole test directory
# at /test, so this file is reachable as /test/fixture-commands.sh.
#
# Six scripts run in the image in total: those three, the two
# docker/puppet/ca-entrypoint*.sh mounted as container entrypoints, and this file
# itself, which uses mktemp, rm, sort, tr and sed. Those five are in the contract
# because the suites call them too -- heavily; this file is an additional
# consumer, not the reason any of them is listed.
#
# Two further suites, test/puppet/puppet-stack.sh and
# test/backends/redis-stack.sh, run on the HOST and reach into the same image
# with `compose exec`. They do not source this file — a fresh shell started by
# `compose exec` inherits neither the contract nor the handler below — so the
# commands they exec are declared here but asserted only when one of the two
# in-container suites runs. `sh` is in the contract for their sake.
#
# Why this exists
# ---------------
# On 2026-09-10 the rolling quay.io/centos/centos:stream10 tag dropped
# diffutils. No Dockerfile had ever asked for it -- the suite's one `diff` call
# had worked for months on whatever the base happened to ship -- so both Compose
# legs failed, and they failed *dishonestly*: the assertion that broke reported a
# certificate-content mismatch on files that were byte for byte identical. The
# base image cannot be pinned against a repeat, because quay does not retain
# superseded CentOS Stream digests (see renovate.json).
#
# So the contract is asserted instead. A command that vanishes from the base now
# fails once, by name, before any test runs -- rather than once per assertion,
# disguised as a defect in the thing under test.
#
# This is the command-level half of a pair. test/Dockerfile.run declares the
# *packages*; this declares the *commands* those packages have to deliver.
# Changing one without the other either leaves the check blind or fails the
# preflight, which is the intended coupling. The lists are deliberately the
# union across every suite that runs in the image: it describes the image's
# contract, not any one script's needs.
#
# The failing branches here are never taken in CI, so they are registered as
# mutations in docs/development/testing.md ("Fixture image command contract")
# and exercised by test/fixture-commands-test.sh (`mage test:fixtureCommands`).

# Every external command the in-container suites invoke. Derived by extracting
# command-position tokens from the six in-container scripts named above, and the
# two host-side suites that exec into the image, then resolving each
# against the built image, then discarding the ones that turned out to be prose
# rather than calls. The product binaries (openvox-ca, openvox-ca-ctl) are
# COPYed in by the Dockerfile rather than installed, and are checked separately.
FIXTURE_COMMANDS=(
    bash
    sh
    basename cat chmod cp cut date dirname head ls mkdir mktemp rm seq sleep \
        sort tail touch tr wc
    curl
    diff
    find
    grep
    openssl
    python3
    sed
)

# The exact size the list above is meant to have. An exact comparison rather
# than a lower bound, because a lower bound generous enough to be safe is also
# generous enough to let entries go: at a floor of 25 this 28-entry contract
# could lose `diff`, `find` and one more -- `diff` being the command this file
# exists because of -- and still pass. Truncation and a botched merge both change the count, which is the
# realistic damage; a deliberate edit that adjusts both is a deliberate change,
# and test/fixture-commands-test.sh asserts the entries that must never go
# regardless of what the count says.
FIXTURE_COMMANDS_EXPECTED=28

# The product binaries the suites drive. Absent these the suite can still be
# meaningful to run (a packaging fault is worth reporting as such), so they are
# reported separately from the base-provided commands.
FIXTURE_BINARIES=(
    openvox-ca
    openvox-ca-ctl
)

# Where a command Bash could not find gets recorded. A file rather than a
# variable: the miss that prompted all of this -- `hostname`, in a banner -- ran
# inside a command substitution, and an increment there is discarded with the
# subshell. Opened by require_fixture_commands.
FIXTURE_MISSING_LOG="${FIXTURE_MISSING_LOG:-}"

# Non-empty when the recorder could not be opened, and why. This has to be a
# state of its own: with no recorder, fixture_missing_list would return nothing,
# the caller would read that as "nothing was missing", and the suite would
# assert a positive fact about the image with the mechanism behind it dead --
# the same dishonesty as the `diff -q ... && pass || fail` this file replaces,
# one layer up.
FIXTURE_MISSING_BROKEN=""

# Bash calls this for any command it cannot resolve, which is the half a declared
# list cannot cover: the list only knows the commands someone thought to write
# down, and only the ones on code paths that ran. This catches the rest at the
# moment of use.
#
# It deliberately does NOT abort. The suites use `|| true` liberally and a
# missing command mid-assertion should still let the run finish and report every
# other result; what must not happen is the silent empty string that let
# `hostname` fail unnoticed in CI for as long as it did. Both in-container
# suites end by calling fixture_missing_assert, which is what turns a record
# into a verdict -- without that call this handler only writes to stderr.
#
# The message avoids the phrase "not found" on purpose: five assertions in
# test/integration-compose.sh grep captured output for it (lines 1469, 1478,
# 1487, 1718 and 1745), and a handler line reaching one of those captures could
# satisfy it.
command_not_found_handle() {
    if [ -n "$FIXTURE_MISSING_LOG" ]; then
        printf '%s\n' "$1" >> "$FIXTURE_MISSING_LOG" 2>/dev/null
    fi
    printf 'FIXTURE: %s is not installed in the fixture image; declare its package in test/Dockerfile.run and add the command to FIXTURE_COMMANDS in test/fixture-commands.sh\n' \
        "$1" >&2
    return 127
}

# _fixture_open_missing_log prepares the recorder, or records why it could not.
#
# A caller-supplied path is honoured but proved first: /test is mounted ro in
# every compose topology, so an exported FIXTURE_MISSING_LOG pointing there
# would silence every append. It is also truncated rather than appended to, so a
# path that survives between runs cannot carry one run's names into the next
# run's verdict.
_fixture_open_missing_log() {
    if [ -n "$FIXTURE_MISSING_LOG" ]; then
        # Refuse anything that is not a plain file. This path is truncated here
        # and removed by fixture_missing_cleanup, so following a symlink would
        # damage whatever it points at. It also rejects the cases that look
        # writable and silently discard: /dev/null keeps nothing, and pointing
        # the recorder at /dev/stderr to watch misses go past in the compose log
        # is a natural thing to try -- either would leave every record unread
        # and the final assertion green.
        if [ -L "$FIXTURE_MISSING_LOG" ] ||
           { [ -e "$FIXTURE_MISSING_LOG" ] && [ ! -f "$FIXTURE_MISSING_LOG" ]; }; then
            FIXTURE_MISSING_BROKEN="FIXTURE_MISSING_LOG at ${FIXTURE_MISSING_LOG} is not a plain file"
            FIXTURE_MISSING_LOG=""
            return 1
        fi
        if ! : > "$FIXTURE_MISSING_LOG" 2>/dev/null; then
            FIXTURE_MISSING_BROKEN="cannot write the supplied FIXTURE_MISSING_LOG at ${FIXTURE_MISSING_LOG}"
            FIXTURE_MISSING_LOG=""
            return 1
        fi
    else
        FIXTURE_MISSING_LOG=$(mktemp "${TMPDIR:-/tmp}/fixture-missing.XXXXXX" 2>/dev/null) || {
            FIXTURE_MISSING_BROKEN="could not create a recorder file under ${TMPDIR:-/tmp}"
            FIXTURE_MISSING_LOG=""
            return 1
        }
    fi

    # Proved by round trip rather than by opening: being able to open a path for
    # writing does not prove it retains what is appended to it, and a recorder
    # that discards is indistinguishable from one that caught nothing. `-s`
    # rather than reading the file back, because reading from something like
    # /dev/stderr could block rather than return.
    printf 'probe\n' >> "$FIXTURE_MISSING_LOG" 2>/dev/null
    if [ ! -s "$FIXTURE_MISSING_LOG" ]; then
        FIXTURE_MISSING_BROKEN="FIXTURE_MISSING_LOG at ${FIXTURE_MISSING_LOG} does not retain what is written to it"
        FIXTURE_MISSING_LOG=""
        return 1
    fi
    : > "$FIXTURE_MISSING_LOG"
    return 0
}

# fixture_missing_cleanup removes the recorder. Callers add it to their own
# trap; installing one here would silently replace the suite's own EXIT trap,
# which is the reasoning test/migration/http-helpers.sh already records.
fixture_missing_cleanup() {
    [ -n "$FIXTURE_MISSING_LOG" ] && rm -f "$FIXTURE_MISSING_LOG"
    return 0
}

# fixture_missing_list prints what the handler recorded, deduplicated and space
# separated, or a description of why there is no record. It prints nothing at
# all only when the recorder was working and caught nothing, so a caller can
# test it with [ -n ... ] and treat any output as a failure.
fixture_missing_list() {
    if [ -n "$FIXTURE_MISSING_BROKEN" ]; then
        printf 'recorder unavailable -- %s' "$FIXTURE_MISSING_BROKEN"
        return 0
    fi
    if [ -z "$FIXTURE_MISSING_LOG" ]; then
        printf 'recorder never opened -- require_fixture_commands was not called'
        return 0
    fi
    [ -s "$FIXTURE_MISSING_LOG" ] || return 0
    sort -u "$FIXTURE_MISSING_LOG" | tr '\n' ' ' | sed 's/ $//'
}

# fixture_missing_assert turns the record into one TAP assertion, using the
# caller's own pass/fail. Both in-container suites define them identically and
# both must call this: a suite that arms the handler without reporting it is
# back to a missing command costing one line of stderr nobody reads. Keeping the
# call in one place is what stops the two suites drifting apart again.
fixture_missing_assert() {
    local desc="fixture image provided every command the suite invoked" _missing
    _missing=$(fixture_missing_list)
    if [ -z "$_missing" ]; then
        pass "$desc"
    else
        fail "$desc" "$_missing"
    fi
    return 0
}

# require_fixture_commands aborts unless the contract is intact and every
# command in it resolves.
#
# Three ways to fail, all of them loud: the list is not the size it should be,
# the recorder cannot be opened, or a command is absent.
require_fixture_commands() {
    local missing=() binmissing=() c

    # Probed with `declare -p` rather than by expanding it: both callers run
    # `set -u`, so a genuinely undefined FIXTURE_COMMANDS would abort on the
    # expansion below and never reach the diagnostic this branch exists to
    # print. (An array is also not a valid operand inside [ ].)
    if ! declare -p FIXTURE_COMMANDS >/dev/null 2>&1; then
        printf 'Bail out! FIXTURE_COMMANDS is not defined\n' >&2
        printf '  # Something unset it after sourcing: a truncation that dropped the list\n' >&2
        printf '  # would have dropped this function with it.\n' >&2
        return 1
    fi

    if [ "${#FIXTURE_COMMANDS[@]}" -ne "$FIXTURE_COMMANDS_EXPECTED" ]; then
        printf 'Bail out! fixture command contract lists %d commands, expected %d\n' \
            "${#FIXTURE_COMMANDS[@]}" "$FIXTURE_COMMANDS_EXPECTED" >&2
        printf '  # Adding or removing a command means updating FIXTURE_COMMANDS_EXPECTED with it.\n' >&2
        return 1
    fi

    # Opened before the command checks so a miss anywhere in the run is
    # recorded, including one the contract does not know to look for.
    if ! _fixture_open_missing_log; then
        printf 'Bail out! %s\n' "$FIXTURE_MISSING_BROKEN" >&2
        printf '  # Without it a command missing later in the run would go unreported.\n' >&2
        return 1
    fi

    for c in "${FIXTURE_COMMANDS[@]}"; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    for c in "${FIXTURE_BINARIES[@]}"; do
        command -v "$c" >/dev/null 2>&1 || binmissing+=("$c")
    done

    if [ "${#missing[@]}" -gt 0 ] || [ "${#binmissing[@]}" -gt 0 ]; then
        printf 'Bail out! the fixture image is missing commands this suite needs\n' >&2
        [ "${#missing[@]}" -gt 0 ] && \
            printf '  # absent from PATH: %s\n' "${missing[*]}" >&2
        [ "${#binmissing[@]}" -gt 0 ] && \
            printf '  # product binaries absent: %s\n' "${binmissing[*]}" >&2
        printf '  # Declare the providing package in test/Dockerfile.run and rebuild the\n' >&2
        printf '  # image. If the package was already declared, the base image dropped it:\n' >&2
        printf '  # see the note at the top of test/fixture-commands.sh.\n' >&2
        return 1
    fi

    return 0
}
