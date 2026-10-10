#!/bin/bash
# Failure-log presentation for the compose integration harnesses.
#
# Sourced by test/backends/redis-stack.sh and test/puppet/puppet-stack.sh,
# both of which need a failing service's own account of what went wrong before
# teardown makes it unrecoverable, and by test/roundtrip/roundtrip.sh. That one
# restarts its services deliberately, once per phase, so for it the "start
# attempt" this file counts is a phase, and its failure is in the tail.
#
# Sourced, where the harnesses deliberately keep independent *copies* of
# their engine detection, argument parsing and TAP helpers: each of those is
# coupled to its own harness's state, and this is not. The one thing that did
# couple the dump helper to its harness -- the `_COMPOSE` array naming the
# compose command and its -f file -- is passed in as an argument here instead.
# Keeping it copied was what let issue #281 be true of both of the original two
# harnesses at once.
#
# What it is for (issue #281). The harnesses used to dump a *tail* of the log.
# `compose logs --tail` returns the NEWEST lines, and the services that matter
# most restart-loop: the two CA replicas in test/compose-backends-redis.yml
# carry `restart: on-failure`, so their log is several concatenated start
# attempts and a tail holds the last futile ones. The attempt that holds the
# reason is the FIRST, which a tail cannot reach and a deeper tail only moves
# further away. Twice in one day a CI failure was reported as 200 identical
# lines of a replica waiting for Redis, with the Go process's own error
# nowhere in the capture.
#
# So the dump leads with the first start attempt, and keeps a tail beneath it
# for the other shape of failure -- a service that failed once, late, without
# restarting, whose reason really is at the end.

# -- How much of each container's log to replay when the run fails ---------
# One pair of knobs for every dump site in every harness, deliberately: when
# the readiness abort dumped the timed-out service at its own shallower depth,
# the culprit ended up with the least log of anything in the run.
#
# HEAD bounds the first-attempt view. It is a bound, not a target: the view
# stops at the end of the first attempt whenever that comes sooner, and a CA
# replica's whole bootstrap is a handful of lines. The depth only matters for
# a service that produced a lot before dying on its first and only attempt.
FAILURE_LOG_HEAD=120
FAILURE_LOG_TAIL=200

# -- Helper: format the first start attempt from a container log -----------
# Usage: failure_log_first_attempt <service> <max-lines>   (log on stdin)
#
# Compose concatenates the restarts of one service into a single log with no
# separator of its own, so the attempt boundary has to come from the log's own
# content: a service that restart-loops re-runs its entrypoint from the top,
# replaying the same first line every time. That line is therefore both the
# banner and the marker -- counting it counts the attempts, and its second
# occurrence is where the first attempt ends.
#
# When it never recurs there is one attempt, which is the correct answer for
# every service without a `restart:` policy, and the view is simply the head
# of the log -- still the front of the first (only) attempt.
failure_log_first_attempt() {  # service-name  max-lines
    awk -v svc="$1" -v max="$2" '
        # Compose prefixes each line with the container name and a pipe
        # ("openvox-ca-1  | Waiting for Redis at redis:6379..."). The prefix
        # is identical across restarts so it would not change the comparison,
        # but strip it anyway so the banner match does not depend on which
        # compose implementation produced the log.
        function body(s,   t) {
            t = s
            sub(/^[A-Za-z0-9_.-]+[[:space:]]*\|[[:space:]]?/, "", t)
            return t
        }
        { line[NR] = $0; text[NR] = body($0) }
        END {
            if (NR == 0) {
                printf "# ---- %s wrote no log ----\n", svc
                exit
            }
            banner = text[1]
            attempts = 1
            last = NR
            # A blank or prefix-only first line says nothing about where an
            # attempt starts; treating it as the banner would count every
            # blank line in the log as a restart.
            if (banner != "") {
                attempts = 0
                for (i = 1; i <= NR; i++) {
                    if (text[i] != banner) continue
                    attempts++
                    if (attempts == 2) last = i - 1
                }
            }
            shown = last < max ? last : max
            printf "# ---- first %d of %d log lines from %s (start attempt 1 of %d) ----\n", \
                shown, NR, svc, attempts
            for (i = 1; i <= shown; i++) print line[i]
            if (last > shown) {
                cut = last - shown
                printf "# ---- (%d more %s of attempt 1 not shown) ----\n", \
                    cut, (cut == 1 ? "line" : "lines")
            }
        }
    '
}

# -- Helper: replay one service's container log, first attempt first -------
# Usage: failure_log_dump <service> <compose-command>...
#   e.g. failure_log_dump openvox-ca "${_COMPOSE[@]}" >&2
#
# Writes to stdout; callers redirect it to stderr so it cannot corrupt the TAP
# stream a consumer is parsing. Never fails the caller: a dump that cannot run
# must not turn a diagnosable failure into a confusing one.
failure_log_dump() {  # service-name  compose-command...
    local _svc="$1"
    shift
    local _log _lines

    # Fetched once, unbounded, with both views derived from the same text. Two
    # `compose logs` calls could see different logs -- the container may still
    # be restarting underneath us -- and any `--tail` here would truncate away
    # the first attempt this function exists to show.
    #
    # `2>&1` where this helper used to write `>&2`: the output has to come back
    # as a value now. Capturing the command's stderr is deliberate, not
    # incidental. Under `podman logs` a container's stderr -- where Go services
    # write their startup and abort diagnostics -- is replayed on *our* stderr,
    # so discarding it would discard the very lines that explain a failed
    # bootstrap. Compose's own errors ("no such service") arrive the same way,
    # which is also what an operator reading a failure dump wants to see.
    _log=$("$@" logs "$_svc" 2>&1) || true

    if [ -z "$_log" ]; then
        printf '# ---- %s wrote no log ----\n' "$_svc"
        return 0
    fi

    printf '%s\n' "$_log" | failure_log_first_attempt "$_svc" "$FAILURE_LOG_HEAD"

    # The tail earns its place only when the log outruns the head view; below
    # that the two would print the same lines twice.
    _lines=$(printf '%s\n' "$_log" | awk 'END { print NR }')
    if [ "$_lines" -gt "$FAILURE_LOG_HEAD" ]; then
        printf '# ---- last %d of %d log lines from %s ----\n' \
            "$(( _lines < FAILURE_LOG_TAIL ? _lines : FAILURE_LOG_TAIL ))" \
            "$_lines" "$_svc"
        printf '%s\n' "$_log" | tail -n "$FAILURE_LOG_TAIL"
    fi

    printf '# ---- end of %s log ----\n' "$_svc"
}
