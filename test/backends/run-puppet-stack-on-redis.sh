#!/bin/bash
# Wrapper that runs the unmodified test/puppet/puppet-stack.sh TAP suite
# against the Redis-backed CA topology (compose-backends-redis.yml), which
# differs from compose-puppet.yml in the compose file name plus the host
# port mappings (CA on 8241, master on 8240, vs. 8141/8140 for puppet).
#
# Approach: sed-rewrite a temporary copy of puppet-stack.sh with the literal
# substitutions needed for the redis topology, then exec the copy. This keeps
# the upstream script untouched and contains all backend-variant knowledge in
# one obvious place.
#
# Usage: invoked by test/backends/redis-stack.sh; not run directly.

set -euo pipefail

cd "$(dirname "$0")/../.."

UPSTREAM=test/puppet/puppet-stack.sh
[ -r "$UPSTREAM" ] || { printf 'Error: %s not found\n' "$UPSTREAM" >&2; exit 1; }

WORK=$(mktemp -d /tmp/puppet-stack-redis.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# Substitutions (literal-string replacements only):
#  1. Compose file               -> compose-backends-redis.yml
#  2. Host CA URL                -> https://localhost:8241
#  3. Host master health URL     -> https://localhost:8240/...
#  4. --resolve / --connect-to   -> add --connect-to redirecting host:8240
#     This pair lets curl keep doing TLS hostname verification against
#     "puppet-master" while the actual TCP connect lands on host port 8240.
sed \
    -e 's|compose-puppet\.yml|compose-backends-redis.yml|g' \
    -e 's|https://localhost:8141|https://localhost:8241|g' \
    -e 's|https://localhost:8140/status/v1/simple|https://localhost:8240/status/v1/simple|g' \
    -e 's|--resolve "puppet-master:8140:127\.0\.0\.1"|--resolve "puppet-master:8140:127.0.0.1" --connect-to "puppet-master:8140:127.0.0.1:8240"|g' \
    "$UPSTREAM" > "$WORK/puppet-stack-redis.sh"
chmod +x "$WORK/puppet-stack-redis.sh"

# Sanity check that all four substitutions actually fired -- if puppet-stack.sh
# is later refactored away from these literals the wrapper would silently run
# against the wrong stack, which is much harder to diagnose than a hard fail
# here.
require_count() {  # description  expected-count  pattern  file
    local _desc="$1" _expected="$2" _pat="$3" _file="$4"
    local _got
    _got=$(grep -c -F "$_pat" "$_file" 2>/dev/null || echo 0)
    if [ "${_got:-0}" -lt "$_expected" ]; then
        printf 'Error: wrapper substitution missed: %s (saw %s of >=%s "%s")\n' \
            "$_desc" "${_got:-0}" "$_expected" "$_pat" >&2
        exit 1
    fi
}
require_count "compose-backends-redis.yml"  3 "compose-backends-redis.yml"        "$WORK/puppet-stack-redis.sh"
require_count "redis-mapped CA host port"   1 "https://localhost:8241"             "$WORK/puppet-stack-redis.sh"
require_count "redis-mapped master health"  1 "https://localhost:8240/status/v1/simple" "$WORK/puppet-stack-redis.sh"
require_count "redis-mapped master port"    1 "127.0.0.1:8240"                     "$WORK/puppet-stack-redis.sh"

exec bash "$WORK/puppet-stack-redis.sh" "$@"
