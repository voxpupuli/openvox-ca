#!/bin/sh
# Local mirror of the verify-release-tag gate's version check: refuse to push
# a v* tag whose name does not equal "v" + the internal/version constant at
# the tagged commit. The server-side gate would refuse it anyway, but only
# after the tag is on the remote (delete/fix/re-tag); this catches it before
# the push. The CI-green half of the gate stays server-side only — it needs
# the network, which a push hook should not.
#
# git feeds the pushed refs on stdin, one per line:
#   <local-ref> <local-sha> <remote-ref> <remote-sha>

status=0
while read -r local_ref local_sha remote_ref remote_sha; do
	case "$remote_ref" in refs/tags/v*) ;; *) continue ;; esac
	case "$local_sha" in *[!0]*) ;; *) continue ;; esac # skip deletions
	tag="${remote_ref#refs/tags/}"
	commit=$(git rev-parse "$local_sha^{commit}" 2>/dev/null) || continue
	want="${tag#v}"
	have=$(git show "$commit:internal/version/version.go" 2>/dev/null |
		sed -n 's/^const Version = "\(.*\)"$/\1/p')
	if [ "$have" != "$want" ]; then
		echo "Refusing to push tag $tag: internal/version at the tagged commit says \"$have\", not \"$want\"."
		echo "Land the version bump first (mage release:prepare $want) and tag the merged commit."
		status=1
	fi
done
exit $status
