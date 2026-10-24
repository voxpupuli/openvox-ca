#!/bin/sh
# Local mirror of the verify-release-tag gate's version checks: refuse to push
# a v* tag whose name does not equal "v" + the internal/version constant at
# the tagged commit, or whose Helm chart version/appVersion disagree with it.
# The server-side gate would refuse it anyway, but only
# after the tag is on the remote (delete/fix/re-tag); this catches it before
# the push. The CI-green half of the gate stays server-side only — it needs
# the network, which a push hook should not.
#
# git feeds the pushed refs on stdin, one per line:
#   <local-ref> <local-sha> <remote-ref> <remote-sha>

status=0
while IFS= read -r line; do
	# git writes the refspec's left side into the first field verbatim, spaces
	# included ('HEAD^{/Release 1.2.3}:refs/tags/v1.2.3' does), so read the
	# three right-hand fields from the end, where no field holds a space. A
	# line whose local sha (the third field from the right) is not 40 or 64
	# hex digits cannot be read, so refuse it rather than skip a tag push
	# without a word (#528).
	rest=$line
	remote_sha=${rest##* }
	rest=${rest% *}
	remote_ref=${rest##* }
	rest=${rest% *}
	local_sha=${rest##* }
	case "$local_sha" in
	*[!0-9a-f]* | "") local_sha=bad ;;
	esac
	case ${#local_sha} in
	40 | 64) ;;
	*)
		printf 'Refusing to push: could not read the pushed ref from "%s".\n' "$line"
		exit 1
		;;
	esac
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
	chart=$(git show "$commit:charts/openvox-ca/Chart.yaml" 2>/dev/null)
	chart_version=$(printf '%s\n' "$chart" | sed -n 's/^version: \(.*\)$/\1/p')
	chart_app_version=$(printf '%s\n' "$chart" | sed -n 's/^appVersion: "\(.*\)"$/\1/p')
	if [ "$chart_version" != "$want" ] || [ "$chart_app_version" != "$want" ]; then
		echo "Refusing to push tag $tag: the Helm chart at the tagged commit says" \
			"version=\"$chart_version\" appVersion=\"$chart_app_version\", not \"$want\"."
		echo "Land the version bump first (mage release:prepare $want) and tag the merged commit."
		status=1
	fi
done
exit $status
