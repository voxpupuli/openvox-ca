# Shared by the pre-push gates, verify-tags.sh and verify-signatures.sh, which
# source it; it is not a hook script itself, and sits outside pre-push/ so
# that it cannot be mistaken for one.

# parse_pushed_ref LINE splits one line of the pre-push hook's stdin,
#   <local-ref> <local-sha> <remote-ref> <remote-sha>
# into local_sha, remote_ref and remote_sha, or refuses the push.
#
# It reads from the right: git writes the refspec's left side into the first
# field verbatim, spaces included ('HEAD^{/Release 1.2.3}:refs/tags/v1.2.3'
# does), and the other three fields never hold a space. A line whose local sha
# (the third field from the right) is not 40 or 64 hex digits cannot be read,
# so the push is refused rather than the ref skipped without a word (#528).
#
# The three variables are this function's output, for the caller to read.
# shellcheck disable=SC2034
parse_pushed_ref() {
	rest=$1
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
		printf 'Refusing to push: could not read the pushed ref from "%s".\n' "$1"
		exit 1
		;;
	esac
}
