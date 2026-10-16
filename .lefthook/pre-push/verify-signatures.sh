#!/bin/sh
# Refuse to push a commit that carries no signature. main's ruleset requires a
# signature GitHub verifies on every commit, and merging a pull request with a
# merge commit lands each of its commits on main as it is, so one unsigned
# commit blocks that merge. GitHub only says so once the pull request is open;
# this says so before the push.
#
# It checks that a commit is *signed* (has a gpgsig header), not that GitHub
# will *verify* the signature. Verification here would depend on the local
# keyring and gpg.ssh.allowedSignersFile, so a validly signed commit can read
# as unverifiable on one machine and good on another; and only GitHub knows
# whether the key is registered to the author's account. A signed commit can
# therefore pass this check and still be refused.
#
# Which commits count, per pushed ref (git feeds the pushed refs on stdin, one
# per line: <local-ref> <local-sha> <remote-ref> <remote-sha>):
#   - a deletion (all-zero local sha) has nothing to check;
#   - a branch update checks <remote-sha>..<local-sha>, merges included;
#   - a new branch, or an update whose old tip is not here to diff against,
#     checks only the commits no remote-tracking ref already reaches, rather
#     than the whole history;
#   - a tag checks the commit it points at, only if no remote-tracking ref
#     already reaches it.
# "Remote-tracking ref" means any remote's, not just the one being pushed to:
# a commit already fetched from a fork or a pull request is exempt.
# Every branch counts, since any branch can become a pull request. Other refs
# (notes, for instance) are left alone. Needs no network.

# git push sends objects as they are; rev-list would otherwise show a local
# refs/replace substitute in their place, which could be signed when the commit
# being pushed is not.
GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_REPLACE_OBJECTS

unsigned=
while read -r _ local_sha remote_ref remote_sha; do
	case "$local_sha" in *[!0]*) ;; *) continue ;; esac # skip deletions
	case "$remote_ref" in
	refs/heads/*)
		case "$remote_sha" in
		*[!0]*) known=$(git rev-parse --verify --quiet "$remote_sha^{commit}") ;;
		*) known= ;;
		esac
		if [ -n "$known" ]; then
			set -- "$local_sha" --not "$known"
		else
			set -- "$local_sha" --not --remotes
		fi
		;;
	refs/tags/*)
		commit=$(git rev-parse --verify --quiet "$local_sha^{commit}") || continue
		if ! new=$(git rev-list -n 1 "$commit" --not --remotes); then
			echo "Refusing to push $remote_ref: could not tell whether the commit it tags is new."
			exit 1
		fi
		[ -n "$new" ] || continue
		set -- --no-walk "$commit"
		;;
	*) continue ;;
	esac

	# rev-list rather than log: it is plumbing, so configuration meant for people
	# cannot change the lines the parse below reads (color.ui=always, for one,
	# wraps log's "commit" lines in escape codes even into a pipe). In the raw
	# format headers start in column 0, their continuation lines with one space
	# and the message with four, so a message cannot fake a header.
	if ! raw=$(git rev-list --pretty=raw "$@"); then
		echo "Refusing to push $remote_ref: could not list the commits it adds."
		exit 1
	fi
	if ! found=$(printf '%s\n' "$raw" | awk '
		function flush() { if (sha != "" && !signed) print sha " " subject }
		/^commit [0-9a-f]+$/ { flush(); sha = $2; signed = 0; subject = ""; header = 1; next }
		header && /^$/ { header = 0; next }
		/^gpgsig(-sha256)? / { signed = 1; next }
		!header && subject == "" && /^    / { subject = substr($0, 5) }
		END { flush() }
	'); then
		echo "Refusing to push $remote_ref: could not read the commits it adds."
		exit 1
	fi
	[ -n "$found" ] && unsigned="$unsigned$found
"
done

[ -z "$unsigned" ] && exit 0

echo "Refusing to push: these commits carry no signature."
printf '%s' "$unsigned" | awk '!seen[$1]++' | while read -r sha subject; do
	# printf, not echo: the subject is someone's commit message, and some
	# shells' echo interprets backslash escapes in it.
	printf '  %s %s\n' "$(git rev-parse --short "$sha")" "$subject"
done
echo "main's ruleset requires a signature GitHub verifies on every commit, and a merge commit lands each one on main as it is."
echo "Fix: set up signing, then 'git rebase --force-rebase --gpg-sign <base>' and push again; see CONTRIBUTING.md, \"Submitting changes\"."
exit 1
