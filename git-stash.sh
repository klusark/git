#!/bin/sh
# Copyright (c) 2007, Nanako Shiraishi

dashless=$(basename "$0" | sed -e 's/-/ /')
USAGE="list [<options>]
   or: $dashless show [<stash>]
   or: $dashless drop [-q|--quiet] [<stash>]
   or: $dashless ( pop | apply ) [--index] [-q|--quiet] [<stash>]
   or: $dashless branch <branchname> [<stash>]
   or: $dashless save [--patch] [-k|--[no-]keep-index] [-q|--quiet]
		      [-u|--include-untracked] [-a|--all] [<message>]
   or: $dashless [push [--patch] [-k|--[no-]keep-index] [-q|--quiet]
		       [-u|--include-untracked] [-a|--all] [-m <message>]
		       [-- <pathspec>...]]
   or: $dashless clear"

SUBDIRECTORY_OK=Yes
OPTIONS_SPEC=
START_DIR=$(pwd)
. git-sh-setup
require_work_tree
prefix=$(git rev-parse --show-prefix) || exit 1
cd_to_toplevel

TMP="$GIT_DIR/.git-stash.$$"
TMPindex=${GIT_INDEX_FILE-"$(git rev-parse --git-path index)"}.stash.$$
trap 'rm -f "$TMP-"* "$TMPindex"' 0

ref_stash=refs/stash

if git config --get-colorbool color.interactive; then
       help_color="$(git config --get-color color.interactive.help 'red bold')"
       reset_color="$(git config --get-color '' reset)"
else
       help_color=
       reset_color=
fi

no_changes () {
	git diff-index --quiet --cached HEAD --ignore-submodules -- "$@" &&
	git diff-files --quiet --ignore-submodules -- "$@" &&
	(test -z "$untracked" || test -z "$(untracked_files "$@")")
}

untracked_files () {
	if test "$1" = "-z"
	then
		shift
		z=-z
	else
		z=
	fi
	excl_opt=--exclude-standard
	test "$untracked" = "all" && excl_opt=
	git ls-files -o $z $excl_opt -- "$@"
}

clear_stash () {
	if test $# != 0
	then
		die "$(gettext "git stash clear with parameters is unimplemented")"
	fi
	if current=$(git rev-parse --verify --quiet $ref_stash)
	then
		git update-ref -d $ref_stash $current
	fi
}

create_stash () {
	stash_msg=
	untracked=
	while test $# != 0
	do
		case "$1" in
		-m|--message)
			shift
			stash_msg=${1?"BUG: create_stash () -m requires an argument"}
			;;
		-m*)
			stash_msg=${1#-m}
			;;
		--message=*)
			stash_msg=${1#--message=}
			;;
		-u|--include-untracked)
			shift
			untracked=${1?"BUG: create_stash () -u requires an argument"}
			;;
		--)
			shift
			break
			;;
		esac
		shift
	done

	git update-index -q --refresh
	if no_changes "$@"
	then
		exit 0
	fi

	# state of the base commit
	if b_commit=$(git rev-parse --verify HEAD)
	then
		head=$(git rev-list --oneline -n 1 HEAD --)
	else
		die "$(gettext "You do not have the initial commit yet")"
	fi

	if branch=$(git symbolic-ref -q HEAD)
	then
		branch=${branch#refs/heads/}
	else
		branch='(no branch)'
	fi
	msg=$(printf '%s: %s' "$branch" "$head")

	# state of the index
	i_tree=$(git write-tree) &&
	i_commit=$(printf 'index on %s\n' "$msg" |
		git commit-tree $i_tree -p $b_commit) ||
		die "$(gettext "Cannot save the current index state")"

	if test -n "$untracked"
	then
		# Untracked files are stored by themselves in a parentless commit, for
		# ease of unpacking later.
		u_commit=$(
			untracked_files -z "$@" | (
				GIT_INDEX_FILE="$TMPindex" &&
				export GIT_INDEX_FILE &&
				rm -f "$TMPindex" &&
				git update-index -z --add --remove --stdin &&
				u_tree=$(git write-tree) &&
				printf 'untracked files on %s\n' "$msg" | git commit-tree $u_tree  &&
				rm -f "$TMPindex"
		) ) || die "$(gettext "Cannot save the untracked files")"

		untracked_commit_option="-p $u_commit";
	else
		untracked_commit_option=
	fi

	if test -z "$patch_mode"
	then

		# state of the working tree
		w_tree=$( (
			git read-tree --index-output="$TMPindex" -m $i_tree &&
			GIT_INDEX_FILE="$TMPindex" &&
			export GIT_INDEX_FILE &&
			git diff-index --name-only -z HEAD -- "$@" >"$TMP-stagenames" &&
			git update-index -z --add --remove --stdin <"$TMP-stagenames" &&
			git write-tree &&
			rm -f "$TMPindex"
		) ) ||
			die "$(gettext "Cannot save the current worktree state")"

	else

		rm -f "$TMP-index" &&
		GIT_INDEX_FILE="$TMP-index" git read-tree HEAD &&

		# find out what the user wants
		GIT_INDEX_FILE="$TMP-index" \
			git add--interactive --patch=stash -- "$@" &&

		# state of the working tree
		w_tree=$(GIT_INDEX_FILE="$TMP-index" git write-tree) ||
		die "$(gettext "Cannot save the current worktree state")"

		git diff-tree -p HEAD $w_tree -- >"$TMP-patch" &&
		test -s "$TMP-patch" ||
		die "$(gettext "No changes selected")"

		rm -f "$TMP-index" ||
		die "$(gettext "Cannot remove temporary index (can't happen)")"

	fi

	# create the stash
	if test -z "$stash_msg"
	then
		stash_msg=$(printf 'WIP on %s' "$msg")
	else
		stash_msg=$(printf 'On %s: %s' "$branch" "$stash_msg")
	fi
	w_commit=$(printf '%s\n' "$stash_msg" |
	git commit-tree $w_tree -p $b_commit -p $i_commit $untracked_commit_option) ||
	die "$(gettext "Cannot record working tree state")"
}

push_stash () {
	keep_index=
	patch_mode=
	untracked=
	stash_msg=
	while test $# != 0
	do
		case "$1" in
		-k|--keep-index)
			keep_index=t
			;;
		--no-keep-index)
			keep_index=n
			;;
		-p|--patch)
			patch_mode=t
			# only default to keep if we don't already have an override
			test -z "$keep_index" && keep_index=t
			;;
		-q|--quiet)
			GIT_QUIET=t
			;;
		-u|--include-untracked)
			untracked=untracked
			;;
		-a|--all)
			untracked=all
			;;
		-m|--message)
			shift
			test -z ${1+x} && usage
			stash_msg=$1
			;;
		-m*)
			stash_msg=${1#-m}
			;;
		--message=*)
			stash_msg=${1#--message=}
			;;
		--help)
			show_help
			;;
		--)
			shift
			break
			;;
		-*)
			option="$1"
			eval_gettextln "error: unknown option for 'stash push': \$option"
			usage
			;;
		*)
			break
			;;
		esac
		shift
	done

	eval "set $(git rev-parse --sq --prefix "$prefix" -- "$@")"

	if test -n "$patch_mode" && test -n "$untracked"
	then
		die "$(gettext "Can't use --patch and --include-untracked or --all at the same time")"
	fi

	test -n "$untracked" || git ls-files --error-unmatch -- "$@" >/dev/null || exit 1

	git update-index -q --refresh
	if no_changes "$@"
	then
		say "$(gettext "No local changes to save")"
		exit 0
	fi

	git reflog exists $ref_stash ||
		clear_stash || die "$(gettext "Cannot initialize stash")"

	create_stash -m "$stash_msg" -u "$untracked" -- "$@"
	git stash--helper store -m "$stash_msg" -q $w_commit ||
	die "$(gettext "Cannot save the current status")"
	say "$(eval_gettext "Saved working directory and index state \$stash_msg")"

	if test -z "$patch_mode"
	then
		test "$untracked" = "all" && CLEAN_X_OPTION=-x || CLEAN_X_OPTION=
		if test -n "$untracked" && test $# = 0
		then
			git clean --force --quiet -d $CLEAN_X_OPTION
		fi

		if test $# != 0
		then
			test -z "$untracked" && UPDATE_OPTION="-u" || UPDATE_OPTION=
			test "$untracked" = "all" && FORCE_OPTION="--force" || FORCE_OPTION=
			git add $UPDATE_OPTION $FORCE_OPTION -- "$@"
			git diff-index -p --cached --binary HEAD -- "$@" |
			git apply --index -R
		else
			git reset --hard -q
		fi

		if test "$keep_index" = "t" && test -n "$i_tree"
		then
			git read-tree --reset $i_tree
			git ls-files -z --modified -- "$@" |
			git checkout-index -z --force --stdin
		fi
	else
		git apply -R < "$TMP-patch" ||
		die "$(gettext "Cannot remove worktree changes")"

		if test "$keep_index" != "t"
		then
			git reset -q -- "$@"
		fi
	fi
}

save_stash () {
	push_options=
	while test $# != 0
	do
		case "$1" in
		--)
			shift
			break
			;;
		-*)
			# pass all options through to push_stash
			push_options="$push_options $1"
			;;
		*)
			break
			;;
		esac
		shift
	done

	stash_msg="$*"

	if test -z "$stash_msg"
	then
		push_stash $push_options
	else
		push_stash $push_options -m "$stash_msg"
	fi
}

have_stash () {
	git rev-parse --verify --quiet $ref_stash >/dev/null
}

list_stash () {
	have_stash || return 0
	git log --format="%gd: %gs" -g --first-parent -m "$@" $ref_stash --
}

show_help () {
	exec git help stash
	exit 1
}

test "$1" = "-p" && set "push" "$@"

PARSE_CACHE='--not-parsed'
# The default command is "push" if nothing but options are given
seen_non_option=
for opt
do
	case "$opt" in
	--) break ;;
	-*) ;;
	*) seen_non_option=t; break ;;
	esac
done

test -n "$seen_non_option" || set "push" "$@"

# Main command set
case "$1" in
list)
	shift
	list_stash "$@"
	;;
show)
	shift
	git stash--helper show "$@"
	;;
save)
	shift
	save_stash "$@"
	;;
push)
	shift
	push_stash "$@"
	;;
apply)
	shift
	cd "$START_DIR"
	git stash--helper apply "$@"
	;;
clear)
	shift
	git stash--helper clear "$@"
	;;
create)
	shift
	git stash--helper create "$@"
	;;
store)
	shift
	git stash--helper store "$@"
	;;
drop)
	shift
	git stash--helper drop "$@"
	;;
pop)
	shift
	cd "$START_DIR"
	git stash--helper pop "$@"
	;;
branch)
	shift
	cd "$START_DIR"
	git stash--helper branch "$@"
	;;
*)
	case $# in
	0)
		push_stash &&
		say "$(gettext "(To restore them type \"git stash apply\")")"
		;;
	*)
		usage
	esac
	;;
esac
