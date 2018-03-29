#include "builtin.h"
#include "config.h"
#include "parse-options.h"
#include "refs.h"
#include "lockfile.h"
#include "cache-tree.h"
#include "unpack-trees.h"
#include "merge-recursive.h"
#include "argv-array.h"
#include "run-command.h"
#include "dir.h"
#include "diff.h"
#include "diffcore.h"
#include "revision.h"

static const char * const git_stash_helper_usage[] = {
	N_("git stash show [<stash>]"),
	N_("git stash--helper drop [-q|--quiet] [<stash>]"),
	N_("git stash--helper pop [--index] [-q|--quiet] [<stash>]"),
	N_("git stash--helper apply [--index] [-q|--quiet] [<stash>]"),
	N_("git stash--helper branch <branchname> [<stash>]"),
	N_("git stash--helper clear"),
	N_("git stash create [<message>]"),
	N_("git stash store [-m|--message <message>] [-q|--quiet] <commit>"),
	NULL
};

static const char * const git_stash_show_usage[] = {
	N_("git stash show [<stash>]"),
	NULL
};

static const char * const git_stash_helper_drop_usage[] = {
	N_("git stash--helper drop [-q|--quiet] [<stash>]"),
	NULL
};

static const char * const git_stash_helper_pop_usage[] = {
	N_("git stash--helper pop [--index] [-q|--quiet] [<stash>]"),
	NULL
};

static const char * const git_stash_helper_apply_usage[] = {
	N_("git stash--helper apply [--index] [-q|--quiet] [<stash>]"),
	NULL
};

static const char * const git_stash_helper_branch_usage[] = {
	N_("git stash--helper branch <branchname> [<stash>]"),
	NULL
};

static const char * const git_stash_helper_clear_usage[] = {
	N_("git stash--helper clear"),
	NULL
};

static const char * const git_stash_create_usage[] = {
	N_("git stash create [<message>]"),
	NULL
};

static const char * const git_stash_store_usage[] = {
	N_("git stash store [-m|--message <message>] [-q|--quiet] <commit>"),
	NULL
};

static const char *ref_stash = "refs/stash";
static int quiet;
static char stash_index_path[PATH_MAX];

struct stash_info {
	struct object_id w_commit;
	struct object_id b_commit;
	struct object_id i_commit;
	struct object_id u_commit;
	struct object_id w_tree;
	struct object_id b_tree;
	struct object_id i_tree;
	struct object_id u_tree;
	struct strbuf revision;
	int is_stash_ref;
	int has_u;
};

static int get_symbolic_name(const char *symbolic, struct strbuf *out)
{
	struct child_process cp = CHILD_PROCESS_INIT;

	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "rev-parse", "--symbolic-full-name", NULL);
	argv_array_push(&cp.args, symbolic);
	return pipe_command(&cp, NULL, 0, out, 0, NULL, 0);
}

static int have_stash(void)
{
	struct child_process cp = CHILD_PROCESS_INIT;

	cp.git_cmd = 1;
	cp.no_stdout = 1;
	argv_array_pushl(&cp.args, "rev-parse", "--verify", "--quiet", NULL);
	argv_array_push(&cp.args, ref_stash);
	return pipe_command(&cp, NULL, 0, NULL, 0, NULL, 0);
}

static void free_stash_info(struct stash_info *info)
{
	strbuf_release(&info->revision);
}

static int get_stash_info(struct stash_info *info, int argc, const char **argv)
{
	struct strbuf w_commit_rev = STRBUF_INIT;
	struct strbuf b_commit_rev = STRBUF_INIT;
	struct strbuf w_tree_rev = STRBUF_INIT;
	struct strbuf b_tree_rev = STRBUF_INIT;
	struct strbuf i_tree_rev = STRBUF_INIT;
	struct strbuf u_tree_rev = STRBUF_INIT;
	struct strbuf symbolic = STRBUF_INIT;
	struct strbuf out = STRBUF_INIT;
	int ret;
	const char *revision;
	const char *commit = NULL;
	char *end_of_rev;
	info->is_stash_ref = 0;

	if (argc > 1) {
		int i;
		struct strbuf refs_msg = STRBUF_INIT;
		for (i = 0; i < argc; ++i)
			strbuf_addf(&refs_msg, " '%s'", argv[i]);

		fprintf_ln(stderr, _("Too many revisions specified:%s"), refs_msg.buf);
		strbuf_release(&refs_msg);

		return -1;
	}

	if (argc == 1)
		commit = argv[0];

	strbuf_init(&info->revision, 0);
	if (commit == NULL) {
		if (have_stash()) {
			free_stash_info(info);
			return error(_("No stash entries found."));
		}

		strbuf_addf(&info->revision, "%s@{0}", ref_stash);
	} else if (strspn(commit, "0123456789") == strlen(commit)) {
		strbuf_addf(&info->revision, "%s@{%s}", ref_stash, commit);
	} else {
		strbuf_addstr(&info->revision, commit);
	}

	revision = info->revision.buf;

	strbuf_addstr(&w_commit_rev, revision);

	ret = !get_oid(w_commit_rev.buf, &info->w_commit);

	strbuf_release(&w_commit_rev);

	if (!ret) {
		error(_("%s is not a valid reference"), revision);
		free_stash_info(info);
		return -1;
	}

	strbuf_addf(&b_commit_rev, "%s^1", revision);
	strbuf_addf(&w_tree_rev, "%s:", revision);
	strbuf_addf(&b_tree_rev, "%s^1:", revision);
	strbuf_addf(&i_tree_rev, "%s^2:", revision);

	ret = !get_oid(b_commit_rev.buf, &info->b_commit) &&
		!get_oid(w_tree_rev.buf, &info->w_tree) &&
		!get_oid(b_tree_rev.buf, &info->b_tree) &&
		!get_oid(i_tree_rev.buf, &info->i_tree);

	strbuf_release(&b_commit_rev);
	strbuf_release(&w_tree_rev);
	strbuf_release(&b_tree_rev);
	strbuf_release(&i_tree_rev);

	if (!ret) {
		error(_("'%s' is not a stash-like commit"), revision);
		free_stash_info(info);
		return -1;
	}

	strbuf_addf(&u_tree_rev, "%s^3:", revision);

	info->has_u = !get_oid(u_tree_rev.buf, &info->u_tree);

	strbuf_release(&u_tree_rev);

	end_of_rev = strchrnul(revision, '@');
	strbuf_add(&symbolic, revision, end_of_rev - revision);

	ret = get_symbolic_name(symbolic.buf, &out);
	strbuf_release(&symbolic);
	if (ret) {
		free_stash_info(info);
		strbuf_release(&out);
		return -1;
	}

	if (out.len - 1 == strlen(ref_stash))
		info->is_stash_ref = !strncmp(out.buf, ref_stash, out.len - 1);
	strbuf_release(&out);

	return 0;
}

static int untracked_files(struct strbuf *out, int include_untracked,
		int include_ignored, const char **pathspecs)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "ls-files", "-o", "-z", NULL);
	if (include_untracked && !include_ignored)
		argv_array_push(&cp.args, "--exclude-standard");
	argv_array_push(&cp.args, "--");
	if (pathspecs)
		argv_array_pushv(&cp.args, pathspecs);
	return pipe_command(&cp, NULL, 0, out, 0, NULL, 0);
}

static int check_no_changes(const char *prefix, int include_untracked,
		int include_ignored, const char **pathspecs)
{
	struct argv_array args1 = ARGV_ARRAY_INIT;
	struct argv_array args2 = ARGV_ARRAY_INIT;
	struct strbuf out = STRBUF_INIT;
	int ret;

	argv_array_pushl(&args1, "diff-index", "--quiet", "--cached", "HEAD",
		"--ignore-submodules", "--", NULL);
	if (pathspecs)
		argv_array_pushv(&args1, pathspecs);

	if (cmd_diff_index(args1.argc, args1.argv, prefix))
		return 0;

	argv_array_pushl(&args2, "diff-files", "--quiet", "--ignore-submodules",
		"--", NULL);
	if (pathspecs)
		argv_array_pushv(&args2, pathspecs);

	if (cmd_diff_files(args2.argc, args2.argv, prefix))
		return 0;

	if (include_untracked)
		untracked_files(&out, include_untracked, include_ignored, pathspecs);

	ret = (!include_untracked || out.len == 0);
	strbuf_release(&out);
	return ret;
}

static void record_working_tree_callback(struct diff_queue_struct *q,
				struct diff_options *opt, void *cbdata)
{
	int i;

	for (i = 0; i < q->nr; i++) {
		struct stat st;
		struct diff_filepair *p = q->queue[i];
		const char *path = p->one->path;
		remove_file_from_index(&the_index, path);
		if (!lstat(path, &st))
			add_to_index(&the_index, path, &st, 0);
	}
}

/*
 * Untracked files are stored by themselves in a parentless commit, for
 * ease of unpacking later.
 */
static int save_untracked(struct stash_info *info, const char *message,
		int include_untracked, int include_ignored, const char **pathspecs)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf out = STRBUF_INIT;
	struct object_id orig_tree;
	int ret;
	const char *index_file = get_index_file();

	set_alternate_index_output(stash_index_path);
	untracked_files(&out, include_untracked, include_ignored, pathspecs);

	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "update-index", "-z", "--add", "--remove",
		"--stdin", NULL);
	argv_array_pushf(&cp.env_array, "GIT_INDEX_FILE=%s", stash_index_path);

	if (pipe_command(&cp, out.buf, out.len, NULL, 0, NULL, 0)) {
		strbuf_release(&out);
		return -1;
	}

	strbuf_reset(&out);

	discard_cache();
	read_cache_from(stash_index_path);

	write_index_as_tree(&orig_tree, &the_index, stash_index_path, 0, NULL);
	discard_cache();

	read_cache_from(stash_index_path);

	write_cache_as_tree(&info->u_tree, 0, NULL);
	strbuf_addf(&out, "untracked files on %s", message);

	ret = commit_tree(out.buf, out.len, &info->u_tree, NULL,
			&info->u_commit, NULL, NULL);
	strbuf_release(&out);
	if (ret)
		return -1;

	set_alternate_index_output(index_file);
	discard_cache();
	read_cache();

	return 0;
}

static int save_working_tree(struct stash_info *info, const char *prefix,
		const char **pathspecs)
{
	struct rev_info rev;
	int nr_trees = 1;
	struct tree_desc t[MAX_UNPACK_TREES];
	struct tree *tree;
	struct unpack_trees_options opts;
	struct object *obj;

	read_cache_from(stash_index_path);

	memset(&opts, 0, sizeof(opts));

	opts.head_idx = 1;
	opts.src_index = &the_index;
	opts.dst_index = &the_index;
	opts.merge = 1;
	opts.fn = oneway_merge;

	tree = parse_tree_indirect(&info->i_tree);
	init_tree_desc(t, tree->buffer, tree->size);

	if (unpack_trees(nr_trees, t, &opts))
		return -1;

	init_revisions(&rev, prefix);
	setup_revisions(0, NULL, &rev, NULL);
	rev.diffopt.output_format |= DIFF_FORMAT_CALLBACK;
	rev.diffopt.format_callback = record_working_tree_callback;
	// TODO: DIFF_OPT_SET(&rev.diffopt, EXIT_WITH_STATUS);

	parse_pathspec(&rev.prune_data, 0, 0, prefix, pathspecs);

	diff_setup_done(&rev.diffopt);
	obj = parse_object(&info->b_commit);
	add_pending_object(&rev, obj, "");
	if (run_diff_index(&rev, 0))
		return -1;

	if (write_cache_as_tree(&info->w_tree, 0, NULL))
		return -1;

	discard_cache();
	read_cache();

	return 0;
}

static int patch_working_tree(struct stash_info *info, const char *prefix,
		const char **pathspecs)
{
	struct argv_array args = ARGV_ARRAY_INIT;
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf out = STRBUF_INIT;
	//size_t unused;
	const char *index_file = get_index_file();

	argv_array_pushl(&args, "read-tree", "HEAD", NULL);
	argv_array_pushf(&args, "--index-output=%s", stash_index_path);
	cmd_read_tree(args.argc, args.argv, prefix);

	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "add--interactive", "--patch=stash", "--", NULL);
	if (pathspecs)
		argv_array_pushv(&cp.args, pathspecs);

	argv_array_pushf(&cp.env_array, "GIT_INDEX_FILE=%s", stash_index_path);
	if (run_command(&cp))
		return error(_("Cannot save the current worktree state"));

	discard_cache();
	read_cache_from(stash_index_path);

	if (write_cache_as_tree(&info->w_tree, 0, NULL))
		return error(_("Cannot save the current worktree state"));

	child_process_init(&cp);
	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "diff-tree", "-p", "HEAD", NULL);
	argv_array_push(&cp.args, oid_to_hex(&info->w_tree));
	argv_array_push(&cp.args, "--");
	if (pipe_command(&cp, NULL, 0, &out, 0, NULL, 0) || out.len == 0)
		return error(_("No changes selected"));

	//info->patch = strbuf_detach(&out, &unused);

	set_alternate_index_output(index_file);
	discard_cache();
	read_cache();

	return 0;
}



static int do_create_stash(struct stash_info *info, const char *prefix,
		const char *message, int include_untracked, int include_ignored,
		int patch, const char **pathspecs)
{
	struct object_id curr_head;
	char *branch_path = NULL;
	const char *branch_name = NULL;
	struct commit_list *parents = NULL;
	struct strbuf out_message = STRBUF_INIT;
	struct strbuf out = STRBUF_INIT;
	struct pretty_print_context ctx = {0};

	struct commit *c = NULL;
	const char *hash;

	read_cache_preload(NULL);
	refresh_index(&the_index, REFRESH_QUIET, NULL, NULL, NULL);
	if (check_no_changes(prefix, include_untracked, include_ignored, pathspecs))
		return -1;

	if (get_oid_tree("HEAD", &info->b_commit))
		return error(_("You do not have the initial commit yet"));

	branch_path = resolve_refdup("HEAD", 0, &curr_head, NULL);

	if (branch_path == NULL || !strcmp(branch_path, "HEAD"))
		branch_name = "(no branch)";
	else
		skip_prefix(branch_path, "refs/heads/", &branch_name);

	c = lookup_commit(&info->b_commit);

	ctx.output_encoding = get_log_output_encoding();
	ctx.abbrev = 1;
	ctx.fmt = CMIT_FMT_ONELINE;
	hash = find_unique_abbrev(&c->object.oid, DEFAULT_ABBREV);

	strbuf_addf(&out_message, "%s: %s ", branch_name, hash);

	pretty_print_commit(&ctx, c, &out_message);

	strbuf_addf(&out, "index on %s\n", out_message.buf);

	commit_list_insert(lookup_commit(&info->b_commit), &parents);

	if (write_cache_as_tree(&info->i_tree, 0, NULL))
		return error(_("git write-tree failed to write a tree"));

	if (commit_tree(out.buf, out.len, &info->i_tree, parents, &info->i_commit, NULL, NULL))
		return error(_("Cannot save the current index state"));

	strbuf_reset(&out);

	if (include_untracked) {
		if (save_untracked(info, out_message.buf, include_untracked, include_ignored, pathspecs))
			return error(_("Cannot save the untracked files"));
	}

	if (patch) {
		if (patch_working_tree(info, prefix, pathspecs))
			return -1;
	} else {
		if (save_working_tree(info, prefix, pathspecs))
			return error(_("Cannot save the current worktree state"));
	}
	parents = NULL;

	if (include_untracked)
		commit_list_insert(lookup_commit(&info->u_commit), &parents);

	commit_list_insert(lookup_commit(&info->i_commit), &parents);
	commit_list_insert(lookup_commit(&info->b_commit), &parents);

	if (message != NULL && strlen(message) != 0)
		strbuf_addf(&out, "On %s: %s\n", branch_name, message);
	else
		strbuf_addf(&out, "WIP on %s\n", out_message.buf);

	if (commit_tree(out.buf, out.len, &info->w_tree, parents, &info->w_commit, NULL, NULL))
		return error(_("Cannot record working tree state"));

	//info->message = out.buf;

	strbuf_release(&out_message);
	free(branch_path);

	return 0;
}

static int create_stash(int argc, const char **argv, const char *prefix)
{
	int include_untracked = 0;
	const char *message = NULL;
	struct stash_info info;
	int ret;
	struct strbuf out = STRBUF_INIT;
	struct option options[] = {
		OPT_BOOL('u', "include-untracked", &include_untracked,
			N_("stash untracked filed")),
		OPT_STRING('m', "message", &message, N_("message"),
			N_("stash commit message")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
			git_stash_create_usage, 0);

	if (argc != 0) {
		int i;
		for (i = 0; i < argc; ++i) {
			if (i != 0) {
				strbuf_addf(&out, " ");
			}
			strbuf_addf(&out, "%s", argv[i]);
		}
		message = out.buf;
	}

	ret = do_create_stash(&info, prefix, message, include_untracked, 0, 0, NULL);

	strbuf_release(&out);

	if (ret)
		return 0;

	printf("%s\n", sha1_to_hex(info.w_commit.hash));
	return 0;
}



static int do_store_stash(const char *prefix, int quiet, const char *message,
		struct object_id commit)
{
	int ret;
	ret = update_ref(message, ref_stash, &commit, NULL,
			REF_FORCE_CREATE_REFLOG, UPDATE_REFS_DIE_ON_ERR);

	if (ret && !quiet)
		return error(_("Cannot update %s with %s"), ref_stash, sha1_to_hex(commit.hash));

	return ret;
}

static int store_stash(int argc, const char **argv, const char *prefix)
{
	const char *message = "Create via \"git stash store\".";
	const char *commit = NULL;
	struct object_id obj;
	struct option options[] = {
		OPT_STRING('m', "message", &message, N_("message"),
			N_("stash commit message")),
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
		OPT_END()
	};
	argc = parse_options(argc, argv, prefix, options, git_stash_store_usage, 0);

	if (argc != 1)
		return error(_("\"git stash store\" requires one <commit> argument"));

	commit = argv[0];

	if (get_oid(commit, &obj)) {
		fprintf_ln(stderr, _("fatal: %s: not a valid SHA1"), commit);
		fprintf_ln(stderr, _("cannot update %s with %s"), ref_stash, commit);
		return -1;
	}

	return do_store_stash(prefix, quiet, message, obj);
}

static int do_clear_stash(void)
{
	struct object_id obj;
	if (get_oid(ref_stash, &obj))
		return 0;

	return delete_ref(NULL, ref_stash, &obj, 0);
}

static int clear_stash(int argc, const char **argv, const char *prefix)
{
	struct option options[] = {
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options, git_stash_helper_clear_usage, PARSE_OPT_STOP_AT_NON_OPTION);

	if (argc != 0)
		return error(_("git stash--helper clear with parameters is unimplemented"));

	return do_clear_stash();
}

static int reset_tree(struct object_id *i_tree, int update, int reset)
{
	struct unpack_trees_options opts;
	int nr_trees = 1;
	struct tree_desc t[MAX_UNPACK_TREES];
	struct tree *tree;
	struct lock_file lock_file = LOCK_INIT;

	read_cache_preload(NULL);
	if (refresh_cache(REFRESH_QUIET))
		return -1;

	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);

	memset(&opts, 0, sizeof(opts));

	tree = parse_tree_indirect(i_tree);
	if (parse_tree(tree))
		return -1;

	init_tree_desc(t, tree->buffer, tree->size);

	opts.head_idx = 1;
	opts.src_index = &the_index;
	opts.dst_index = &the_index;
	opts.merge = 1;
	opts.reset = reset;
	opts.update = update;
	opts.fn = oneway_merge;

	if (unpack_trees(nr_trees, t, &opts))
		return -1;

	if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK))
		return error(_("unable to write new index file"));

	return 0;
}

static int diff_tree_binary(struct strbuf *out, struct object_id *w_commit)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	const char *w_commit_hex = oid_to_hex(w_commit);

	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "diff-tree", "--binary", NULL);
	argv_array_pushf(&cp.args, "%s^2^..%s^2", w_commit_hex, w_commit_hex);

	return pipe_command(&cp, NULL, 0, out, 0, NULL, 0);
}

static int apply_cached(struct strbuf *out)
{
	struct child_process cp = CHILD_PROCESS_INIT;

	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "apply", "--cached", NULL);
	return pipe_command(&cp, out->buf, out->len, NULL, 0, NULL, 0);
}

static int reset_head(const char *prefix)
{
	struct argv_array args = ARGV_ARRAY_INIT;

	argv_array_push(&args, "reset");
	return cmd_reset(args.argc, args.argv, prefix);
}

static int diff_cached_index(struct strbuf *out, struct object_id *c_tree)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	const char *c_tree_hex = oid_to_hex(c_tree);

	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "diff-index", "--cached", "--name-only", "--diff-filter=A", NULL);
	argv_array_push(&cp.args, c_tree_hex);
	return pipe_command(&cp, NULL, 0, out, 0, NULL, 0);
}

static int update_index(struct strbuf *out)
{
	struct child_process cp = CHILD_PROCESS_INIT;

	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "update-index", "--add", "--stdin", NULL);
	return pipe_command(&cp, out->buf, out->len, NULL, 0, NULL, 0);
}

static int restore_untracked(struct object_id *u_tree)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	int res;

	cp.git_cmd = 1;
	argv_array_push(&cp.args, "read-tree");
	argv_array_push(&cp.args, oid_to_hex(u_tree));
	argv_array_pushf(&cp.env_array, "GIT_INDEX_FILE=%s", stash_index_path);
	if (run_command(&cp)) {
		remove_path(stash_index_path);
		return -1;
	}

	child_process_init(&cp);
	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "checkout-index", "--all", NULL);
	argv_array_pushf(&cp.env_array, "GIT_INDEX_FILE=%s", stash_index_path);

	res = run_command(&cp);
	remove_path(stash_index_path);
	return res;
}

static int do_apply_stash(const char *prefix, struct stash_info *info, int index)
{
	struct merge_options o;
	struct object_id c_tree;
	struct object_id index_tree;
	const struct object_id *bases[1];
	int bases_count = 1;
	struct commit *result;
	int ret;
	int has_index = index;

	read_cache_preload(NULL);
	if (refresh_cache(REFRESH_QUIET))
		return -1;

	if (write_cache_as_tree(&c_tree, 0, NULL) || reset_tree(&c_tree, 0, 0))
		return error(_("Cannot apply a stash in the middle of a merge"));

	if (index) {
		if (!oidcmp(&info->b_tree, &info->i_tree) || !oidcmp(&c_tree, &info->i_tree)) {
			has_index = 0;
		} else {
			struct strbuf out = STRBUF_INIT;

			if (diff_tree_binary(&out, &info->w_commit)) {
				strbuf_release(&out);
				return -1;
			}

			ret = apply_cached(&out);
			strbuf_release(&out);
			if (ret)
				return -1;

			discard_cache();
			read_cache();
			if (write_cache_as_tree(&index_tree, 0, NULL))
				return -1;

			reset_head(prefix);
		}
	}

	if (info->has_u) {
		if (restore_untracked(&info->u_tree))
			return error(_("Could not restore untracked files from stash"));
	}

	init_merge_options(&o);

	o.branch1 = "Updated upstream";
	o.branch2 = "Stashed changes";

	if (!oidcmp(&info->b_tree, &c_tree))
		o.branch1 = "Version stash was based on";

	if (quiet)
		o.verbosity = 0;

	if (o.verbosity >= 3)
		printf_ln(_("Merging %s with %s"), o.branch1, o.branch2);

	bases[0] = &info->b_tree;

	ret = merge_recursive_generic(&o, &c_tree, &info->w_tree, bases_count, bases, &result);
	if (ret != 0) {
		struct argv_array args = ARGV_ARRAY_INIT;
		argv_array_push(&args, "rerere");
		cmd_rerere(args.argc, args.argv, prefix);

		if (index)
			fprintf_ln(stderr, _("Index was not unstashed."));

		return ret;
	}

	if (has_index) {
		if (reset_tree(&index_tree, 0, 0))
			return -1;
	} else {
		struct strbuf out = STRBUF_INIT;

		if (diff_cached_index(&out, &c_tree)) {
			strbuf_release(&out);
			return -1;
		}

		if (reset_tree(&c_tree, 0, 1)) {
			strbuf_release(&out);
			return -1;
		}

		ret = update_index(&out);
		strbuf_release(&out);
		if (ret)
			return -1;

		discard_cache();
	}

	if (!quiet) {
		struct argv_array args = ARGV_ARRAY_INIT;
		argv_array_push(&args, "status");
		cmd_status(args.argc, args.argv, prefix);
	}

	return 0;
}

static int apply_stash(int argc, const char **argv, const char *prefix)
{
	int index = 0;
	struct stash_info info;
	int ret;
	struct option options[] = {
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
		OPT_BOOL(0, "index", &index,
			N_("attempt to recreate the index")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
			git_stash_helper_apply_usage, 0);

	if (get_stash_info(&info, argc, argv))
		return -1;

	ret = do_apply_stash(prefix, &info, index);
	free_stash_info(&info);
	return ret;
}

static int do_drop_stash(const char *prefix, struct stash_info *info)
{
	struct argv_array args = ARGV_ARRAY_INIT;
	int ret;
	struct child_process cp = CHILD_PROCESS_INIT;

	argv_array_pushl(&args, "reflog", "delete", "--updateref", "--rewrite", NULL);
	argv_array_push(&args, info->revision.buf);
	ret = cmd_reflog(args.argc, args.argv, prefix);
	if (!ret) {
		if (!quiet)
			printf(_("Dropped %s (%s)\n"), info->revision.buf, oid_to_hex(&info->w_commit));
	} else {
		return error(_("%s: Could not drop stash entry"), info->revision.buf);
	}

	cp.git_cmd = 1;
	/* Even though --quiet is specified, rev-parse still outputs the hash */
	cp.no_stdout = 1;
	argv_array_pushl(&cp.args, "rev-parse", "--verify", "--quiet", NULL);
	argv_array_pushf(&cp.args, "%s@{0}", ref_stash);
	ret = run_command(&cp);

	if (ret)
		do_clear_stash();

	return 0;
}

static int assert_stash_ref(struct stash_info *info)
{
	if (!info->is_stash_ref)
		return error(_("'%s' is not a stash reference"), info->revision.buf);

	return 0;
}

static int drop_stash(int argc, const char **argv, const char *prefix)
{
	struct stash_info info;
	int ret;
	struct option options[] = {
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
			git_stash_helper_drop_usage, 0);

	if (get_stash_info(&info, argc, argv))
		return -1;

	if (assert_stash_ref(&info)) {
		free_stash_info(&info);
		return -1;
	}

	ret = do_drop_stash(prefix, &info);
	free_stash_info(&info);
	return ret;
}

static int show_stash(int argc, const char **argv, const char *prefix)
{
	struct argv_array args = ARGV_ARRAY_INIT;
	struct stash_info info;
	int numstat = 0;
	int patch = 0;
	int ret;

	struct option options[] = {
		OPT_BOOL(0, "numstat", &numstat,
			N_("Shows number of added and deleted lines in decimal notation")),
		OPT_BOOL('p', "patch", &patch,
			N_("Generate patch")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
			git_stash_show_usage, 0);

	if (get_stash_info(&info, argc, argv))
		return -1;

	argv_array_push(&args, "diff");
	if (numstat)
		argv_array_push(&args, "--numstat");

	if (patch)
		argv_array_push(&args, "-p");

	if (!patch && !numstat)
		argv_array_push(&args, "--stat");

	argv_array_push(&args, oid_to_hex(&info.b_commit));
	argv_array_push(&args, oid_to_hex(&info.w_commit));
	ret = cmd_diff(args.argc, args.argv, prefix);
	free_stash_info(&info);
	return ret;
}

static int pop_stash(int argc, const char **argv, const char *prefix)
{
	int index = 0, ret;
	struct stash_info info;
	struct option options[] = {
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
		OPT_BOOL(0, "index", &index,
			N_("attempt to recreate the index")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
			git_stash_helper_pop_usage, 0);

	if (get_stash_info(&info, argc, argv))
		return -1;

	if (assert_stash_ref(&info)) {
		free_stash_info(&info);
		return -1;
	}

	if (do_apply_stash(prefix, &info, index)) {
		printf_ln(_("The stash entry is kept in case you need it again."));
		free_stash_info(&info);
		return -1;
	}

	ret = do_drop_stash(prefix, &info);
	free_stash_info(&info);
	return ret;
}

static int branch_stash(int argc, const char **argv, const char *prefix)
{
	const char *branch = NULL;
	int ret;
	struct argv_array args = ARGV_ARRAY_INIT;
	struct stash_info info;
	struct option options[] = {
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
			git_stash_helper_branch_usage, 0);

	if (argc == 0)
		return error(_("No branch name specified"));

	branch = argv[0];

	if (get_stash_info(&info, argc - 1, argv + 1))
		return -1;

	argv_array_pushl(&args, "checkout", "-b", NULL);
	argv_array_push(&args, branch);
	argv_array_push(&args, oid_to_hex(&info.b_commit));
	ret = cmd_checkout(args.argc, args.argv, prefix);
	if (ret) {
		free_stash_info(&info);
		return -1;
	}

	ret = do_apply_stash(prefix, &info, 1);
	if (!ret && info.is_stash_ref)
		ret = do_drop_stash(prefix, &info);

	free_stash_info(&info);

	return ret;
}

int cmd_stash__helper(int argc, const char **argv, const char *prefix)
{
	int result = 0;
	pid_t pid = getpid();
	const char *index_file;

	struct option options[] = {
		OPT_END()
	};

	git_config(git_default_config, NULL);

	argc = parse_options(argc, argv, prefix, options, git_stash_helper_usage,
		PARSE_OPT_KEEP_UNKNOWN|PARSE_OPT_KEEP_DASHDASH);

	index_file = get_index_file();
	xsnprintf(stash_index_path, PATH_MAX, "%s.stash.%"PRIuMAX, index_file, (uintmax_t)pid);

	if (argc < 1)
		usage_with_options(git_stash_helper_usage, options);
	else if (!strcmp(argv[0], "show"))
		result = show_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "apply"))
		result = apply_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "clear"))
		result = clear_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "create"))
		result = create_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "drop"))
		result = drop_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "pop"))
		result = pop_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "branch"))
		result = branch_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "store"))
		result = store_stash(argc, argv, prefix);
	else {
		error(_("unknown subcommand: %s"), argv[0]);
		usage_with_options(git_stash_helper_usage, options);
		result = 1;
	}

	return result;
}
