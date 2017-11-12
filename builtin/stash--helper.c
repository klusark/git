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

static const char * const git_stash_helper_usage[] = {
	N_("git stash--helper drop [-q|--quiet] [<stash>]"),
	N_("git stash--helper pop [--index] [-q|--quiet] [<stash>]"),
	N_("git stash--helper apply [--index] [-q|--quiet] [<stash>]"),
	N_("git stash--helper branch <branchname> [<stash>]"),
	N_("git stash--helper clear"),
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
	argv_array_pushf(&cp.args, "%s", symbolic);
	return pipe_command(&cp, NULL, 0, out, 0, NULL, 0);
}

static int have_stash(void)
{
	struct child_process cp = CHILD_PROCESS_INIT;

	cp.git_cmd = 1;
	cp.no_stdout = 1;
	argv_array_pushl(&cp.args, "rev-parse", "--verify", "--quiet", NULL);
	argv_array_pushf(&cp.args, "%s", ref_stash);
	return pipe_command(&cp, NULL, 0, NULL, 0, NULL, 0);
}

static void destroy_stash_info(struct stash_info *info)
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
		fprintf(stderr, _("Too many revisions specified:"));
		for (i = 0; i < argc; ++i) {
			fprintf(stderr, " '%s'", argv[i]);
		}
		fprintf(stderr, "\n");

		return -1;
	}

	if (argc == 1)
		commit = argv[0];

	strbuf_init(&info->revision, 0);
	if (commit == NULL) {
		if (have_stash()) {
			destroy_stash_info(info);
			return error(_("No stash entries found."));
		}

		strbuf_addf(&info->revision, "%s@{0}", ref_stash);
	} else if (strspn(commit, "0123456789") == strlen(commit)) {
		strbuf_addf(&info->revision, "%s@{%s}", ref_stash, commit);
	} else {
		strbuf_addstr(&info->revision, commit);
	}

	revision = info->revision.buf;

	strbuf_addf(&w_commit_rev, "%s", revision);


	ret = !get_oid(w_commit_rev.buf, &info->w_commit);

	strbuf_release(&w_commit_rev);

	if (!ret) {
		destroy_stash_info(info);
		return error(_("%s is not a valid reference"), revision);
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
		destroy_stash_info(info);
		return error(_("'%s' is not a stash-like commit"), revision);
	}

	strbuf_addf(&u_tree_rev, "%s^3:", revision);

	info->has_u = !get_oid(u_tree_rev.buf, &info->u_tree);

	strbuf_release(&u_tree_rev);

	end_of_rev = strchrnul(revision, '@');
	strbuf_add(&symbolic, revision, end_of_rev - revision);

	ret = get_symbolic_name(symbolic.buf, &out);
	strbuf_release(&symbolic);
	if (ret) {
		destroy_stash_info(info);
		strbuf_release(&out);
		return -1;
	}

	if (out.len - 1 == strlen(ref_stash))
		info->is_stash_ref = !strncmp(out.buf, ref_stash, out.len - 1);
	strbuf_release(&out);

	return 0;
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

static int update_index(struct strbuf *out) {
	struct child_process cp = CHILD_PROCESS_INIT;
	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "update-index", "--add", "--stdin", NULL);
	return pipe_command(&cp, out->buf, out->len, NULL, 0, NULL, 0);
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
		struct child_process cp = CHILD_PROCESS_INIT;
		struct child_process cp2 = CHILD_PROCESS_INIT;
		int res;

		cp.git_cmd = 1;
		argv_array_push(&cp.args, "read-tree");
		argv_array_push(&cp.args, oid_to_hex(&info->u_tree));
		argv_array_pushf(&cp.env_array, "GIT_INDEX_FILE=%s", stash_index_path);

		cp2.git_cmd = 1;
		argv_array_pushl(&cp2.args, "checkout-index", "--all", NULL);
		argv_array_pushf(&cp2.env_array, "GIT_INDEX_FILE=%s", stash_index_path);

		res = run_command(&cp) || run_command(&cp2);
		remove_path(stash_index_path);
		if (res)
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
	destroy_stash_info(&info);
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
		destroy_stash_info(&info);
		return -1;
	}

	ret = do_drop_stash(prefix, &info);
	destroy_stash_info(&info);
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
		destroy_stash_info(&info);
		return -1;
	}

	if (do_apply_stash(prefix, &info, index)) {
		printf_ln(_("The stash entry is kept in case you need it again."));
		destroy_stash_info(&info);
		return -1;
	}

	ret = do_drop_stash(prefix, &info);
	destroy_stash_info(&info);
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
		destroy_stash_info(&info);
		return -1;
	}

	ret = do_apply_stash(prefix, &info, 1);
	if (!ret && info.is_stash_ref)
		ret = do_drop_stash(prefix, &info);

	destroy_stash_info(&info);

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
	xsnprintf(stash_index_path, PATH_MAX, "%s.stash.%d", index_file, pid);

	if (argc < 1)
		usage_with_options(git_stash_helper_usage, options);
	else if (!strcmp(argv[0], "apply"))
		result = apply_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "clear"))
		result = clear_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "drop"))
		result = drop_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "pop"))
		result = pop_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "branch"))
		result = branch_stash(argc, argv, prefix);
	else {
		error(_("unknown subcommand: %s"), argv[0]);
		usage_with_options(git_stash_helper_usage, options);
		result = 1;
	}

	return result;
}
