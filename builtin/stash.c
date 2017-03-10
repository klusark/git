#include "builtin.h"
#include "cache.h"
#include "parse-options.h"
#include "refs.h"
#include "tree.h"
#include "lockfile.h"
#include "object.h"
#include "tree-walk.h"
#include "cache-tree.h"
#include "unpack-trees.h"
#include "diff.h"
#include "revision.h"
#include "commit.h"
#include "diffcore.h"
#include "merge-recursive.h"
#include "argv-array.h"
#include "run-command.h"

static const char * const git_stash_helper_usage[] = {
	N_("git stash--helper [--no-changes]"),
	NULL
};

static const char *diff_index_args[] = {
	"diff-index", "--quiet", "--cached", "HEAD", "--ignore-submodules", "--", NULL
};

static const char *diff_files_args[] = {
	"diff-files", "--quiet", "--ignore-submodules", NULL
};

// TODO: quiet isn' always
static const char *reset_quiet_args[] = {
	"reset", "--hard", "--quiet", NULL
};

static const char *reset_args[] = {
	"reset", "--hard", NULL
};

static const char *ref_stash = "refs/stash";
static int quiet = 0;
static struct lock_file lock_file;

struct stash_info {
	unsigned char w_commit[20];
	unsigned char b_commit[20];
	unsigned char i_commit[20];
	unsigned char w_tree[20];
	unsigned char b_tree[20];
	unsigned char i_tree[20];
	const char *message;
	const char *REV;
	int is_stash_ref;
};

static int check_no_changes(const char *prefix)
{
	return cmd_diff_index(ARRAY_SIZE(diff_index_args) - 1, diff_index_args, prefix) == 0 &&
		cmd_diff_files(ARRAY_SIZE(diff_files_args) - 1, diff_files_args, prefix) == 0;
}

static int get_stash_info(struct stash_info *info, const char *commit)
{
	struct strbuf w_commit_rev = STRBUF_INIT;
	struct strbuf b_commit_rev = STRBUF_INIT;
	struct strbuf i_commit_rev = STRBUF_INIT;
	struct strbuf w_tree_rev = STRBUF_INIT;
	struct strbuf b_tree_rev = STRBUF_INIT;
	struct strbuf i_tree_rev = STRBUF_INIT;
	struct object_context unused;
	struct strbuf commit_buf = STRBUF_INIT;
	info->is_stash_ref = 0;

	int ret;

	const char *REV = commit;
	if (commit == NULL) {
		REV = "refs/stash@{0}";
	} else if (strlen(commit) < 3) {
		strbuf_addf(&commit_buf, "refs/stash@{%s}", commit);
		REV = commit_buf.buf;
	}
	info->REV = REV;

	strbuf_addf(&w_commit_rev, "%s", REV);
	strbuf_addf(&b_commit_rev, "%s^1", REV);
	strbuf_addf(&i_commit_rev, "%s^2", REV);
	strbuf_addf(&w_tree_rev, "%s:", REV);
	strbuf_addf(&b_tree_rev, "%s^1:", REV);
	strbuf_addf(&i_tree_rev, "%s^2:", REV);


	ret = (
		get_sha1_with_context(w_commit_rev.buf, 0, info->w_commit, &unused) == 0 &&
		get_sha1_with_context(b_commit_rev.buf, 0, info->b_commit, &unused) == 0 &&
		get_sha1_with_context(i_commit_rev.buf, 0, info->i_commit, &unused) == 0 &&
		get_sha1_with_context(w_tree_rev.buf, 0, info->w_tree, &unused) == 0 &&
		get_sha1_with_context(b_tree_rev.buf, 0, info->b_tree, &unused) == 0 &&
		get_sha1_with_context(i_tree_rev.buf, 0, info->i_tree, &unused) == 0);

	/*char *full = NULL;
	unsigned char discard[20];
	dwim_ref(REV, strlen(REV), discard, &full);
		printf("asdfasdfsadf %s %s\n", full, REV);
	if (full) {
		info->is_stash_ref = strcmp(full, "refs/stash") == 0;
		}
	free(full);*/
	info->is_stash_ref = REV[4] == '/';

	return ret;
}

struct foo_callback_data {
	const char **argv;
};

static void foo_callback(struct diff_queue_struct *q,
				struct diff_options *opt, void *cbdata)
{
	int i;
	struct stat st;
	struct foo_callback_data *data = cbdata;

	for (i = 0; i < q->nr; i++) {
		struct diff_filepair *p = q->queue[i];
		const char *path = p->one->path;
		if (data->argv) {
			int found = 0;
			int i = 0;
			const char *arg = data->argv[i++];
			while (arg != NULL) {
				if (strcmp(arg, path) == 0) {
					found = 1;
					break;
				}
				arg = data->argv[i++];
			}
			if (found == 0) {
				continue;
			}
		}
		remove_file_from_index(&the_index, path);
		if (!lstat(path, &st))
			add_to_index(&the_index, path, &st, 0);

	}
}


static int do_create_stash(struct stash_info *stash_info, const char *prefix, const char *message, int include_untracked, const char **argv)
{
	struct object_id curr_head;
	char *branch_path = NULL;
	const char *branch_name;
	unsigned char i_tree[20];
	unsigned char w_tree[20];
	unsigned char w_commit[20];
	unsigned char i_commit[20];
	unsigned char b_commit[20];
	struct commit_list *parents = NULL;
	int ret;

	struct commit *c = NULL;

	refresh_index(&the_index, REFRESH_QUIET, NULL, NULL, NULL);
	//if (check_no_changes(prefix))
	//	return 0;

	if (get_sha1_tree("HEAD", b_commit)) {
		printf("You do not have the initial commit yet");
		return 1;
	}


	branch_path = resolve_refdup("HEAD", 0, curr_head.hash, NULL);

	if (branch_path == NULL) {
		branch_name = "(no_branch)";
	} else {
		skip_prefix(branch_path, "refs/heads/", &branch_name);
	}


	ret = write_cache_as_tree(i_tree, 0, NULL);

	c = lookup_commit(b_commit);

	struct strbuf out = STRBUF_INIT;
	struct pretty_print_context ctx = {0};
	ctx.output_encoding = get_log_output_encoding();
	ctx.abbrev = 1;
	ctx.fmt = CMIT_FMT_ONELINE;
	const char *hash = find_unique_abbrev(c->object.oid.hash, DEFAULT_ABBREV);


	strbuf_addf(&out, "%s: %s ", branch_name, hash);
	pretty_print_commit(&ctx, c, &out);


	commit_list_insert(lookup_commit(b_commit), &parents);

	ret = commit_tree(out.buf, out.len, i_tree, parents, i_commit, NULL, NULL);
	//printf("%s\n", sha1_to_hex(i_commit));


	struct unpack_trees_options opts;
	int nr_trees = 1;
	struct tree_desc t[MAX_UNPACK_TREES];
	struct tree *tree;

	memset(&opts, 0, sizeof(opts));

	tree = parse_tree_indirect(i_tree);
	parse_tree(tree);

	opts.head_idx = 1;
	opts.src_index = &the_index;
	opts.dst_index = &the_index;
	opts.merge = 1;
	opts.fn = oneway_merge;

	init_tree_desc(t, tree->buffer, tree->size);

	if (unpack_trees(nr_trees, t, &opts))
		return -1;

	prime_cache_tree(&the_index, tree);

	struct rev_info rev;
	int cached = 0;

	init_revisions(&rev, prefix);
	setup_revisions(0, NULL, &rev, NULL);
	rev.diffopt.output_format |= DIFF_FORMAT_CALLBACK;
	struct foo_callback_data data;
	data.argv = argv;
	rev.diffopt.format_callback_data = &data;
	rev.diffopt.format_callback = foo_callback;
	diff_setup_done(&rev.diffopt);
	//setup_revisions(0, NULL, &rev, NULL);
	//struct tree *head_tree = lookup_tree(head.hash);
	struct object *obj = parse_object(b_commit);
	add_pending_object(&rev, obj, "");
	int result = run_diff_index(&rev, cached);

	ret = write_cache_as_tree(w_tree, 0, NULL);
	//printf("wtree: %s\n", sha1_to_hex(w_tree));

	parents = NULL;

	commit_list_insert(lookup_commit(i_commit), &parents);
	commit_list_insert(lookup_commit(b_commit), &parents);


	struct strbuf out2 = STRBUF_INIT;

	if (message != NULL && strlen(message) != 0) {
		strbuf_addf(&out2, "On %s: %s", branch_name, message);
	} else {
		strbuf_addf(&out2, "WIP on %s ", out.buf);
	}

	ret = commit_tree(out2.buf, out2.len, w_tree, parents, w_commit, NULL, NULL);

	if (stash_info) {
		memcpy(stash_info->w_commit, w_commit, 20);
		memcpy(stash_info->i_tree, i_tree, 20);
		stash_info->message = out2.buf;
	}

	/*printf("%s\n", sha1_to_hex(w_commit));
	printf("%s\n", sha1_to_hex(b_commit));
	printf("%s\n", sha1_to_hex(i_tree));
	printf("%s\n", sha1_to_hex(i_commit));
	printf("%s\n", out2.buf);*/

	//printf("got to bottom!\n");
	//if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK)) {
	//	return error(_("unable to write new index file"));
	//}
	free(branch_path);

	return 0;
}

static int create_stash(int argc, const char **argv, const char *prefix)
{
	int include_untracked = 0;
	const char *message = NULL;
	struct option options[] = {
		OPT_BOOL('u', "include-untracked", &include_untracked,
			 N_("perform 'git stash next'")),
		OPT_STRING('m', "message", &message, N_("message"),
			 N_("perform 'git stash next'")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, 0);

	if (argc != 0) {
		struct strbuf out = STRBUF_INIT;
		for (int i = 0; i < argc; ++i) {
			if (i != 0) {
				strbuf_addf(&out, " ");
			}
			strbuf_addf(&out, "%s", argv[i]);
		}
		message = out.buf;
	}

	struct stash_info info = {0};

	int result = do_create_stash(&info, prefix, message, include_untracked, NULL);
	printf("%s\n", sha1_to_hex(info.w_commit));
	return result;
}

static int do_store_stash(const char *prefix, const char *message, unsigned char w_commit[20])
{
	return update_ref(message, ref_stash, w_commit, NULL, REF_FORCE_CREATE_REFLOG, UPDATE_REFS_DIE_ON_ERR);
}

static int store_stash(int argc, const char **argv, const char *prefix)
{
	const char *message;
	struct option options[] = {
		OPT_STRING('m', "message", &message, N_("message"),
			 N_("perform 'git stash next'")),
		OPT_END()
	};
	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, 0);

	if (message == NULL) {
		message = "Create via \"git stash store\".";
	}

	if (argc == 0) {
		die("no commit?");
	}

	unsigned char sha1[20];
	const char *commit = argv[0];

	if (get_sha1(commit, sha1)) {
		die("%s: not a valid SHA1", commit);
	}

	return do_store_stash(prefix, message, sha1);
}

static int do_clear_stash()
{
	unsigned char w_commit[20];
	struct object_context unused;
	int ret;
	ret = get_sha1_with_context(ref_stash, 0, w_commit, &unused);
	if (ret != 0) {
		return 0;
	}
	return delete_ref("", ref_stash, w_commit, 0);
}

static int clear_stash(int argc, const char **argv, const char *prefix)
{
	struct option options[] = {
		OPT_END()
	};
	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, 0);

	return do_clear_stash();
}

static int reset_tree(unsigned char i_tree[20], int update, int reset)
{
	struct unpack_trees_options opts;
	int nr_trees = 1;
	struct tree_desc t[MAX_UNPACK_TREES];
	struct tree *tree;

	refresh_index(&the_index, REFRESH_QUIET, NULL, NULL, NULL);
	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);

	memset(&opts, 0, sizeof(opts));

	tree = parse_tree_indirect(i_tree);
	parse_tree(tree);
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

	prime_cache_tree(&the_index, tree);

	if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK)) {
		return error(_("unable to write new index file"));
	}
}

static int do_push_stash(const char *prefix, const char *message, int keep_index, const char **argv)
{
	int result;

	refresh_index(&the_index, REFRESH_QUIET, NULL, NULL, NULL);
	if (check_no_changes(prefix)) {
		printf("No local changes to save");
		return 0;
	}

	if (!reflog_exists(ref_stash)) {
		result = do_clear_stash();
		if (result != 0) {
			error(_("Cannot initialize stashs"));
			return result;
		}
	}

	struct stash_info info = {0};

	do_create_stash(&info, prefix, message, 0, argv);
	result = do_store_stash(prefix, info.message, info.w_commit);

	if (result == 0 && !quiet) {
		printf("Saved working directory and index state $stash_msg\n");
	}

	if (quiet) {
		cmd_reset(ARRAY_SIZE(reset_quiet_args) - 1, reset_quiet_args, prefix);
	} else {
		cmd_reset(ARRAY_SIZE(reset_args) - 1, reset_args, prefix);
	}

	if (keep_index) {
		reset_tree(info.i_tree, 1, 1);
	}

	return 0;
}


static int push_stash(int argc, const char **argv, const char *prefix)
{
	const char *message = NULL;
	int include_untracked = 0;
	int keep_index = 0;
	struct option options[] = {
		OPT_BOOL('u', "include-untracked", &include_untracked,
			 N_("perform 'git stash next'")),
		OPT_BOOL('k', "keep-index", &keep_index,
			 N_("perform 'git stash next'")),
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
		OPT_STRING('m', "message", &message, N_("message"),
			 N_("perform 'git stash next'")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, PARSE_OPT_STOP_AT_NON_OPTION);

	const char **args = NULL;

	if (argc != 0) {
		args = argv;
	}

	return do_push_stash(prefix, message, keep_index, args);
}

static int save_stash(int argc, const char **argv, const char *prefix)
{
	const char *message = NULL;
	int include_untracked = 0;
	int keep_index = 0;
	struct option options[] = {
		OPT_BOOL('u', "include-untracked", &include_untracked,
			 N_("perform 'git stash next'")),
		OPT_BOOL('k', "keep-index", &keep_index,
			 N_("perform 'git stash next'")),
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
		OPT_STRING('m', "message", &message, N_("message"),
			 N_("perform 'git stash next'")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, PARSE_OPT_STOP_AT_NON_OPTION);

	return do_push_stash(message, prefix, keep_index, NULL);
}

static int do_apply_stash(const char *prefix, const char *commit, int index)
{
	struct object_id h1, h2;
	struct merge_options o;
	int ret;
	struct stash_info info = {0};
	unsigned char c_tree[20];
	unsigned char index_tree[20];

	ret = get_stash_info(&info, commit);

	if (!ret)
		printf("invalid");

	refresh_index(&the_index, REFRESH_QUIET, NULL, NULL, NULL);

	ret = write_cache_as_tree(c_tree, 0, NULL);
	const char *me = "git-stash";
	switch (ret) {
	case 0:
		break;
	case WRITE_TREE_UNREADABLE_INDEX:
		die("%s: error reading the index", me);
		break;
	case WRITE_TREE_UNMERGED_INDEX:
		die("%s: error building trees", me);
		break;
	case WRITE_TREE_PREFIX_ERROR:
		die("%s: prefix %s not found", me, prefix);
		break;
	}


	if (index) {
		if (memcmp(info.b_tree, info.i_tree, 20) == 0 || memcmp(c_tree, info.i_tree, 20) == 0) {
			index = 0;
		} else {
		struct child_process cp = CHILD_PROCESS_INIT;
		struct child_process cp2 = CHILD_PROCESS_INIT;
		cp.git_cmd = 1;
		argv_array_push(&cp.args, "diff-tree");
		argv_array_push(&cp.args, "--binary");
		argv_array_pushf(&cp.args, "%s^2^..%s^2", sha1_to_hex(info.w_commit), sha1_to_hex(info.w_commit));
		struct strbuf out = STRBUF_INIT;
		pipe_command(&cp, NULL, 0, &out, 0, NULL, 0);

		cp2.git_cmd = 1;
		argv_array_push(&cp2.args, "apply");
		argv_array_push(&cp2.args, "--cached");
		pipe_command(&cp2, out.buf, out.len, NULL, 0, NULL, 0);

		discard_cache();
		read_cache();
		ret = write_cache_as_tree(index_tree, 0, NULL);

		struct argv_array args;
		argv_array_init(&args);
		argv_array_push(&args, "reset");
		cmd_reset(args.argc, args.argv, prefix);
		}
	}


	init_merge_options(&o);

	o.branch1 = sha1_to_hex(c_tree);
	o.branch2 = sha1_to_hex(info.w_tree);

	if (get_oid(o.branch1, &h1))
		die(_("could not resolve ref '%s'"), o.branch1);
	if (get_oid(o.branch2, &h2))
		die(_("could not resolve ref '%s'"), o.branch2);

	//o.branch1 = better_branch_name(o.branch1);
	//o.branch2 = better_branch_name(o.branch2);

	if (!quiet) {
		//printf(_("Merging %s with %s\n"), o.branch1, o.branch2);
	}

	//if (quiet) {
		o.verbosity = 0;
	//}

	const struct object_id *bases[1];
	int bases_count = 1;
	struct commit *result;
	struct object_id *oid = xmalloc(sizeof(struct object_id));
	get_oid(sha1_to_hex(info.b_tree), oid);
	bases[0] = oid;

	ret = merge_recursive_generic(&o, &h1, &h2, bases_count, bases, &result);
	if (ret < 0)
		return 128; /* die() error code */

	if (index) {
		reset_tree(index_tree, 0, 0);
	} else {
		reset_tree(c_tree, 0, 1);
	}

	if (!quiet) {
		struct argv_array args;
		argv_array_init(&args);
		argv_array_push(&args, "status");
		cmd_status(args.argc, args.argv, prefix);
	}

	return 0;
}

static int apply_stash(int argc, const char **argv, const char *prefix)
{
	const char *commit = NULL;
	int index;
	struct option options[] = {
		OPT_BOOL(0, "index", &index,
			 N_("perform 'git stash next'")),
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, 0);

	if (argc == 1) {
		commit = argv[0];
	}

	return do_apply_stash(prefix, commit, index);
}

static int do_drop_stash(const char *prefix, const char *commit)
{
	struct argv_array args;
	int ret;
	struct stash_info info = {0};

	ret = get_stash_info(&info, commit);
	argv_array_init(&args);
	argv_array_push(&args, "reflog");
	argv_array_push(&args, "delete");
	argv_array_push(&args, "--updateref");
	argv_array_push(&args, "--rewrite");
	argv_array_push(&args, info.REV);
	ret = cmd_reflog(args.argc, args.argv, prefix);
	if (ret == 0) {
		if (!quiet) {
			printf("Dropped\n");
		}
	} else {
		die("could not drop");
	}

	struct child_process cp = CHILD_PROCESS_INIT;
	cp.git_cmd = 1;
	argv_array_init(&cp.args);
	argv_array_push(&cp.args, "rev-parse");
	argv_array_push(&cp.args, "--verify");
	argv_array_push(&cp.args, "--quiet");
	argv_array_push(&cp.args, "refs/stash@{0}");
	ret = run_command(&cp);

	if (ret != 0) {
		do_clear_stash();
	}
	return 0;
}

static int drop_stash(int argc, const char **argv, const char *prefix)
{
	const char *commit = NULL;
	struct option options[] = {
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, 0);

	if (argc == 1) {
		commit = argv[0];
	}

	return do_drop_stash(prefix, commit);
}

static int list_stash(int argc, const char **argv, const char *prefix)
{
	struct option options[] = {
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, PARSE_OPT_KEEP_UNKNOWN);

	unsigned char w_commit[20];
	struct object_context unused;
	int ret;
	ret = get_sha1_with_context(ref_stash, 0, w_commit, &unused);
	if (ret != 0) {
		return 0;
	}

	struct argv_array args;
	argv_array_init(&args);
	argv_array_push(&args, "log");
	argv_array_push(&args, "--format=%gd: %gs");
	argv_array_push(&args, "-g");
	argv_array_push(&args, "--first-parent");
	argv_array_push(&args, "-m");
	argv_array_pushv(&args, argv);
	argv_array_push(&args, "refs/stash");
	ret = cmd_log(args.argc, args.argv, prefix);

	return ret;
}

static int show_stash(int argc, const char **argv, const char *prefix)
{
	struct argv_array args;
	struct stash_info info = {0};
	const char *commit = NULL;
	int ret;
	int numstat = 0;
	int patch = 0;

	struct option options[] = {
		OPT_BOOL(0, "numstat", &numstat,
			 N_("perform 'git stash next'")),
		OPT_BOOL('p', "patch", &patch,
			 N_("perform 'git stash next'")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, 0);

	if (argc == 1) {
		commit = argv[0];
	}
	ret = get_stash_info(&info, commit);
	if (!ret) {
		die("invalid");
	}
	argv_array_init(&args);
	argv_array_push(&args, "diff");
	if (numstat) {
		argv_array_push(&args, "--numstat");
	} else if (patch) {
		argv_array_push(&args, "-p");
	} else {
		argv_array_push(&args, "--stat");
	}
	argv_array_push(&args, sha1_to_hex(info.b_commit));
	argv_array_push(&args, sha1_to_hex(info.w_commit));
	return cmd_diff(args.argc, args.argv, prefix);
}

static int do_pop_stash(const char *prefix, const char *commit, int index)
{

	struct stash_info info = {0};

	get_stash_info(&info, commit);
	if (!info.is_stash_ref) {
		return 1;
	}

	do_apply_stash(prefix, commit, index);
	do_drop_stash(prefix, commit);
	return 0;
}

static int pop_stash(int argc, const char **argv, const char *prefix)
{
	int index = 0;
	const char *commit = NULL;
	struct option options[] = {
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
		OPT_BOOL(0, "index", &index,
			 N_("perform 'git stash next'")),
		OPT_END()
	};


	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, 0);

	if (argc == 1) {
		commit = argv[0];
	}

	return do_pop_stash(prefix, commit, index);
}

static int branch_stash(int argc, const char **argv, const char *prefix)
{
	const char *commit = NULL, *branch = NULL;
	int ret;
	struct option options[] = {
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, 0);

	if (argc != 0) {
		branch = argv[0];
		if (argc == 2) {
			commit = argv[1];
		}
	}
	struct stash_info info = {0};

	ret = get_stash_info(&info, commit);

	struct argv_array args;
	argv_array_init(&args);
	argv_array_push(&args, "checkout");
	argv_array_push(&args, "-b");
	argv_array_push(&args, branch);
	argv_array_push(&args, sha1_to_hex(info.b_commit));
	ret = cmd_checkout(args.argc, args.argv, prefix);

	ret = do_apply_stash(prefix, commit, 1);
	if (info.is_stash_ref) {
		ret = do_drop_stash(prefix, commit);
	}

	return ret;
}

int cmd_stash(int argc, const char **argv, const char *prefix)
{
	int result = 0;

	struct option options[] = {
		OPT_END()
	};

	git_config(git_default_config, NULL);

	argc = parse_options(argc, argv, prefix, options, git_stash_helper_usage,
		PARSE_OPT_KEEP_UNKNOWN);

	if (argc < 1) {
		result = do_push_stash(NULL, prefix, 0, NULL);
	} else if (!strcmp(argv[0], "list"))
		result = list_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "show"))
		result = show_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "save"))
		result = save_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "push"))
		result = push_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "apply"))
		result = apply_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "clear"))
		result = clear_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "create"))
		result = create_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "store"))
		result = store_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "drop"))
		result = drop_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "pop"))
		result = pop_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "branch"))
		result = branch_stash(argc, argv, prefix);
	else {
		if (argv[0][0] == '-') {
			struct argv_array args;
			argv_array_init(&args);
			argv_array_push(&args, "push");
			argv_array_pushv(&args, argv);
			result = push_stash(args.argc, args.argv, prefix);
			if (result == 0) {
				printf("To restore them type \"git stash apply\"\n");
			}
		} else {
			error(_("Unknown subcommand: %s"), argv[0]);
			result = 1;
		}
	}

	return result;
}
