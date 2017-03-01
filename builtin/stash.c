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
	unsigned char i_tree[20];
	unsigned char w_tree[20];
	unsigned char w_commit[20];
	unsigned char i_commit[20];
	unsigned char b_commit[20];
	const char *message;
};

static int check_no_changes(const char *prefix)
{
	return cmd_diff_index(ARRAY_SIZE(diff_index_args) - 1, diff_index_args, prefix) == 0 &&
		cmd_diff_files(ARRAY_SIZE(diff_files_args) - 1, diff_files_args, prefix) == 0;
}



static void foo_callback(struct diff_queue_struct *q,
				struct diff_options *opt, void *cbdata)
{
	int i;
	struct stat st;

	for (i = 0; i < q->nr; i++) {
		struct diff_filepair *p = q->queue[i];
		const char *path = p->one->path;
		remove_file_from_index(&the_index, path);
		if (!lstat(path, &st))
			add_to_index(&the_index, path, &st, 0);

	}
}

static int do_create_stash(struct stash_info *stash_info, const char *prefix, const char *message, int include_untracked)
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


	ret = write_cache_as_tree(i_tree, 0, prefix);

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
	rev.diffopt.format_callback = foo_callback;
	diff_setup_done(&rev.diffopt);
	//setup_revisions(0, NULL, &rev, NULL);
	//struct tree *head_tree = lookup_tree(head.hash);
	struct object *obj = parse_object(b_commit);
	add_pending_object(&rev, obj, "");
	int result = run_diff_index(&rev, cached);

	ret = write_cache_as_tree(w_tree, 0, prefix);
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

	int result = do_create_stash(&info, prefix, message, include_untracked);
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
	return 0;
}

static int do_push_stash(const char *prefix, const char *message, int keep_index)
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

	do_create_stash(&info, prefix, message, 0);
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
		struct unpack_trees_options opts;
		int nr_trees = 1;
		struct tree_desc t[MAX_UNPACK_TREES];
		struct tree *tree;

		refresh_index(&the_index, REFRESH_QUIET, NULL, NULL, NULL);
		hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);

		memset(&opts, 0, sizeof(opts));

		tree = parse_tree_indirect(info.i_tree);
		parse_tree(tree);
		init_tree_desc(t, tree->buffer, tree->size);

		opts.head_idx = 1;
		opts.src_index = &the_index;
		opts.dst_index = &the_index;
		opts.merge = 1;
		opts.reset = 1;
		opts.update = 1;
		opts.fn = oneway_merge;


		if (unpack_trees(nr_trees, t, &opts))
			return -1;

		prime_cache_tree(&the_index, tree);

		if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK)) {
			return error(_("unable to write new index file"));
		}
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
				 git_stash_helper_usage, 0);

	return do_push_stash(prefix, message, keep_index);
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
				 git_stash_helper_usage, 0);

	return do_push_stash(message, prefix, keep_index);
}

static int do_apply_stash(const char *prefix, const char *commit)
{
	unsigned char c_tree[20];
	int ret;

	refresh_index(&the_index, REFRESH_QUIET, NULL, NULL, NULL);

	ret = write_cache_as_tree(c_tree, 0, prefix);

	return 1;
}

static int apply_stash(int argc, const char **argv, const char *prefix)
{
	const char *commit = NULL;
	struct option options[] = {
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options,
				 git_stash_helper_usage, 0);

	if (argc == 1) {
		commit = argv[0];
	}

	return do_apply_stash(prefix, commit);
}

int cmd_stash(int argc, const char **argv, const char *prefix)
{
	int result = 0;

	struct option options[] = {
		OPT_END()
	};

	git_config(git_default_config, NULL);

	argc = parse_options(argc, argv, prefix, options, git_stash_helper_usage,
		PARSE_OPT_STOP_AT_NON_OPTION);

	if (argc < 1) {
		result = do_push_stash(NULL, prefix, 0);
		if (result == 0) {
			printf("To restore them type \"git stash apply\"");
		}
	} else if (!strcmp(argv[0], "create"))
		result = create_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "store"))
		result = store_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "push"))
		result = push_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "save"))
		result = save_stash(argc, argv, prefix);
	else if (!strcmp(argv[0], "apply"))
		result = apply_stash(argc, argv, prefix);
	else
		error(_("Unknown subcommand: %s"), argv[0]);


	return result;
}
