# Composite action restore pip cache

This action restores the pip download cache from GitHub's cache.

The action is composed of four steps:

1. **Generate random UUID** - This step computes a random UUID, using the shell command `uuidgen`, which will be part of the cache key. Since pip cache will always be restored when a virtual environment is not found on GitHub's cache, a random UUID is required to generate a cache miss.
2. **Get pip cache directory** - This step retrieves the path to the pip cache. If *custom_pip_cache_path* is not an empty string, it will be used as pip cache path. Otherwise, the pip cache will be computed using `pip cache dir`.
3. **Restore pip cache** - This step performs the heavy lifting of the restoring. Using GitHub's [**cache/restore**](https://github.com/actions/cache/blob/main/restore/README.md) action, the cache is restored using a **partial match**. This is performed by setting the following [inputs](https://github.com/actions/cache/tree/main/restore#inputs):
   1. **key** - an explicit key for a cache entry - will be set to a random UUID which will always trigger a cache miss.
   2. **path** - a list of files, directories, paths to restore - will be set to the pip download cache path.
   3. **restore-keys** - an ordered list of prefix-matched keys to use for restoring stale cache if no cache hit occurred for key - will be set to `<git_reference>-pip-cache-` to restore the most recent pip cache for the chosen git reference.
4. **Explain cache output** - This step analyze the results of the [**cache/restore**](https://github.com/actions/cache/blob/main/restore/README.md) action and sets *real_cache_hit* environment variable to true if there was a match, false otherwise. This is necessary because, in the case of a **partial match**, the *cache-hit*, output of [**cache/restore**](https://github.com/actions/cache/blob/main/restore/README.md), will be false. Instead, we use the `cache-matched-key`, another output of [**cache/restore**](https://github.com/actions/cache/blob/main/restore/README.md), which contains a reference for both **partial** and full matches, but will be empty in the case of a cache miss.

NOTE:

This action, despite seeming a bit unusual, is correct because GitHub does not allow cache updates or overwrites.

Let's think about a real-world scenario:

A user updates the requirements file.

In this case our query to GitHub's cache for the previously cached virtual environment will **always** miss. This happens because changing the requirements file results in a new SHA256 hash, so the cache key changes.

Thus, we aim to restore the pip cache to at least *mitigate* the impact of the changes in the requirements. Specifically, we want to save time by avoiding the download of packages that did not change.

Next, we try to query the GitHub's cache for the previously cached pip cache. However, there are a few issues:

1. We cannot use the SHA256 of the requirements file because it has changed, leading to cache misses.
2. We cannot create a cache key without a random component because, as said earlier, GitHub does not allow overwriting or updating of a cache item. For example, a cache key like `develop-pip-cache-` would generate an error when attempting to save a new cache if one already exists with the same name.

## Documentation

### Inputs

* **custom_pip_cache** - Optional - Path to the pip cache. It can be used for setting a custom pip cache path. It defaults to an empty string. In this case, the pip cache path will be computed using `pip cache dir`. More information regarding the previous command is available [here](https://pip.pypa.io/en/stable/cli/pip_cache/#description)
* **git_reference** - Optional - A git reference that will be used to build the cache key. It defaults to `github.ref_name` which is a context variable containing **the short ref name of the branch or tag that triggered the workflow run**. For example it may be `feature-branch-1` or, for pull requests, `<pr_number>/merge`.

### Outputs

* **cache-hit** - A boolean value which states whether pip cache was found on GitHub's cache or not.
