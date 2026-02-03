# Composite action save pip cache

This action saves the pip download cache.

Every time a user runs `pip install <package_name>`, pip downloads the package and all its dependencies.The packages are saved in a directory which, by default, is located at `~/.cache/pip`.
Saving this cache in GitHub's cache allows us to save time when installing those packages. As a matter of fact, before installing packages, pip's cache can be restored using [**restore_pip_cache**](../restore_pip_cache/README.md) action.

The action is composed of three steps:

1. **Generate random UUID** - This step computes a random UUID, using shell command `uuidgen`, which will be part of the cache key. The uniqueness of the UUID ensures that there will be no collisions between cache keys, which is crucial because **GitHub won't allow the creation of two caches with the same key** (cache update/overwrite **is not supported**).
2. **Get pip cache directory** - This step retrieves the path to the pip cache. If *custom_pip_cache_path* is not an empty string, it will be used as pip cache path. Otherwise, the pip cache will be computed using `pip cache dir`.
3. **Save pip cache** - This step performs the heavy lifting of the caching. Using GitHub's [**cache/save**](https://github.com/actions/cache/blob/main/save/README.md) action, the cache is saved with a key composed of:
   1. The git reference input, *git_reference*
   2. A static part, `pip-cache`
   3. The previously computed UUID

## Documentation

### Inputs

* **custom_pip_cache** - Optional - Path to the pip cache. It can be used for setting a custom pip cache path. It defaults to an empty string. In this case, the pip cache path will be computed using `pip cache dir`. More information regarding the previous command is available [here](https://pip.pypa.io/en/stable/cli/pip_cache/#description)
* **git_reference** - Optional - A git reference that will be used to build the cache key. It defaults to `github.ref_name` which is a context variable containing **the short ref name of the branch or tag that triggered the workflow run**. For example it may be `feature-branch-1` or, for pull requests, `<pr_number>/merge`.
