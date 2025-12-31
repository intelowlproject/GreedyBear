# Composite action save APT cache

This action saves the APT cache, almost always located at `/var/cache/apt/archives/*.deb` to the GitHub's cache.

Combined with [**restore_apt_cache**](../restore_apt_cache/README.md) helps save time by avoiding the download of APT requirements.

The action is composed of two steps:

1. **Compute APT requirements file SHA256 hash** - This step uses the [**misc/compute_files_hash**](../../misc/compute_files_hash/README.md) action to compute the SHA256 hash of the APT requriments file that will be part of the cache key.
2. **Save APT cache** - This step does the real caching on GitHub. The GitHub's [**cache/save**](https://github.com/actions/cache/blob/main/save/README.md) is used with the following parameters:
   1. **path** - A list of files, directories, or paths to cache - set to `/var/cache/apt/archives/*.deb` to save all `*.deb` files in APT cache.
   2. **key** - An explicit key for a cache entry - set to the combination of three strings:
      1. *git_reference*, provided as an input to the action.
      2. A static part, `-apt-`
      3. The previously computed SHA256 hash of the APT requirements file.

## Documentation

### Inputs

* **apt_requirements_file_path** - Required - Path to the APT requirements file. It will be used to compute a SHA256 hash used in the cache key.
* **git_reference** - Optional - A git reference that will be used to build the cache key. It defaults to `github.ref_name` which is a context variable containing **the short ref name of the branch or tag that triggered the workflow run**. For example it may be `feature-branch-1` or, for pull requests, `<pr_number>/merge`.
