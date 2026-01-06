# Composite action restore APT cache

This action restores an APT cache from GitHub's cache.

Combined with [**save_apt_cache**](../save_apt_cache/README.md), it helps save time by avoiding the download of APT requirements.

The action is composed of five steps:

1. **Compute APT requirements files SHA256 hash** - This step uses [**misc/compute_files_hash**](../../misc/compute_files_hash/README.md) action to compute a single SHA256 hash of the APT requirements file described by the *apt_rquirements_file_path* input variable. The computed SHA256 hash will be part of the cache key.
2. **Backup `/var/cache/apt/archives permissions`** - This step backs up the permissions associated to the `/var/cache/apt/archives` directory. So, after restoring the APT cache they can be restored to the original ones.
3. **Add write permissions for all to `/var/cache/apt/archives`** - This step sets the write permission to the `/var/cache/apt/archives`. This is crucial because the [**cache/restore**](https://github.com/actions/cache/blob/main/restore/README.md) GitHub's action needs to be able to write to it. Without setting the correct write permission, a permission error is raised.
4. **Restore APT cache** - This step restores the APT cache. It uses the GitHub's [**cache/restore**](https://github.com/actions/cache/blob/main/restore/README.md) action with the following parameters:
   * **path** - A list of files, directories, or paths to restore - set to `/var/cache/apt/archives/*.deb`.
   * **key** - An explicit key for a cache entry - set to the combination of three strings:
      * *git_reference*, provided as an input to the action.
      * A static part, `-apt-`
      * The previously computed SHA256 hash of the APT requirements file.
5. **Restore original permissions to `/var/cache/apt/archives` and delete backup** - This step restore the original permissions to the `/var/cache/apt/archives` directory. Finally, the backup file is deleted.

## Documentation

### Inputs

* **apt_requirements_file_path** - Required - Path to the APT requirements file. It will be used to compute a SHA256 hash used in the cache key.
* **git_reference** - Optional - A git reference that will be used to build the cache key. It defaults to `github.ref_name` which is a context variable containing **the short ref name of the branch or tag that triggered the workflow run**. For example it may be `feature-branch-1` or, for pull requests, `<pr_number>/merge`.

### Outputs

* **cache-hit** - A boolean value which is true when APT cache is found in the GitHub's cache, false otherwise.
