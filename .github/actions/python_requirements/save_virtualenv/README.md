# Composite action save Python virtual environment

This action saves a Python virtual environment to GitHub's cache.

Combined with [**restore_virtualenv**](../restore_virtualenv/README.md), **it helps save time by avoiding the installation of Python requirements**.

The action is composed of two steps:

1. **Compute requirements files SHA256 hash** - This step uses [**misc/compute_files_hash**](../../misc/compute_files_hash/README.md) to compute a single SHA256 hash of the files described by the *requirements_paths*. The computed SHA256 hash will be part of the cache key.
2. **Cache virtual environment** - This step does the heavy lifting of saving the virtual environment to GitHub's cache. It uses the GitHub's [**cache/save**](https://github.com/actions/cache/blob/main/save/README.md) action with the following parameters:
   1. **path** - A list of files, directories, or paths to cache - set to the virtual environment path input variable *virtual_environment_path*.
   2. **key** - An explicit key for a cache entry - set to the combination of three strings:
      1. *git_reference*, provided as an input to the action.
      2. A static part, `-venv-`
      3. The previously computed SHA256 hash of the requirements files.

## Documentation

### Inputs

* **virtual_environment_path** - Optional - Path where the virtual environment is located. It may be used to provide a custom path for the virtual environment. It defaults to `.venv`.
* **requirements_paths** - Required - A space separated list of requirements file paths. They will be used to compute a SHA256 hash used in the cache key.
* **git_reference** - Optional - A git reference that will be used to build the cache key. It defaults to `github.ref_name` which is a context variable containing **the short ref name of the branch or tag that triggered the workflow run**. For example it may be `feature-branch-1` or, for pull requests, `<pr_number>/merge`.
