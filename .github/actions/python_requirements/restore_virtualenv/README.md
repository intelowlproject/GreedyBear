# Composite action restore Python virtual environment

This action restores a Python virtual environment from GitHub's cache.

Combined with [**save_virtualenv**](../save_virtualenv/README.md), **it helps save time by avoiding the installation of Python requirements**.

The action is composed of three steps:

1. **Compute requirements files SHA256 hash** - This step uses [**misc/compute_files_hash**](../../misc/compute_files_hash/README.md) action to compute a single SHA256 hash of the files described by the *requirements_paths*. The computed SHA256 hash will be part of the cache key.
2. **Restore virtual environment** - This step does the heavy lifting of restoring the virtual environment from GitHub's cache. It uses the GitHub's [**cache/restore**](https://github.com/actions/cache/blob/main/restore/README.md) action with the following parameters:
   * **path** - A list of files, directories, or paths to restore - set to the virtual environment path input variable *virtual_environment_path*.
   * **key** - An explicit key for a cache entry - set to the combination of three strings:
      * *git_reference*, provided as an input to the action.
      * A static part, `-venv-`
      * The previously computed SHA256 hash of the requirements files.
3. **Activate restored virtual environment** - If the Python virtual environment was found in the GitHub's cache, it needs to be activated. This is performed using [**python_requirements/create_virtualenv**](../create_virtualenv/README.md) action with the following parameters:
   * **virtualenv_path** - set to the Python virtual environment path.
   * **activate_only** - set to true because it doesn't need to be created.

## Documentation

### Inputs

* **virtual_environment_path** - Optional - Path where the virtual environment is located. It may be used to provide a custom path for the virtual environment. It defaults to `.venv`.
* **requirements_paths** - Required - A space separated list of requirements file paths. They will be used to compute a SHA256 hash used in the cache key. It defaults to an empty string.
* **git_reference** - Optional - A git reference that will be used to build the cache key. It defaults to `github.ref_name` which is a context variable containing **the short ref name of the branch or tag that triggered the workflow run**. For example it may be `feature-branch-1` or, for pull requests, `<pr_number>/merge`.

### Outputs

* **cache-hit** - A boolean value which is true when virtual environment is found in the GitHub's cache, false otherwise.
