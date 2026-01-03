# Composite action create Python virtual environment

This GitHub action creates a Python virtual environment using Python's `venv` module.

When the *activate_only* flag set is to true, the virtual environment at *virtualenv_path* will only be activated—**no creation will take place**.

NOTE:

To activate a Python virtual environment, the `activate` script is often used.
However, in a GitHub Action environment, this is not enough because environment variables are "lost" at the end of the Action. For this we need to do two things:

1. Append the `VIRTUAL_ENV` environment variable to the `GITHUB_ENV` environment file. The [`GITHUB_ENV`](https://docs.github.com/en/enterprise-cloud@latest/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#setting-an-environment-variable) files makes environment variables available to any subsequent steps in a workflow job. Finally, it's important to note that `VIRTUAL_ENV` variable is created by the `activate` script and contains the path to the virtual environment.
2. Prepend the virtual environment's `bin` path to the system PATH. To allow also any subsequent steps in a workflow to be able to use it, [`GITHUB_PATH`](https://docs.github.com/en/enterprise-cloud@latest/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#adding-a-system-path) is employed.

## Documentation

### Inputs

* **virtualenv_path** - Optional - The path where the virtual environment will be created. It defaults to `.venv`.
* **activate_only** - Optional - Flag that states whether to only activate the virtual environment. If false, a new virtual environment will be created before being activated. It defaults to false.