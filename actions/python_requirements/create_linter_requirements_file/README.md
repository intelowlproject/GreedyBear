# Composite action create Python linter requirements file

This action creates the `requirements-linters.txt` file which will contain all **linter dependencies** required by the CI.
The user can then choose which linters will be run, and hence written to the `requirements-linters.txt`, by the CI by setting some flags to true like *use_black*.

As of today only the following linters are supported:

* `autoflake`
* `bandit`
* `black`
* `flake8`
* `flake8-django`
* `isort`
* `pylint`
* `pylint-django`
* `ruff`

## Documentation

### Inputs

* **install_from** - Optional - The path used as working directory when creating the `requirements-linters.txt` file. It defaults to the current directory (i.e. `.`).
* `project_linter_requirements_file` - Optional - The path of a project `requirements-linters.txt`. This was designed in case requirements for linters other than `autoflake`, `bandit`, `black`, `flake8`, `flake8-django`, `isort`, `pylint` and `pylint-django` are required. If specified, the dependencies in the project `requirements-linters.txt` will be appended in the newly created `requirements-linters.txt`. **Be careful: if a relative path is used this will depend on *install_from*.** Defaults to empty strings, and hence **no custom `requirements-linters.txt`**.
* **django_settings_module** - Optional - Path to the Django settings file. It's used to make GitHub action aware of Django presence. In the case of a Django project, `flake8-django` and `pylint-django`, may be used and hence they will be added to the newly created requirements file. **Be careful: if a relative path is used this will depend on *install_from*.** Defaults to empty strings, and hence **no Django settings file**.
* **use_autoflake** - Optional - Flag to state whether to use or not `autoflake` linter. It defaults to false.
* **use_bandit** - Optional - Flag to state whether to use or not `bandit` linter. It defaults to false.
* **use_black** - Optional - Flag to state whether to use `black` formatter. It defaults to false.
* **use_flake8** - Optional - Flag to state whether to use or not `flake8` linter. It defaults to false.
* **use_isort** - Optional - Flag to state whether to use or not `isort` formatter. It defaults to false.
* **use_pylint** - Optional - Flag to state whether to use or not `pylint` linter. It defaults to false.
* **use_ruff_formatter** - Optional - Flag to state whether to use `ruff` **formatter** (so without the linting). It defaults to false.
* **use_ruff_linter** - Optional - Flag to state whether to use `ruff` **linter** (so without the formatting). It defaults to false.
