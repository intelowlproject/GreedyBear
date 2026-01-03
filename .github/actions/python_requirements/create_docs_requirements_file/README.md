# Composite action create Python docs requirements file

This action creates the `requirements-docs.txt` file. This is a Python requirements file that will contain all **dependencies required to build the documentation**.

## Documentation

### Inputs

* **install_from** - Optional - The path used as working directory when creating the `requirements-docs.txt` file. It defaults to the current directory (i.e. `.`).
* **project_docs_requirements_file** - Optional - The path of a project `requirements-docs.txt`. This was designed in case requirements to build documentation other than rstcheck, sphinx, sphinx_rtd_theme, sphinxcontrib-spelling and sphinxcontrib-django2 are required. If specified, the dependencies in the project `requirements-docs.txt` will be appended in the newly created `requirements-docs.txt`. **Be careful: if a relative path is used this will depend on *install_from*.** Defaults to empty strings, and hence **no custom `requirements-docs.txt`**.
* **django_settings_module** - Optional - Path to the Django settings file. It's used to make GitHub action aware of Django presence. In this case, `sphinxcontrib-django2` is also added to the newly created requirement file. **Be careful: if a relative path is used this will depend on *install_from*.** Defaults to empty strings, and hence **no Django settings file**.
* **check_docs_directory** - Optional - Path that will be used by rstcheck to check documentation. **Be careful: if a relative path is used this will depend on *install_from*.** Defaults to empty strings, and hence **documentation won't be checked**.
