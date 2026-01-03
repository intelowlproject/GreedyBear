# Composite action create Python dev requirements file

This action creates the `requirements-dev.txt` file which will contain all **development dependencies**.

As of today, the only development dependency supported is `coverage`.

## Documentation

### Inputs

* **install_from** - Optional - The path used as working directory when creating the `requirements-dev.txt` file. It defaults to the current directory (i.e. `.`).
* **project_dev_requirements_file** - Optional - The path of a project `requirements-dev.txt`. This was designed in case development requirements other than coverage are required. If specified, the dependencies in the project `requirements-dev.txt` will be appended in the newly created `requirements-dev.txt`. **Be careful: if a relative path is used this will depend on *install_from*.** Defaults to empty strings, and hence **no custom `requirements-dev.txt`**.
* **use_coverage** - Optional - Whether to use coverage or not. It defaults to false.
