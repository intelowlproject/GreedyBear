# Changelog
From the v1.3.0 onwards please check the Release Pages on Github for information regarding the changelog

## Certego .github Package Changelog

## 2.0.x
### 2.0.0
#### Features
* Added "release.yml" action to to push containers to AWS ECR
* Added *create_apt_cache.yaml* workflow to cache APT requirements each time a commit is pushed on selected branch and **when the requirements file has changed**.
* Added documentation.
* Added "Ruff" to the list of available Python linters.
#### Bugfix
* Updated python linters also in '_python.yml' workflow (missing from previous release)
* Explicitly disabled `xpack.security` in Elasticsearch container, since it is enabled by default in newer versions of Elasticsearch
* Added missing inputs for "create_linter_requirements_file" action.
#### Changes
* Deprecation of license check table-headers
* Updated Python linters:
  * bandit 1.7.9 -> 1.8.3
  * black 24.8.0 -> 25.1.0
  * flake8 7.1.1 -> 7.1.2
  * isort 5.13.2 -> 6.0.1
  * pylint-django 2.5.5 -> 2.6.1
  * pylint 3.2.6 -> 3.3.5
* Removed `awalsh128/cache-apt-pkgs-action@latest` action and rewrote APT caching using GitHub's `actions/cache/restore@v4` and `actions/cache/save@v4`.
* Added both frontend and backend exclusions on _detect_changes.yaml (paths that won't be considered by git diff)
* Updated CodeQL action v2 -> v3 (v2 has been [deprecated](https://github.blog/changelog/2024-01-12-code-scanning-deprecation-of-codeql-action-v2/) on december '24)
* Removed `setup-python-dependencies` from `codeql/action.yml` since it has no effect anymore. See [this](https://github.blog/changelog/2024-01-23-codeql-2-16-python-dependency-installation-disabled-new-queries-and-bug-fixes/) for more information.
* Linters versions in step `Create requirements-linters.txt` of `_python.yml` action are now computed according to `configurations/python_linters/requirements-linters.txt`. As of now, linter updates are only required in `configurations/python_linters/requirements-linters.txt`.
* Reworked Python requirements caching.
* Updated some Github actions:
  * setup-python v4 -> v5
  * action-gh-release v1 -> v2
* Added "Install system dependencies required by Python packages" step to "Create Python cache" workflow.

## GreedyBear Changelog

## [v1.2.1](https://github.com/honeynet/GreedyBear/releases/tag/v1.2.1)
* Fixes and adjusts in the "Feeds Page"
* Added verification of Registration Setup
* Adjusted management of frontend env variables
* Fixed General Honeypots name extraction in the Enrichment APIs

## [v1.2.0](https://github.com/honeynet/GreedyBear/releases/tag/v1.2.0)
**New features**
* Added a new "Registration" page to allow people to register to the service.

**Stability issues**
* Several bug fixing and dep upgrades

## [v1.1.1](https://github.com/honeynet/GreedyBear/releases/tag/v1.1.1)
Various fixes to the previous release

## [v1.1.0](https://github.com/honeynet/GreedyBear/releases/tag/v1.1.0)
**New features**
* Added a new "Feeds" section in the GUI where it is possible to browse available feeds
* Added chance to enable/disable Honeypot Data Extraction from Django Admin
* The dashboard is now showing data from all extracted honeypots (and not only Log4j and Cowrie)

**Stability issues**
* Added Tests Framework for the React Frontend
* Main Docker Image is a lot lighter than before
* adjusted Uwsgi deployment and installer
* improved CI by integrating [Certego .github](https://github.com/certego/.github)
* several dependencies upgrades

## [v1.0.2](https://github.com/honeynet/GreedyBear/releases/tag/v1.0.2)
* Added Installer Script for GreedyBear directly on a TPOT
* other tweaks to deployment and Nginx


## [v1.0.1](https://github.com/honeynet/GreedyBear/releases/tag/v1.0.1)

Added support for all the other available honeypots! (#86)

## [v1.0.0](https://github.com/honeynet/GreedyBear/releases/tag/v1.0.0)

** FIRST RELEASE! **
A new GUI is available to explore the data with an awesome dashboard!

