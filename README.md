<p align="center"><img src="docs/static/greedybear.png" width=350 height=404 alt="GreedyBear"/></p>

# GreedyBear
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/intelowlproject/Greedybear)](https://github.com/intelowlproject/Greedybear/releases)
[![GitHub Repo stars](https://img.shields.io/github/stars/intelowlproject/Greedybear?style=social)](https://github.com/intelowlproject/Greedybear/stargazers)
[![Twitter Follow](https://img.shields.io/twitter/follow/intel_owl?style=social)](https://twitter.com/intel_owl)
[![Linkedin](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/intelowl/)

[![CodeFactor](https://www.codefactor.io/repository/github/intelowlproject/greedybear/badge)](https://www.codefactor.io/repository/github/intelowlproject/greedybear)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![CodeQL](https://github.com/intelowlproject/GreedyBear/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/intelowlproject/GreedyBear/actions/workflows/codeql-analysis.yml)
[![Dependency Review](https://github.com/intelowlproject/GreedyBear/actions/workflows/dependency_review.yml/badge.svg)](https://github.com/intelowlproject/GreedyBear/actions/workflows/dependency_review.yml)
[![Pull request automation](https://github.com/intelowlproject/GreedyBear/actions/workflows/pull_request_automation.yml/badge.svg)](https://github.com/intelowlproject/GreedyBear/actions/workflows/pull_request_automation.yml)

The project goal is to extract data of the attacks detected by a [TPOT](https://github.com/telekom-security/tpotce) or a cluster of them and to generate some feeds that can be used to prevent and detect attacks.

[Official announcement here](https://www.honeynet.org/2021/12/27/new-project-available-greedybear/).

## Documentation [![Documentation Status](https://readthedocs.org/projects/greedybear/badge/?version=latest)](https://greedybear.readthedocs.io/en/latest/?badge=latest)

Documentation about GreedyBear installation, usage, configuration and contribution can be found at https://greedybear.readthedocs.io/.

## Public feeds

There are public feeds provided by The Honeynet Project in this [site](greedybear.honeynet.org). [Example](https://greedybear.honeynet.org/api/feeds/log4j/all/recent.txt)

Please do not perform too many requests to extract feeds or you will be banned.

If you want to be updated regularly, please download the feeds only once every 10 minutes (this is the time between each internal update).

To check all the available feeds, Please refer to our [usage guide](https://greedybear.readthedocs.io/en/latest/Usage.html)


## Enrichment Service

GreedyBear provides an easy-to-query API to get the information available in GB regarding the queried observable (domain or IP address).

To understand more, Please refer to our [usage guide](https://greedybear.readthedocs.io/en/latest/Usage.html)

## Run Greedybear on your environment
The tool has been created not only to provide the feeds from The Honeynet Project's cluster of TPOTs.

If you manage one or more T-POTs of your own, you can get the code of this application and run Greedybear on your environment.
In this way, you are able to provide new feeds of your own.

To install it locally, Please refer to our [installation guide](https://greedybear.readthedocs.io/en/latest/Installation.html)
