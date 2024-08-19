<p align="center"><img src="static/greedybear.png" width=350 height=404 alt="GreedyBear"/></p>

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

## Documentation

Documentation about GreedyBear installation, usage, configuration and contribution can be found at [this link](https://intelowlproject.github.io/docs/GreedyBear/Introduction/)

## Public feeds

There are public feeds provided by [The Honeynet Project](https://www.honeynet.org) in this [site](https://greedybear.honeynet.org). [Example](https://greedybear.honeynet.org/api/feeds/log4j/all/recent.txt)

Please do not perform too many requests to extract feeds or you will be banned.

If you want to be updated regularly, please download the feeds only once every 10 minutes (this is the time between each internal update).

To check all the available feeds, Please refer to our [usage guide](https://intelowlproject.github.io/docs/GreedyBear/Usage/)


## Enrichment Service

GreedyBear provides an easy-to-query API to get the information available in GB regarding the queried observable (domain or IP address).

To understand more, Please refer to our [usage guide](https://intelowlproject.github.io/docs/GreedyBear/Usage/)

## Run Greedybear on your environment
The tool has been created not only to provide the feeds from The Honeynet Project's cluster of TPOTs.

If you manage one or more T-POTs of your own, you can get the code of this application and run Greedybear on your environment.
In this way, you are able to provide new feeds of your own.

To install it locally, Please refer to our [installation guide](https://intelowlproject.github.io/docs/GreedyBear/Installation/)

## Sponsors

#### Certego

<a href="https://www.certego.net/?utm_source=greedybear"> <img style="margin-right: 2px" width=250 height=71 src="static/Certego.png" alt="Certego Logo"/></a>

[Certego](https://www.certego.net/?utm_source=greedybear) is a MDR (Managed Detection and Response) and Threat Intelligence Provider based in Italy.

Started as a personal Christmas project from [Matteo Lodi](https://twitter.com/matte_lodi), since then GreedyBear is being improved mainly thanks to the efforts of the Certego Threat Intelligence Team.

#### The Honeynet Project

<a href="https://www.honeynet.org"> <img style="border: 0.2px solid black" width=125 height=125 src="static/honeynet_logo.png" alt="Honeynet.org logo"> </a>

[The Honeynet Project](https://www.honeynet.org) is a non-profit organization working on creating open source cyber security tools and sharing knowledge about cyber threats.

