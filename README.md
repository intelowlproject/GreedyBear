# GreedyBear
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/honeynet/Greedybear)](https://github.com/honeynet/Greedybear/releases)
[![GitHub Repo stars](https://img.shields.io/github/stars/honeynet/Greedybear?style=social)](https://github.com/honeynet/Greedybear/stargazers)

[![CodeFactor](https://www.codefactor.io/repository/github/honeynet/greedybear/badge)](https://www.codefactor.io/repository/github/honeynet/greedybear)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![Pull request automation](https://github.com/honeynet/GreedyBear/actions/workflows/pull_request_automation.yml/badge.svg)](https://github.com/honeynet/GreedyBear/actions/workflows/pull_request_automation.yml)

The project goal is to extract data of the attacks detected by a [TPOT](https://github.com/telekom-security/tpotce) or a cluster of them and to generate some feeds that can be used to prevent and detect attacks.

[Official announcement here](https://www.honeynet.org/2021/12/27/new-project-available-greedybear/).

## Feeds

### Public feeds

There are public feeds provided by The Honeynet Project in this site: greedybear.honeynet.org. [Example](https://greedybear.honeynet.org/api/feeds/log4j/all/recent.txt)

Please do not perform too many requests to extract feeds or you will be banned.

If you want to be updated regularly, please download the feeds only once every 10 minutes (this is the time between each internal update).


### Available feeds
The feeds are reachable through the following URL: 
```
https://<greedybear_site>/api/feeds/<feed_type>/<attack_type>/<age>.<format>
```

The available `feed_type` are:

* `log4j`: attacks detected from the [Log4pot](https://github.com/thomaspatzke/Log4Pot).
* `cowrie`: attacks detected from the [Cowrie Honeypot](https://github.com/cowrie/cowrie)
* `all`: get all types at once

The available `attack_type` are:

* `scanner`: IP addresses captured by the honeypots while performing attacks
* `payload_request`: IP addresses and domains extracted from payloads that would have been executed after a speficic attack would have been successful
* `all`: get all types at once

The available `age` are:

* `recent`: most recent IOCs seen in the last 3 days
* `persistent`: these IOCs are the ones that were seen regularly by the honeypots. This feeds will start empty once no prior data was collected and will become bigger over time.

The available `format` are:

* `txt`: plain text (just one line for each IOC)
* `csv`: CSV-like file (just one line for each IOC)
* `json`: JSON file with additional information regarding the IOCs


## Run Greedybear on your environment
The tool has been created not only to provide the feeds from The Honeynet Project's cluster of TPOTs.

If you manage one or more T-POTs of your own, you can get the code of this application and run Greedybear on your environment.
In this way, you are able to provide new feeds of your own.