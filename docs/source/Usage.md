# Usage

## Feeds
GreedyBear is created with the aim to collect the information from the TPOTs and generate some actionable feeds, so that they can be easily accessible and act as valuable information to prevent and detect attacks.

The feeds are reachable through the following URL:
```
https://<greedybear_site>/api/feeds/<feed_type>/<attack_type>/<age>.<format>
```
The available feed_type are:

* `log4j`: attacks detected from the Log4pot.
* `cowrie`: attacks detected from the Cowrie Honeypot
* `all`: get all types at once

The available attack_type are:

* `scanner`: IP addresses captured by the honeypots while performing attacks
* `payload_request': IP addresses and domains extracted from payloads that would have been executed after a speficic attack would have been successful
* `all`: get all types at once


The available age are:

* `recent`: most recent IOCs seen in the last 3 days
* `persistent`: these IOCs are the ones that were seen regularly by the honeypots. This feeds will start empty once no prior data was collected and will become bigger over time.

The available formats are:

* `txt`: plain text (just one line for each IOC)
* `csv`: CSV-like file (just one line for each IOC)
* `json`: JSON file with additional information regarding the IOCs

Check the [Redoc specification](https://greedybear.readthedocs.io/en/latest/Redoc.html) or the to get all the details about how to use the available APIs.

## Enrichment

GreedyBear provides an easy-to-query API to get the information available in GB regarding the queried observable (domain or IP address).

```
https://<greedybear_site>/api/enrichment?query=<observable>
```

This "Enrichment" API is protected through authentication. Please reach out [Matteo Lodi](https://twitter.com/matte_lodi) or another member of [The Honeynet Project](https://twitter.com/ProjectHoneynet) if you are interested in gain access to this API.

If you would like to leverage this API without the need of writing even a line of code and together with a lot of other awesome tools, consider using [IntelOwl](https://github.com/intelowlproject/IntelOwl).