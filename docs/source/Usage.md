# Usage
GreedyBear is created with the aim to collect the information from the TPOTs and generate some actionable feeds, so that they can be easliy accessible and act as valuable information to prevent and detect attacks.

## Feeds
The feeds are reachable through the following URL:
```
https://<greedybear_site>/api/feeds/<feed_type>/<attack_type>/<age>.<format>
```
These feeds are regularly updated every 10 minutes.

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


You can also query for a specific observable through the following URL:
```
https://<greedybear_site>/api/enrichment?query=<observable_name>
```
The `observable_name` can be:
* An valid `IP` or `domain`