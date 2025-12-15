import re
from typing import List

import requests
from greedybear.cronjobs.base import Cronjob
from greedybear.models import EnrichmentTag, IOC


class BasicEnrichmentCron(Cronjob):
    """Fetch enrichment data from public sources and tag IP addresses.

    Sources can be extended. Each source produces a list of IPs (one per line)
    or simple text lists. For each discovered IP we create an `EnrichmentTag`
    pointing to the `IOC` when present.
    """

    SOURCES = [
        ("ransomwaretracker", "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt"),
        ("feodotracker", "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist"),
    ]

    IPV4_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

    def run(self) -> None:
        for source_name, url in self.SOURCES:
            try:
                r = requests.get(url, timeout=15)
            except Exception as e:
                self.log.warning(f"Failed to fetch {url}: {e}")
                continue

            if r.status_code != 200:
                self.log.warning(f"Failed to fetch {url}: HTTP {r.status_code}")
                continue

            lines = [ln.strip() for ln in r.text.splitlines() if ln.strip()]
            ips = self._extract_ips(lines)
            for ip in ips:
                try:
                    EnrichmentTag.objects.get(ip_address=ip, source=source_name)
                except EnrichmentTag.DoesNotExist:
                    tag_value = source_name
                    self.log.info(f"added enrichment tag {ip} from {source_name}")
                    ioc = None
                    try:
                        ioc = IOC.objects.get(name=ip)
                    except IOC.DoesNotExist:
                        pass
                    EnrichmentTag(ip_address=ip, ioc=ioc, source=source_name, tag=tag_value).save()

    def _extract_ips(self, lines: List[str]) -> List[str]:
        ips = []
        for line in lines:
            # skip comments
            if line.startswith("#"):
                continue
            # sometimes lines contain additional fields; pick first token
            token = line.split()[0]
            if self.IPV4_REGEX.match(token):
                ips.append(token)
        return ips
