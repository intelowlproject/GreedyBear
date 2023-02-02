# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from greedybear.consts import GENERAL_HONEYPOTS, SCANNER
from greedybear.cronjobs.attacks import ExtractAttacks
from greedybear.cronjobs.honeypots import Honeypot

# FEEDS
# Extract only source IPs from a list of Honeypots


class ExtractGeneral(ExtractAttacks):
    def __init__(self, minutes_back=None):
        super().__init__(minutes_back=minutes_back)
        self.general = []
        self.added_scanners = [0] * len(GENERAL_HONEYPOTS)
        for idx, hp in enumerate(GENERAL_HONEYPOTS):  # Create Honeypot for each Honeypot from list
            self.general.append(Honeypot(hp))

    def _general_lookup(self):
        for idx, hp in enumerate(self.general):
            self._get_scanners(idx)
            self.log.info(f"added {self.added_scanners[idx]} scanners for {hp.name}")

    def _get_scanners(self, idx):
        search = self._base_search(self.general[idx])
        name = self.general[idx].name
        # get no more than X IPs a day
        search.aggs.bucket(
            "attacker_ips",
            "terms",
            field="src_ip.keyword",
            size=1000,
        )
        agg_response = search[0:0].execute()
        for tag in agg_response.aggregations.attacker_ips.buckets:
            if not tag.key:
                self.log.warning(f"why tag.key is empty? tag: {tag}")
                continue
            self.log.info(f"found IP {tag.key} by honeypot {name}")
            scanner_ip = str(tag.key)
            self._add_ioc(scanner_ip, SCANNER, general=name.lower())
            self.added_scanners[idx] += 1

    def run(self):
        self._healthcheck()
        for idx, hp in enumerate(self.general):
            self._check_first_time_run(hp.name.lower(), general=True)
        self._general_lookup()
