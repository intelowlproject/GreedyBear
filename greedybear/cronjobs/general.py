# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from greedybear.consts import SCANNER
from greedybear.cronjobs.attacks import ExtractAttacks
from greedybear.cronjobs.honeypots import Honeypot
from greedybear.models import GeneralHoneypot


class ExtractGeneral(ExtractAttacks):
    def __init__(self, honeypot, minutes_back=None):
        super().__init__(minutes_back=minutes_back)
        self.hp = honeypot
        self.added_scanners = 0

    def _general_lookup(self):
        self._get_scanners()
        self.log.info(f"added {self.added_scanners} scanners for {self.hp.name}")

    def _get_scanners(self):
        search = self._base_search(self.hp)
        name = self.hp.name
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
            self._add_ioc(scanner_ip, SCANNER, general=name)
            self.added_scanners += 1

    def run(self):
        self._healthcheck()
        self._check_first_time_run(self.hp.name.lower(), general=True)
        self._general_lookup()


class ExtractAllGenerals(ExtractAttacks):
    def __init__(self, minutes_back=None):
        super().__init__(minutes_back=minutes_back)
        self.honeypots = [Honeypot(hp.name) for hp in GeneralHoneypot.objects.all().filter(active=True)]

    def run(self):
        for honeypot in self.honeypots:
            ExtractGeneral(honeypot, self.minutes_back).run()
