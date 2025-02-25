# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from greedybear.consts import ATTACK_DATA_FIELDS, SCANNER
from greedybear.cronjobs.attacks import ExtractAttacks
from greedybear.cronjobs.honeypots import Honeypot
from greedybear.models import IOC, GeneralHoneypot


class ExtractGeneral(ExtractAttacks):
    def __init__(self, honeypot, minutes_back=None):
        super().__init__(minutes_back=minutes_back)
        self.hp = honeypot
        self.added_scanners = 0

    def _general_lookup(self):
        self._get_scanners()
        self.log.info(f"added {self.added_scanners} scanners for {self.hp.name}")

    def _get_scanners(self):
        honeypot_name = self.hp.name
        for ioc in self._get_attacker_data(self.hp, ATTACK_DATA_FIELDS):
            self.log.info(f"found IP {ioc.name} by honeypot {honeypot_name}")
            self._add_ioc(ioc, attack_type=SCANNER, general=honeypot_name)
            self.added_scanners += 1

    def run(self):
        self._healthcheck()
        self._check_first_time_run(self.hp.name.lower(), general=True)
        self._general_lookup()
        return self.ioc_records


class ExtractAllGenerals(ExtractAttacks):
    def __init__(self, minutes_back=None):
        super().__init__(minutes_back=minutes_back)
        self.honeypots = [Honeypot(hp.name) for hp in GeneralHoneypot.objects.all().filter(active=True)]

    def run(self):
        for honeypot in self.honeypots:
            iocs = ExtractGeneral(honeypot, self.minutes_back).run()
            self.ioc_records.extend(iocs)
        self._update_scores()
