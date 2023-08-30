# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.honeypots import Honeypot
from greedybear.models import GeneralHoneypot


class MonitorHoneypots(Cronjob):
    def __init__(self):
        super(MonitorHoneypots, self).__init__()
        self.honeypots_to_monitor = [Honeypot("Log4pot"), Honeypot("Cowrie")]
        # FEEDS - add monitor for all general honeypots from list
        general_honeypots = GeneralHoneypot.objects.all().filter(active=True)
        for hp in general_honeypots:
            self.honeypots_to_monitor.append(Honeypot(hp.name))

    @property
    def minutes_back_to_lookup(self):
        return 60

    def run(self):
        for honeypot_to_monitor in self.honeypots_to_monitor:
            self.log.info(f"checking if logs from the honeypot {honeypot_to_monitor.name} are available")
            search = self._base_search(honeypot_to_monitor)

            hits = search[:10].execute()
            if not hits:
                self.log.warning(f"no logs available for the Honeypot {honeypot_to_monitor.name}." f" Something could be wrong in the TPOT cluster")
