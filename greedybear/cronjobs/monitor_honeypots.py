from greedybear.cronjobs.base import ExtractDataFromElastic


class MonitorHoneypots(ExtractDataFromElastic):
    def __init__(self):
        super(MonitorHoneypots, self).__init__()
        self.honeypots_to_monitor = ["Log4pot", "Cowrie"]

    @property
    def minutes_back_to_lookup(self):
        return 60

    def run(self):
        for honeypot_to_monitor in self.honeypots_to_monitor:
            self.log.info(
                f"checking if logs from the honeypot {honeypot_to_monitor} are available"
            )
            search = self._base_search(honeypot_to_monitor)

            hits = search[:10].execute()
            if not hits:
                self.log.error(
                    f"no logs available for the Honeypot {honeypot_to_monitor}."
                    f" Something is wrong in the TPOT cluster"
                )
