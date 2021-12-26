from greedybear.cronjobs.base import ExtractDataFromElastic
from greedybear.cronjobs.honeypots import Honeypot
from greedybear.models import Sensors


class ExtractSensors(ExtractDataFromElastic):
    """
    this cron is required to extract sensors IP addresses and whitelist them
    """

    def __init__(self):
        super().__init__()

    @property
    def minutes_back_to_lookup(self):
        return 1440  # a day

    def _extract_sensors(self):
        honeypot = Honeypot("Suricata")
        search = self._base_search(honeypot)

        added_sensors = 0

        # get no more than X IPs a day
        search.aggs.bucket(
            "sensors_ips",
            "terms",
            field="t-pot_ip_ext.keyword",
            size=1000,
        )
        agg_response = search[0:0].execute()
        for tag in agg_response.aggregations.sensors_ips.buckets:
            if not tag.key:
                self.log.warning(f"why tag.key is empty? tag: {tag}")
                continue
            self.log.info(f"found IP {tag.key} by honeypot {honeypot.name}")
            try:
                Sensors.objects.get(address=tag.key)
            except Sensors.DoesNotExist:
                sensor = Sensors(address=tag.key)
                sensor.save()
                added_sensors += 1

        self.log.info(f"added {added_sensors} new sensors in the database")

    def run(self):
        self._healthcheck()
        self._extract_sensors()
