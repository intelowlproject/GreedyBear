from greedybear.cronjobs.base import ExtractDataFromElastic, Honeypot
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
        honeypot = Honeypot("log4pot")
        search = self._base_search(honeypot)

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

    def run(self):
        self._healthcheck()
        self._extract_sensors()