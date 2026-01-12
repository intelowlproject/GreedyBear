import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.models import IOC, WhatsMyIPDomain


class WhatsMyIPCron(Cronjob):
    def run(self) -> None:
        r = requests.get(
            "https://raw.githubusercontent.com/MISP/misp-warninglists/refs/heads/main/lists/whats-my-ip/list.json",
            timeout=10,
        )
        json_file = r.json()
        for domain in json_file["list"]:
            try:
                WhatsMyIPDomain.objects.get(domain=domain)
            except WhatsMyIPDomain.DoesNotExist:
                WhatsMyIPDomain(domain=domain).save()
                self.log.info(f"added new whatsmyip domain {domain=}")
                self._remove_old_ioc(domain)

    def _remove_old_ioc(self, domain):
        try:
            ioc = IOC.objects.get(name=domain)
        except IOC.DoesNotExist:
            pass
        else:
            ioc.delete()
            self.log.info(f"deleted whatsmyip {domain=}")
