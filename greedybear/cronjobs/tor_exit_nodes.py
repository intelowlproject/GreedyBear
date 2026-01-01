# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import re

import requests
from greedybear.cronjobs.base import Cronjob
from greedybear.models import IOC, TorExitNodes


class TorExitNodesCron(Cronjob):
    def run(self) -> None:
        url = "https://check.torproject.org/exit-addresses"
        r = requests.get(url, timeout=10)
        r.raise_for_status()

        data_extracted = r.content.decode()
        # Extract IPs using regex pattern from IntelOwl implementation
        ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        findings = re.findall(ip_pattern, data_extracted)

        # Remove duplicates while preserving order
        unique_ips = list(dict.fromkeys(findings))

        for ip_address in unique_ips:
            try:
                TorExitNodes.objects.get(ip_address=ip_address)
            except TorExitNodes.DoesNotExist:
                self.log.info(f"added new Tor exit node {ip_address}")
                TorExitNodes(ip_address=ip_address).save()
                self._update_old_ioc(ip_address)

    def _update_old_ioc(self, ip_address):
        try:
            ioc = IOC.objects.get(name=ip_address)
        except IOC.DoesNotExist:
            pass
        else:
            ioc.ip_reputation = "tor exit node"
            ioc.save()
