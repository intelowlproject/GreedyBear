import re

import requests
from greedybear.cronjobs.base import Cronjob
from greedybear.models import IOC, TorExitNodes


class TorExitNodesCron(Cronjob):
    """Fetch Tor exit addresses and store them locally.

    This cronjob fetches the official Tor exit-addresses list from the
    Tor Project and saves new IPs to the `TorExitNodes` model. When a
    new IP is discovered, existing `IOC` records with that IP will be
    updated to have `ip_reputation = 'tor exit node'`.
    """

    TOR_EXIT_URL = "https://check.torproject.org/exit-addresses"

    def run(self) -> None:
        r = requests.get(self.TOR_EXIT_URL, timeout=15)
        if r.status_code != 200:
            self.log.warning(f"Failed to fetch tor exit list: HTTP {r.status_code}")
            return

        for line_bytes in r.iter_lines():
            if not line_bytes:
                continue
            try:
                line = line_bytes.decode("utf-8").strip()
            except Exception:
                continue

            # lines with exit addresses look like: "ExitAddress 1.2.3.4 2025-..."
            if not line.startswith("ExitAddress"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip_address = parts[1]
            reason = parts[2] if len(parts) > 2 else None

            try:
                TorExitNodes.objects.get(ip_address=ip_address)
            except TorExitNodes.DoesNotExist:
                self.log.info(f"added new tor exit node {ip_address}")
                TorExitNodes(ip_address=ip_address, reason=reason).save()
                self._update_old_ioc(ip_address)

    def _update_old_ioc(self, ip_address):
        try:
            ioc = IOC.objects.get(name=ip_address)
        except IOC.DoesNotExist:
            pass
        else:
            ioc.ip_reputation = "tor exit node"
            ioc.save()
