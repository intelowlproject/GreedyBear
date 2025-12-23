import re

import requests
from greedybear.cronjobs.base import Cronjob
from greedybear.models import IOC, MassScanner


class MassScannersCron(Cronjob):
    def run(self) -> None:
        regex_compiled = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*#\s*(.+)*", re.DOTALL)
        r = requests.get("https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt", timeout=10)
        for line_bytes in r.iter_lines():
            if line_bytes:
                line = line_bytes.decode("utf-8")
                if not line or line.startswith("#"):
                    continue
                if match := re.match(regex_compiled, line):
                    ip_address = match.group(1)
                    reason = match.group(2)
                    try:
                        MassScanner.objects.get(ip_address=ip_address)
                    except MassScanner.DoesNotExist:
                        self.log.info(f"added new mass scanner {ip_address}")
                        MassScanner(ip_address=ip_address, reason=reason).save()
                        self._update_old_ioc(ip_address)
                else:
                    self.log.warning(f"unexpected line: {line}")

    def _update_old_ioc(self, ip_address):
        try:
            ioc = IOC.objects.get(name=ip_address)
        except IOC.DoesNotExist:
            pass
        else:
            ioc.ip_reputation = "mass scanner"
            ioc.save()
