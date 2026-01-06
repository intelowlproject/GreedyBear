import re

import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.utils import is_valid_ipv4
from greedybear.models import IOC, MassScanner


class MassScannersCron(Cronjob):
    def run(self) -> None:
        # Simple regex to extract potential IPv4 addresses
        ip_candidate_regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        # Regex to extract optional comment/reason after '#'
        comment_regex = re.compile(r"#\s*(.+)", re.DOTALL)

        r = requests.get(
            "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt",
            timeout=10,
        )
        for line_bytes in r.iter_lines():
            if line_bytes:
                line = line_bytes.decode("utf-8")
                if not line or line.startswith("#"):
                    continue

                # Try to extract IP candidate from the line
                ip_match = ip_candidate_regex.search(line)
                if not ip_match:
                    # No IP-like pattern found, log at DEBUG level
                    self.log.debug(f"No IP pattern found in line: {line}")
                    continue

                # Validate the extracted candidate
                is_valid, ip_address = is_valid_ipv4(ip_match.group(1))
                if not is_valid:
                    # Not a valid IPv4, log at DEBUG level
                    self.log.debug(f"Invalid IPv4 address in line: {line}")
                    continue

                # Extract optional comment/reason
                reason = ""
                comment_match = comment_regex.search(line)
                if comment_match:
                    reason = comment_match.group(1)

                # Add or update mass scanner entry
                try:
                    MassScanner.objects.get(ip_address=ip_address)
                except MassScanner.DoesNotExist:
                    self.log.info(f"added new mass scanner {ip_address}")
                    MassScanner(ip_address=ip_address, reason=reason).save()
                    self._update_old_ioc(ip_address)

    def _update_old_ioc(self, ip_address):
        try:
            ioc = IOC.objects.get(name=ip_address)
        except IOC.DoesNotExist:
            pass
        else:
            ioc.ip_reputation = "mass scanner"
            ioc.save()
