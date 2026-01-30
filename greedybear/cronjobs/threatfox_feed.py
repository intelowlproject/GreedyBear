import csv
import io
from datetime import datetime

import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.utils import is_valid_ipv4
from greedybear.cronjobs.repositories import IocRepository, ThreatFoxRepository


class ThreatFoxCron(Cronjob):
    """Fetch and store ThreatFox IOCs (IP addresses) from Abuse.ch."""

    MAX_ENTRIES = 10000  # Hard limit as per maintainer requirements

    def __init__(self, threatfox_repo=None, ioc_repo=None):
        super().__init__()
        self.threatfox_repo = threatfox_repo if threatfox_repo is not None else ThreatFoxRepository()
        self.ioc_repo = ioc_repo if ioc_repo is not None else IocRepository()

    def run(self) -> None:
        """Fetch ThreatFox IP-port IOCs and store them."""
        try:
            self.log.info("Starting download of ThreatFox IP-port feed from abuse.ch")

            # Download the IP-port recent feed (CSV format)
            # Using 'recent' (last 48h) instead of 'full' to stay within rate limits
            r = requests.get(
                "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
                timeout=30,
            )
            r.raise_for_status()

            # Clear old entries before loading new ones
            self.log.info("Clearing old ThreatFox entries")
            self.threatfox_repo.delete_all()

            # Parse CSV - filter out comment lines first
            # ThreatFox CSV has comment lines starting with #, need to remove before DictReader
            csv_lines = r.text.splitlines()
            filtered_lines = [line for line in csv_lines if line.strip() and not line.strip().startswith("#")]
            csv_text = "\n".join(filtered_lines)

            csv_reader = csv.DictReader(io.StringIO(csv_text), delimiter=",", quotechar='"')

            entries_added = 0
            for row in csv_reader:
                # Skip empty rows
                if not row:
                    continue

                # Extract IP from "ip:port" format
                ioc_value = row.get("ioc", "") or row.get("IOC", "")

                if not ioc_value:
                    continue

                if ":" in ioc_value:
                    ip_address = ioc_value.split(":", 1)[0]
                else:
                    ip_address = ioc_value

                # Validate IP
                is_valid, validated_ip = is_valid_ipv4(ip_address)
                if not is_valid:
                    self.log.debug(f"Invalid IPv4 address: {ip_address}")
                    continue

                # Check hard limit
                if entries_added >= self.MAX_ENTRIES:
                    self.log.warning(f"Reached hard limit of {self.MAX_ENTRIES} ThreatFox entries")
                    break

                # Extract malware family
                malware_family = row.get("malware") or row.get("malware_printable", "")

                # Extract last_seen_online
                last_seen_str = row.get("last_online") or row.get("last_seen")
                last_seen_online = None
                if last_seen_str:
                    try:
                        last_seen_online = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        pass

                # Store entry
                entry, created = self.threatfox_repo.get_or_create(validated_ip, malware_family=malware_family, last_seen_online=last_seen_online)

                if created:
                    self.log.info(f"Added ThreatFox entry: {validated_ip} ({malware_family})")
                    entries_added += 1
                    self._update_ioc_reputation(validated_ip, malware_family)

            self.log.info(f"Completed ThreatFox download. Added {entries_added} entries.")

        except requests.RequestException as e:
            self.log.error(f"Failed to fetch ThreatFox feed: {e}")
            raise

    def _update_ioc_reputation(self, ip_address: str, malware_family: str):
        """Update the IP reputation of an existing IOC to mark it as ThreatFox-listed."""
        reputation = f"threatfox: {malware_family}" if malware_family else "threatfox"
        updated = self.ioc_repo.update_ioc_reputation(ip_address, reputation)
        if updated:
            self.log.debug(f"Updated IOC {ip_address} reputation to '{reputation}'")
