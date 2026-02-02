import os
from datetime import datetime

import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.utils import is_valid_ipv4
from greedybear.cronjobs.repositories import AbuseIPDBRepository, IocRepository


class AbuseIPDBCron(Cronjob):
    """Fetch and store AbuseIPDB blacklist entries."""

    MAX_ENTRIES = 10000  # Hard limit as per maintainer requirements

    def __init__(self, abuseipdb_repo=None, ioc_repo=None):
        super().__init__()
        self.abuseipdb_repo = abuseipdb_repo if abuseipdb_repo is not None else AbuseIPDBRepository()
        self.ioc_repo = ioc_repo if ioc_repo is not None else IocRepository()

    def run(self) -> None:
        """Fetch AbuseIPDB blacklist and store entries."""
        try:
            # Get API key from environment
            api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
            if not api_key:
                self.log.error("ABUSEIPDB_API_KEY environment variable not set")
                return

            self.log.info("Starting download of AbuseIPDB blacklist")

            # Download the blacklist (max 10k with free API key)
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/blacklist",
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                },
                params={
                    "confidenceMinimum": 75,  # Only high-confidence entries
                    "limit": self.MAX_ENTRIES,
                },
                timeout=30,
            )
            r.raise_for_status()

            data = r.json()

            # Clear old entries before loading new ones
            self.log.info("Clearing old AbuseIPDB entries")
            self.abuseipdb_repo.delete_all()

            entries_added = 0
            blacklist_data = data.get("data", [])

            for entry in blacklist_data:
                ip_address = entry.get("ipAddress", "")

                # Validate IP
                is_valid, validated_ip = is_valid_ipv4(ip_address)
                if not is_valid:
                    self.log.debug(f"Invalid IPv4 address: {ip_address}")
                    continue

                # Check hard limit
                if entries_added >= self.MAX_ENTRIES:
                    self.log.warning(f"Reached hard limit of {self.MAX_ENTRIES} AbuseIPDB entries")
                    break

                abuse_score = entry.get("abuseConfidenceScore", 0)

                # Parse last reported timestamp
                last_reported_str = entry.get("lastReportedAt", "")
                last_reported_at = None
                if last_reported_str:
                    try:
                        last_reported_at = datetime.fromisoformat(last_reported_str.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        pass

                # Store entry
                abuse_entry, created = self.abuseipdb_repo.get_or_create(validated_ip, abuse_confidence_score=abuse_score, last_reported_at=last_reported_at)

                if created:
                    self.log.info(f"Added AbuseIPDB entry: {validated_ip} (score: {abuse_score})")
                    entries_added += 1

            self.log.info(f"Completed AbuseIPDB download. Added {entries_added} entries.")

        except requests.RequestException as e:
            self.log.error(f"Failed to fetch AbuseIPDB blacklist: {e}")
            raise
