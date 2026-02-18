import re
from ipaddress import ip_address

import requests
from django.conf import settings

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.utils import is_valid_ipv4
from greedybear.cronjobs.repositories import ThreatFoxRepository


class ThreatFoxCron(Cronjob):
    """
    Fetch and store ThreatFox IOC data locally.

    Downloads IP-based IOCs from ThreatFox and stores them in the database
    for later enrichment. Cleans up old entries to keep the database fresh.
    """

    def __init__(self, threatfox_repo=None):
        """
        Initialize the ThreatFox cronjob.

        Args:
            threatfox_repo: Optional ThreatFoxRepository instance for testing.
        """
        super().__init__()
        self.threatfox_repo = threatfox_repo if threatfox_repo is not None else ThreatFoxRepository()

    def run(self) -> None:
        """
        Fetch ThreatFox IOCs and store them locally.

        Downloads recent IOCs (last 7 days) from ThreatFox API, filters for
        IP-based IOCs, and stores them in the local database for enrichment.
        """
        try:
            api_key = settings.THREATFOX_API_KEY
            if not api_key:
                self.log.warning("ThreatFox API key not configured. Skipping download.")
                return

            self.log.info("Starting ThreatFox feed download")

            # Clear old entries first
            self._cleanup_old_entries()

            # Fetch recent IOCs from ThreatFox (last 7 days)
            url = "https://threatfox-api.abuse.ch/api/v1/"
            headers = {
                "Content-Type": "application/json",
                "Auth-Key": api_key,
            }
            data = {"query": "get_iocs", "days": 7}

            response = requests.post(url, json=data, headers=headers, timeout=30)
            response.raise_for_status()

            json_data = response.json()

            if json_data.get("query_status") != "ok":
                self.log.warning(f"ThreatFox API returned non-OK status: {json_data.get('query_status')}")
                return

            iocs = json_data.get("data", [])
            self.log.info(f"Retrieved {len(iocs)} IOCs from ThreatFox")

            added_count = 0
            for ioc_data in iocs:
                # Extract IP from different IOC types
                ioc_value = ioc_data.get("ioc", "")
                ioc_type = ioc_data.get("ioc_type", "")

                # Extract IP address from different IOC types
                ip_addr = None

                if ioc_type == "ip:port":
                    # Extract IP from "ip:port" format
                    ip_addr = ioc_value.split(":")[0] if ":" in ioc_value else None
                elif ioc_type in ["ip", "ipv4"]:
                    ip_addr = ioc_value
                elif ioc_type == "url":
                    # Try to extract IP from URL
                    # Simple extraction: look for IP patterns in the URL
                    ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
                    match = re.search(ip_pattern, ioc_value)
                    if match:
                        ip_addr = match.group(1)

                # Validate IP address
                if ip_addr:
                    is_valid, validated_ip = is_valid_ipv4(ip_addr)
                    if is_valid:
                        # Check if IP is global (not private, loopback, etc.)
                        try:
                            parsed_ip = ip_address(validated_ip)
                            if parsed_ip.is_loopback or parsed_ip.is_private or parsed_ip.is_multicast or parsed_ip.is_link_local or parsed_ip.is_reserved:
                                self.log.debug(f"Skipping non-global IP: {validated_ip}")
                                continue
                        except ValueError:
                            continue

                        # Store in database
                        malware = ioc_data.get("malware", "")
                        malware_printable = ioc_data.get("malware_printable", "")
                        threat_type = ioc_data.get("threat_type", "")
                        confidence_level = ioc_data.get("confidence_level")
                        tags = ioc_data.get("tags") or []

                        entry, created = self.threatfox_repo.get_or_create(
                            ip_address=validated_ip,
                            malware=malware,
                            malware_printable=malware_printable,
                            threat_type=threat_type,
                            confidence_level=confidence_level,
                            tags=tags,
                        )

                        if created:
                            added_count += 1
                            self.log.debug(f"Added ThreatFox entry: {validated_ip} - {malware_printable or malware}")

            self.log.info(f"ThreatFox feed download completed. Added {added_count} new entries.")
            self.log.info(f"Total ThreatFox entries in database: {self.threatfox_repo.count()}")

        except requests.RequestException as e:
            self.log.error(f"Failed to fetch ThreatFox feed: {e}")
            raise
        except Exception as e:
            self.log.error(f"Unexpected error in ThreatFox feed download: {e}")
            raise

    def _cleanup_old_entries(self):
        """Delete ThreatFox entries older than 30 days to keep database clean."""
        deleted_count = self.threatfox_repo.cleanup_old_entries(days=30)
        if deleted_count > 0:
            self.log.info(f"Cleaned up {deleted_count} old ThreatFox entries")
