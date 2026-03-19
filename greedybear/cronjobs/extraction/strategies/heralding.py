# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from greedybear.consts import SCANNER
from greedybear.cronjobs.extraction.strategies.base import BaseExtractionStrategy
from greedybear.cronjobs.extraction.utils import (
    iocs_from_hits,
    threatfox_submission,
)
from greedybear.cronjobs.repositories import IocRepository, SensorRepository
from greedybear.models import Credential

HERALDING_HONEYPOT = "Heralding"

# Protocols that Heralding emulates for credential capture.
HERALDING_PROTOCOLS = frozenset(
    {
        "ssh",
        "telnet",
        "ftp",
        "http",
        "https",
        "pop3",
        "imap",
        "smtp",
        "vnc",
        "socks5",
        "postgresql",
        "mysql",
        "mssql",
        "rdp",
    }
)


class HeraldingExtractionStrategy(BaseExtractionStrategy):
    """
    Extraction strategy for Heralding credential-catching honeypot.

    Heralding emulates multiple protocols (SSH, Telnet, FTP, HTTP, etc.)
    and captures credential brute-force attempts. This strategy:
    - Extracts scanner IPs as IOCs
    - Stores credentials with the protocol they targeted
    """

    def __init__(
        self,
        honeypot: str,
        ioc_repo: IocRepository,
        sensor_repo: SensorRepository,
    ):
        super().__init__(honeypot, ioc_repo, sensor_repo)
        self.credentials_added = 0

    def extract_from_hits(self, hits: list[dict]) -> None:
        """
        Extract IOCs from Heralding honeypot log hits.

        Processes scanner IPs, then classifies credential-brute-force
        attempts and stores protocol-aware credentials.

        Args:
            hits: List of Elasticsearch hit dictionaries to process.
        """
        self._get_scanners(hits)
        self._classify_credential_attacks(hits)
        self.log.info(f"added {len(self.ioc_records)} scanners, {self.credentials_added} credentials from {self.honeypot}")

    def _get_scanners(self, hits: list[dict]) -> None:
        """Extract scanner IPs from hits."""
        for ioc in iocs_from_hits(hits):
            self.log.info(f"found IP {ioc.name} by honeypot {self.honeypot}")
            ioc_record = self.ioc_processor.add_ioc(
                ioc,
                attack_type=SCANNER,
                general_honeypot_name=HERALDING_HONEYPOT,
            )
            if ioc_record:
                self.ioc_records.append(ioc_record)
                threatfox_submission(ioc_record, ioc.related_urls, self.log)

    def _classify_credential_attacks(self, hits: list[dict]) -> None:
        """
        Classify credential brute-force attempts by protocol and persist credentials.

        Extracts username/password pairs from Heralding hits and stores them
        together with the normalized protocol on the Credential model.
        Duplicate tuples in the same batch are deduplicated.

        Args:
            hits: List of Elasticsearch hit documents.
        """
        credentials: set[tuple[str, str, str]] = set()
        for hit in hits:
            protocol = self._extract_protocol(hit)
            if not protocol:
                continue

            raw_username = hit.get("username")
            raw_password = hit.get("password")
            if not raw_username and not raw_password:
                continue

            username = str(raw_username or "")
            password = str(raw_password or "")
            credentials.add((username, password, protocol))

        for username, password, protocol in sorted(credentials):
            _, created = Credential.objects.get_or_create(
                username=username,
                password=password,
                protocol=protocol,
            )
            if created:
                self.credentials_added += 1
                self.log.info(f"stored credential for protocol={protocol}")

    def _extract_protocol(self, hit: dict) -> str | None:
        """
        Extract and normalise the protocol name from a hit.

        Heralding logs include a ``protocol`` field indicating which
        emulated service the attacker connected to. The value is
        lower-cased and validated against the known set of Heralding
        protocols.

        Args:
            hit: Elasticsearch hit document.

        Returns:
            Normalised protocol string, or ``None`` if absent/unknown.
        """
        raw = hit.get("protocol")
        if raw:
            normalised = str(raw).strip().lower()
            if normalised in HERALDING_PROTOCOLS:
                return normalised
        return None
