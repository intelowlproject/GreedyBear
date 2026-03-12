# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from collections import defaultdict

from greedybear.consts import SCANNER
from greedybear.cronjobs.extraction.strategies import BaseExtractionStrategy
from greedybear.cronjobs.extraction.utils import (
    iocs_from_hits,
    threatfox_submission,
)
from greedybear.cronjobs.repositories import IocRepository, SensorRepository
from greedybear.models import IOC, Tag

HERALDING_SOURCE = "heralding"
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
    - Tags scanners with the protocols they targeted
    - Tracks login attempt counts per IP
    """

    def __init__(
        self,
        honeypot: str,
        ioc_repo: IocRepository,
        sensor_repo: SensorRepository,
    ):
        super().__init__(honeypot, ioc_repo, sensor_repo)
        self.protocol_tags_added = 0

    def extract_from_hits(self, hits: list[dict]) -> None:
        """
        Extract IOCs from Heralding honeypot log hits.

        Processes scanner IPs, then classifies credential-brute-force
        attempts by analysing the protocols used and tagging the IOC
        records accordingly.

        Args:
            hits: List of Elasticsearch hit dictionaries to process.
        """
        self._get_scanners(hits)
        self._classify_credential_attacks(hits)
        self.log.info(f"added {len(self.ioc_records)} scanners, {self.protocol_tags_added} protocol tags from {self.honeypot}")

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
        Classify credential brute-force attempts by protocol and tag IOCs.

        Groups hits by source IP and extracts the set of protocols each
        attacker targeted. Each protocol is stored as a Tag record
        (key="protocol", source="heralding") on the corresponding IOC.

        Args:
            hits: List of Elasticsearch hit documents.
        """
        # Seed cache from IOC records loaded by _get_scanners so we avoid
        # repeated DB lookups for the same scanner IP across many hits.
        ioc_cache: dict[str, object] = {ioc.name: ioc for ioc in self.ioc_records}

        # Group protocols per source IP
        protocols_by_ip: dict[str, set[str]] = defaultdict(set)
        for hit in hits:
            scanner_ip = hit.get("src_ip")
            if not scanner_ip:
                continue
            protocol = self._extract_protocol(hit)
            if protocol:
                protocols_by_ip[scanner_ip].add(protocol)

        for scanner_ip, protocols in protocols_by_ip.items():
            if scanner_ip not in ioc_cache:
                ioc_cache[scanner_ip] = self.ioc_repo.get_ioc_by_name(scanner_ip)
            ioc_record = ioc_cache[scanner_ip]
            if not ioc_record:
                continue

            self._add_protocol_tags(ioc_record, protocols)

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
        raw = hit.get("protocol", "")
        if not raw:
            return None
        normalised = str(raw).strip().lower()
        if normalised in HERALDING_PROTOCOLS:
            return normalised
        return None

    def _add_protocol_tags(self, ioc_record: IOC, protocols: set[str]) -> None:
        """
        Store detected protocols as Tag records on the IOC.

        Creates one tag per protocol with key="protocol",
        source="heralding". Skips duplicates if the tag already exists.

        Args:
            ioc_record: Persisted IOC instance to tag.
            protocols: Set of protocol name strings to store.
        """
        for protocol in sorted(protocols):
            _, created = Tag.objects.get_or_create(
                ioc=ioc_record,
                key="protocol",
                value=protocol,
                source=HERALDING_SOURCE,
            )
            if created:
                self.protocol_tags_added += 1
                self.log.info(f"tagged {ioc_record.name} with protocol={protocol}")
