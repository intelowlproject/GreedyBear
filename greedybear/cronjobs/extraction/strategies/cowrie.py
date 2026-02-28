# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import re
from collections import defaultdict
from hashlib import sha256
from urllib.parse import urlparse

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.extraction.strategies import BaseExtractionStrategy
from greedybear.cronjobs.extraction.utils import (
    get_ioc_type,
    iocs_from_hits,
    threatfox_submission,
)
from greedybear.cronjobs.repositories import (
    CowrieSessionRepository,
    IocRepository,
    SensorRepository,
)
from greedybear.models import IOC, CommandSequence, CowrieSession, Credential
from greedybear.regex import REGEX_URL_PROTOCOL


def parse_url_hostname(url: str) -> str | None:
    """
    Extract hostname from URL safely.

    Args:
        url: URL string to parse

    Returns:
        Hostname if parsing succeeds, None otherwise
    """
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except (ValueError, AttributeError):
        return None


def normalize_command(message: str) -> str:
    """
    Normalize command string by removing CMD prefix and null characters.

    Args:
        message: Raw command message string

    Returns:
        Normalized command string, truncated to 1024 characters
    """
    # Truncate to 1024 chars to match CommandSequence.commands field max_length
    return message.removeprefix("CMD: ").replace("\x00", "[NUL]")[:1024]


def normalize_credential_field(field: str) -> str:
    """
    Normalize credential fields by replacing null characters.

    Args:
        field: Credential field string

    Returns:
        Normalized credential field
    """
    return field.replace("\x00", "[NUL]")


class CowrieExtractionStrategy(BaseExtractionStrategy):
    """
    Extraction strategy for Cowrie SSH/Telnet honeypot.

    Extracts scanner IPs, payload URLs from login attempts and file
    downloads, and session data including credentials and command
    sequences. Links related IOCs (scanners to download URLs) and
    deduplicates command sequences by hash.
    """

    def __init__(
        self,
        honeypot: str,
        ioc_repo: IocRepository,
        sensor_repo: SensorRepository,
        session_repo: CowrieSessionRepository = None,
    ):
        super().__init__(honeypot, ioc_repo, sensor_repo)
        self.session_repo = session_repo or CowrieSessionRepository()
        self.payloads_in_message = 0
        self.added_url_downloads = 0

    def extract_from_hits(self, hits: list[dict]) -> None:
        """
        Main extraction entry point. Processes hits and extracts scanners,
        payloads, downloads, and sessions.

        Args:
            hits: List of Elasticsearch hit documents
        """
        self._get_scanners(hits)
        self._extract_possible_payload_in_messages(hits)
        self._get_url_downloads(hits)
        self.log.info(
            f"added {len(self.ioc_records)} scanners, {self.payloads_in_message} payloads found in messages, {self.added_url_downloads} download URLs"
        )

    def _get_scanners(self, hits: list[dict]) -> None:
        """Extract scanner IPs and sessions."""
        for ioc in iocs_from_hits(hits):
            self.log.info(f"found IP {ioc.name} by honeypot cowrie")
            ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=SCANNER, general_honeypot_name="Cowrie")
            if ioc_record:
                self.ioc_records.append(ioc_record)
                threatfox_submission(ioc_record, ioc.related_urls, self.log)
                self._get_sessions(ioc_record, hits)

    def _extract_possible_payload_in_messages(self, hits: list[dict]) -> None:
        """
        Extract URLs hidden in attack payloads (login messages, file uploads).
        Processes all hits once for efficiency (O(M) instead of O(N*M)).

        Args:
            hits: List of hits to search for payloads
        """
        for hit in hits:
            if hit.get("eventid", "") not in [
                "cowrie.login.failed",
                "cowrie.session.file_upload",
            ]:
                continue

            match_url = re.search(REGEX_URL_PROTOCOL, hit.get("message", ""))
            if not match_url:
                continue

            scanner_ip = hit["src_ip"]
            payload_url = match_url.group()
            payload_hostname = parse_url_hostname(payload_url)

            if not payload_hostname:
                self.log.warning(f"Failed to parse hostname from URL: {payload_url}")
                continue

            self.log.info(f"found hidden URL {payload_url} in payload from attacker {scanner_ip}")
            self.log.info(f"extracted hostname {payload_hostname} from {payload_url}")

            ioc = IOC(
                name=payload_hostname,
                type=get_ioc_type(payload_hostname),
                related_urls=[payload_url],
            )
            sensor = hit.get("_sensor")
            if sensor:
                ioc._sensors_to_add = [sensor]
            self.ioc_processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST, general_honeypot_name="Cowrie")
            self._add_fks(scanner_ip, payload_hostname)
            self.payloads_in_message += 1

    def _get_url_downloads(self, hits: list[dict]) -> None:
        """
        Extract file download attempts and associate scanners with download URLs.

        Args:
            hits: List of hits to search for download events
        """
        for hit in hits:
            if "url" not in hit:
                continue
            if hit.get("eventid", "") != "cowrie.session.file_download":
                continue

            scanner_ip = str(hit["src_ip"])
            download_url = str(hit["url"])

            self.log.info(f"found IP {scanner_ip} downloading from {download_url}")

            # Extract and track download URL
            if download_url:
                hostname = parse_url_hostname(download_url)
                if not hostname:
                    self.log.warning(f"Failed to parse hostname from download URL: {download_url}")
                    continue

                ioc = IOC(
                    name=hostname,
                    type=get_ioc_type(hostname),
                    related_urls=[download_url],
                )
                sensor = hit.get("_sensor")
                if sensor:
                    ioc._sensors_to_add = [sensor]
                ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST, general_honeypot_name="Cowrie")
                if ioc_record:
                    self.added_url_downloads += 1
                    threatfox_submission(ioc_record, ioc.related_urls, self.log)
                self._add_fks(scanner_ip, hostname)

    def _get_sessions(self, ioc: IOC, hits: list[dict]) -> None:
        """
        Extract and save session data for a given scanner IOC.

        Args:
            ioc: Scanner IOC object
            hits: List of hits to process
        """
        self.log.info(f"adding cowrie sessions from {ioc.name}")
        hits_per_session = defaultdict(list)

        for hit in hits:
            if hit["src_ip"] != ioc.name:
                continue
            hits_per_session[hit["session"]].append(hit)

        for sid, session_hits in hits_per_session.items():
            session_record = self.session_repo.get_or_create_session(session_id=sid, source=ioc)

            for hit in sorted(session_hits, key=lambda hit: hit["timestamp"]):
                self._process_session_hit(session_record, hit, ioc)

            if session_record.commands is not None:
                self._deduplicate_command_sequence(session_record)
                self.session_repo.save_command_sequence(session_record.commands)
                self.log.info(f"saved new command execute from {ioc.name} with hash {session_record.commands.commands_hash}")

            self.ioc_repo.save(session_record.source)
            self.session_repo.save_session(session_record)

        self.log.info(f"{len(hits_per_session)} sessions added")

    def _process_session_hit(self, session_record: CowrieSession, hit: dict, ioc: IOC) -> None:
        """
        Process a single hit and update the session record.

        Args:
            session_record: CowrieSession instance to update
            hit: Hit document to process
            ioc: Associated IOC for logging
        """
        eventid = hit.get("eventid")

        match eventid:
            case "cowrie.session.connect":
                session_record.start_time = hit["timestamp"]

            case "cowrie.login.failed" | "cowrie.login.success":
                session_record.login_attempt = True
                username = normalize_credential_field(hit["username"])
                password = normalize_credential_field(hit["password"])
                credential, _ = Credential.objects.get_or_create(username=username, password=password)
                session_record.credentials.add(credential)
                session_record.source.login_attempts += 1

            case "cowrie.command.input":
                self.log.info(f"found a command execution from {ioc.name}")
                session_record.command_execution = True

                if session_record.commands is None:
                    session_record.commands = CommandSequence()
                    session_record.commands.first_seen = hit["timestamp"]

                command = normalize_command(hit["message"])
                session_record.commands.last_seen = hit["timestamp"]
                session_record.commands.commands.append(command)

            case "cowrie.session.closed":
                session_record.duration = hit["duration"]

        session_record.interaction_count += 1

    def _add_fks(self, scanner_ip: str, hostname: str) -> None:
        """
        Link related IOCs bidirectionally (scanner IP <-> hostname).

        Args:
            scanner_ip: Scanner IP address
            hostname: Hostname to link with scanner
        """
        scanner_ip_instance = self.ioc_repo.get_ioc_by_name(scanner_ip)
        hostname_instance = self.ioc_repo.get_ioc_by_name(hostname)

        # Log warning if IOCs are missing - shouldn't happen in normal operation
        if not scanner_ip_instance or not hostname_instance:
            self.log.warning(
                f"Cannot link IOCs - missing from database: scanner_ip={scanner_ip_instance is not None}, hostname={hostname_instance is not None}"
            )
            return

        # Link bidirectionally - Django's .add() handles deduplication automatically
        scanner_ip_instance.related_ioc.add(hostname_instance)
        self.ioc_repo.save(scanner_ip_instance)

        hostname_instance.related_ioc.add(scanner_ip_instance)
        self.ioc_repo.save(hostname_instance)

    def _deduplicate_command_sequence(self, session: CowrieSession) -> bool:
        """
        Deduplicate command sequences by hashing and merging with existing sequences.

        Args:
            session: CowrieSession instance containing command sequence data

        Returns:
            True if merged with existing sequence, False if new sequence
        """
        commands_str = "\n".join(session.commands.commands)
        commands_hash = sha256(commands_str.encode()).hexdigest()

        cmd_seq = self.session_repo.get_command_sequence_by_hash(commands_hash=commands_hash)
        if cmd_seq is None:
            session.commands.commands_hash = commands_hash
            return False

        last_seen = session.commands.last_seen
        session.commands = cmd_seq
        session.commands.last_seen = last_seen
        return True
