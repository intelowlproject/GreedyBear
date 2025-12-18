# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import re
from collections import defaultdict
from hashlib import sha256
from urllib.parse import urlparse

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.extraction.strategies import BaseExtractionStrategy
from greedybear.cronjobs.extraction.utils import (get_ioc_type, iocs_from_hits,
                                                  threatfox_submission)
from greedybear.cronjobs.repositories import (CowrieSessionRepository,
                                              IocRepository, SensorRepository)
from greedybear.models import IOC, CommandSequence, CowrieSession
from greedybear.regex import REGEX_URL_PROTOCOL


class CowrieExtractionStrategy(BaseExtractionStrategy):
    """
    Extraction strategy for Cowrie SSH/Telnet honeypot.
    Extracts scanner IPs, payload URLs from login attempts and file downloads,
    and session data including credentials and command sequences. Links related
    IOCs (scanners to download URLs) and deduplicates command sequences by hash.
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
        self.added_ip_downloads = 0
        self.added_url_downloads = 0

    def extract_from_hits(self, hits: list[dict]) -> None:
        self._get_scanners(hits)
        self._get_url_downloads(hits)
        self.log.info(
            f"added {len(self.ioc_records)} scanners, "
            f"{self.payloads_in_message} payload found in messages, "
            f"{self.added_ip_downloads} IP that tried to download, "
            f"{self.added_url_downloads} URL to download"
        )

    def _get_scanners(self, hits: list[dict]) -> None:
        for ioc in iocs_from_hits(hits):
            ioc.cowrie = True
            self.log.info(f"found IP {ioc.name} by honeypot cowrie")
            ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=SCANNER)
            if ioc_record:
                self.ioc_records.append(ioc_record)
                threatfox_submission(ioc_record, ioc.related_urls, self.log)
                self._extract_possible_payload_in_messages(ioc_record.name, hits)
                self._get_sessions(ioc_record, hits)

    def _extract_possible_payload_in_messages(self, scanner_ip: str, hits: list[dict]) -> None:
        # looking for URLs inside attacks payloads
        for hit in hits:
            if hit["src_ip"] != scanner_ip:
                continue
            if hit.get("eventid", "") not in ["cowrie.login.failed", "cowrie.session.file_upload"]:
                continue
            match_url = re.search(REGEX_URL_PROTOCOL, hit.get("message", ""))
            if match_url:
                payload_url = match_url.group()
                self.log.info(f"found hidden URL {payload_url} in payload from attacker {scanner_ip}")
                payload_hostname = urlparse(payload_url).hostname
                self.log.info(f"extracted hostname {payload_hostname} from {payload_url}")
                ioc = IOC(
                    name=payload_hostname,
                    type=get_ioc_type(payload_hostname),
                    cowrie=True,
                    related_urls=[payload_url],
                )
                self.ioc_processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST)
                self._add_fks(scanner_ip, payload_hostname)
                self.payloads_in_message += 1

    def _get_url_downloads(self, hits: list[dict]) -> None:
        for hit in hits:
            if "url" not in hit:
                continue
            if hit.get("eventid", "") != "cowrie.session.file_download":
                continue
            self.log.info(f"found IP {hit["src_ip"]} trying to execute download from {hit["url"]}")
            scanner_ip = str(hit["src_ip"])
            ioc = IOC(name=scanner_ip, type=get_ioc_type(scanner_ip), cowrie=True)
            ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=SCANNER)
            if ioc_record:
                self.added_ip_downloads += 1
                threatfox_submission(ioc_record, ioc.related_urls, self.log)
            download_url = str(hit["url"])
            if download_url:
                hostname = urlparse(download_url).hostname
                ioc = IOC(
                    name=hostname,
                    type=get_ioc_type(hostname),
                    cowrie=True,
                    related_urls=[download_url],
                )
                ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST)
                if ioc_record:
                    self.added_url_downloads += 1
                    threatfox_submission(ioc_record, ioc.related_urls, self.log)
                self._add_fks(scanner_ip, hostname)

    def _get_sessions(self, ioc: IOC, hits: list[dict]) -> None:
        self.log.info(f"adding cowrie sessions from {ioc.name}")
        hits_per_session = defaultdict(list)

        for hit in hits:
            if hit["src_ip"] != ioc.name:
                continue
            hits_per_session[hit["session"]].append(hit)

        for sid, hits in hits_per_session.items():
            session_record = self.session_repo.get_or_create_session(session_id=sid, source=ioc)
            for hit in sorted(hits, key=lambda hit: hit["timestamp"]):
                match hit["eventid"]:
                    case "cowrie.session.connect":
                        session_record.start_time = hit["timestamp"]
                    case "cowrie.login.failed" | "cowrie.login.success":
                        session_record.login_attempt = True
                        username = hit["username"].replace("\x00", "[NUL]")
                        password = hit["password"].replace("\x00", "[NUL]")
                        session_record.credentials.append(f"{username} | {password}")
                        session_record.source.login_attempts += 1
                    case "cowrie.command.input":
                        self.log.info(f"found a command execution from {ioc.name}")
                        session_record.command_execution = True
                        if session_record.commands is None:
                            session_record.commands = CommandSequence()
                            session_record.commands.first_seen = hit["timestamp"]
                        command = hit["message"].removeprefix("CMD: ").replace("\x00", "[NUL]")
                        session_record.commands.last_seen = hit["timestamp"]
                        session_record.commands.commands.append(command[:1024])
                    case "cowrie.session.closed":
                        session_record.duration = hit["duration"]
                session_record.interaction_count += 1
            if session_record.commands is not None:
                # moved this check at the end to avoid forgetting about this...
                # ...if the "closed" record is not available
                self._deduplicate_command_sequence(session_record)
                self.session_repo.save_command_sequence(session_record.commands)
                self.log.info(f"saved new command execute from {ioc.name} " f"with hash {session_record.commands.commands_hash}")
            self.ioc_repo.save(session_record.source)
            self.session_repo.save_session(session_record)

        self.log.info(f"{len(hits_per_session)} sessions added")

    def _add_fks(self, scanner_ip, hostname):
        self.log.info(f"adding foreign keys for the following iocs: {scanner_ip}, {hostname}")
        scanner_ip_instance = self.ioc_repo.get_ioc_by_name(scanner_ip)
        hostname_instance = self.ioc_repo.get_ioc_by_name(hostname)

        if scanner_ip_instance is not None:
            if hostname_instance and hostname_instance not in scanner_ip_instance.related_ioc.all():
                scanner_ip_instance.related_ioc.add(hostname_instance)
            self.ioc_repo.save(scanner_ip_instance)

        if hostname_instance is not None:
            if scanner_ip_instance and scanner_ip_instance not in hostname_instance.related_ioc.all():
                hostname_instance.related_ioc.add(scanner_ip_instance)
            self.ioc_repo.save(hostname_instance)

    def _deduplicate_command_sequence(self, session: CowrieSession) -> bool:
        """
        Deduplicates command sequences by hashing and either linking to an existing
        sequence or preparing for creation of a new one.

        Args:
            session: A CowrieSession instance containing command sequence data

        Returns:
            bool: True if merged with existing sequence, else False
        """
        commands_str = "\n".join(session.commands.commands)
        commands_hash = sha256(commands_str.encode()).hexdigest()
        # Check if the recorded sequence already exists
        cmd_seq = self.session_repo.get_command_sequence_by_hash(commands_hash=commands_hash)
        if cmd_seq is None:
            # In case sequence does not exist:
            # Assign hash to the the sequence
            session.commands.commands_hash = commands_hash
            return False
        # In case sequence does already exist:
        # Delete newly created sequence from DB
        # and assign existing sequence to session
        last_seen = session.commands.last_seen
        session.commands = cmd_seq
        # updated the last seen
        session.commands.last_seen = last_seen
        return True
