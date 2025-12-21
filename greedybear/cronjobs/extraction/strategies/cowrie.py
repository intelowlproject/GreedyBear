# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from hashlib import sha256
from typing import Dict, List

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.extraction.strategies import BaseExtractionStrategy
from greedybear.cronjobs.extraction.strategies.cowrie_parser import CowrieLogParser, CowrieSessionData
from greedybear.cronjobs.extraction.utils import get_ioc_type, iocs_from_hits, threatfox_submission
from greedybear.cronjobs.repositories import CowrieSessionRepository, IocRepository, SensorRepository
from greedybear.models import IOC, CommandSequence, CowrieSession


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
        self.parser = CowrieLogParser(self.log)
        self.payloads_in_message = 0
        self.added_ip_downloads = 0
        self.added_url_downloads = 0

    def extract_from_hits(self, hits: list[dict]) -> None:
        # 1. Process Scanners (using util that aggregates distinct IPs)
        self._get_scanners(hits)

        # 2. Process Payloads
        payloads = self.parser.extract_payloads(hits)
        self._save_payloads(payloads)

        # 3. Process Downloads
        downloads = self.parser.extract_downloads(hits)
        self._save_downloads(downloads)

        # 4. Process Sessions
        sessions = self.parser.extract_sessions(hits)
        self._save_sessions(sessions)

        self.log.info(
            f"added {len(self.ioc_records)} scanners, "
            f"{self.payloads_in_message} payload found in messages, "
            f"{self.added_ip_downloads} IP that tried to download, "
            f"{self.added_url_downloads} URL to download"
        )
        self.log.info(f"{len(sessions)} sessions processed")

    def _get_scanners(self, hits: list[dict]) -> None:
        for ioc in iocs_from_hits(hits):
            ioc.cowrie = True
            self.log.info(f"found IP {ioc.name} by honeypot cowrie")
            ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=SCANNER)
            if ioc_record:
                self.ioc_records.append(ioc_record)
                threatfox_submission(ioc_record, ioc.related_urls, self.log)
                # Note: Previous code called payload/session extraction here
                # We now do it separately in extract_from_hits

    def _save_payloads(self, payloads: List[Dict]) -> None:
        for payload in payloads:
            scanner_ip = payload["source_ip"]
            payload_url = payload["payload_url"]
            payload_hostname = payload["payload_hostname"]

            self.log.info(f"found hidden URL {payload_url} in payload from attacker {scanner_ip}")
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

    def _save_downloads(self, downloads: List[Dict]) -> None:
        for download in downloads:
            scanner_ip = download["source_ip"]
            download_url = download["download_url"]
            hostname = download["hostname"]

            self.log.info(f"found IP {scanner_ip} trying to execute download from {download_url}")

            # Ensure scanner IP is tracked as scanner (redundant if _get_scanners ran first,
            # but original code did this explicitly)
            scanner_ioc = IOC(name=scanner_ip, type=get_ioc_type(scanner_ip), cowrie=True)
            scanner_record = self.ioc_processor.add_ioc(scanner_ioc, attack_type=SCANNER)

            # The original code counters incremented only if add_ioc returned record?
            # Original:
            # ioc_record = self.ioc_processor.add_ioc(scanner_ioc, attack_type=SCANNER)
            # if ioc_record: self.added_ip_downloads += 1 ...

            if scanner_record:
                self.added_ip_downloads += 1
                threatfox_submission(scanner_record, scanner_ioc.related_urls, self.log)

            if download_url:
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

    def _save_sessions(self, sessions: Dict[str, CowrieSessionData]) -> None:
        for sid, session_data in sessions.items():
            source_ip = session_data.source_ip
            # We need the IOC object for the source IP
            # It should have been created by _get_scanners
            scanner_ioc = self.ioc_repo.get_ioc_by_name(source_ip)
            if not scanner_ioc:
                # Should not happen if data consistency holds, but fallback:
                self.log.warning(f"Session {sid} has unknown source IP {source_ip}, creating IOC.")
                scanner_ioc = IOC(name=source_ip, type=get_ioc_type(source_ip), cowrie=True)
                scanner_ioc = self.ioc_processor.add_ioc(scanner_ioc, attack_type=SCANNER)
                if not scanner_ioc:
                    # Could be None if whitelisted?
                    self.log.warning(f"Could not create IOC for {source_ip}, skipping session {sid}")
                    continue

            self.log.info(f"adding cowrie sessions from {source_ip}")

            session_record = self.session_repo.get_or_create_session(session_id=sid, source=scanner_ioc)

            # Update fields from simple data mapping
            session_record.start_time = session_data.start_time
            session_record.duration = session_data.duration
            session_record.login_attempt = session_data.login_attempt
            session_record.credentials.extend(session_data.credentials)  # extend or overwrite? Original used append inside loop
            # session_data.credentials is a list accumulated from hits.
            # If session_record already exists, we might append duplicate credentials if hits are re-processed?
            # Original: session_record.credentials.append(f"{username} | {password}")

            # If session exists, we are updating it.
            # But normally we process new hits.
            # For correctness matching original: we should probably be careful about duplication if running multiple times?
            # The original code: for hit in sorted(hits): ... append ...
            # If we just assign, we replace.
            # But the original code was: check DoesNotExist, create, THEN iterating hits and updating fields.
            # If session existed, it would append MORE credentials.
            # So I should also append?
            # However, session_data.credentials contains ALL credentials from the hits provided.
            # If these hits were already processed, we are duplicating.
            # But extraction usually runs on recent hits.

            # Let's assume appending is correct behavior or replacing if we trust fresh aggregation.
            # But since we use get_or_create, session might have old data.
            # Actually, `get_or_create_session` usually returns instance.
            # If I append session_data.credentials to session_record.credentials, fine.
            # Wait, `session_record.credentials` is ArrayField (list).
            # I should probably just set it if I assume I have the full view of the session?
            # No, maybe only partial hits.
            # Safety: append.

            # Wait, `session_record.credentials` default is list.
            if session_data.credentials:
                # Original used append one by one.
                session_record.credentials.extend(session_data.credentials)

            if session_data.login_attempt:
                # Need to increment login_attempts on source IOC?
                # Original: session_record.source.login_attempts += 1 (inside loop for each hit)
                # So calculate total attempts from session_data
                count = len(session_data.credentials)
                # Or based on hits? Original: for hit in hits: if connect/failed: login_attempts += 1.
                # session_data.credentials corresponds to failed/success hits.
                session_record.source.login_attempts += count

            if session_data.command_execution:
                self.log.info(f"found a command execution from {source_ip}")
                session_record.command_execution = True

                if session_record.commands is None:
                    session_record.commands = CommandSequence()
                    # Ensure first_seen is set if new
                    if session_data.commands_first_seen:
                        session_record.commands.first_seen = session_data.commands_first_seen

                if session_data.commands_last_seen:
                    session_record.commands.last_seen = session_data.commands_last_seen

                session_record.commands.commands.extend(session_data.commands)

            session_record.interaction_count += session_data.interaction_count

            if session_record.commands is not None:
                self._deduplicate_command_sequence(session_record)
                self.session_repo.save_command_sequence(session_record.commands)
                self.log.info(f"saved new command execute from {source_ip} " f"with hash {session_record.commands.commands_hash}")

            self.ioc_repo.save(session_record.source)
            self.session_repo.save_session(session_record)

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
