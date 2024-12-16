# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import re
from collections import defaultdict
from urllib.parse import urlparse

from greedybear.consts import ATTACK_DATA_FIELDS, PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.attacks import ExtractAttacks
from greedybear.cronjobs.honeypots import Honeypot
from greedybear.models import IOC, CowrieSession
from greedybear.regex import REGEX_URL_PROTOCOL


class ExtractCowrie(ExtractAttacks):
    def __init__(self, minutes_back=None):
        super().__init__(minutes_back=minutes_back)
        self.cowrie = Honeypot("Cowrie")
        self.added_scanners = 0
        self.payloads_in_message = 0
        self.added_ip_downloads = 0
        self.added_url_downloads = 0

    def _cowrie_lookup(self):
        self._get_scanners()
        self._get_url_downloads()
        self.log.info(
            f"added {self.added_scanners} scanners, "
            f"{self.payloads_in_message} payload found in messages,"
            f" {self.added_ip_downloads} IP that tried to download,"
            f" {self.added_url_downloads} URL to download"
        )

    def _get_scanners(self):
        for ioc in self._get_attacker_data(self.cowrie, ATTACK_DATA_FIELDS):
            ioc.cowrie = True
            self.log.info(f"found IP {ioc.name} by honeypot cowrie")
            self._add_ioc(ioc, attack_type=SCANNER)
            self.added_scanners += 1
            self._extract_possible_payload_in_messages(ioc.name)
            self._get_sessions(ioc.name)

    def _extract_possible_payload_in_messages(self, scanner_ip):
        # looking for URLs inside attacks payloads
        search = self._base_search(self.cowrie)
        search = search.filter("terms", eventid=["cowrie.login.failed", "cowrie.session.file_upload"])
        search = search.filter("term", src_ip=scanner_ip)
        search = search.source(["message"])
        hits = search[:100].execute()
        for hit in hits:
            match_url = re.search(REGEX_URL_PROTOCOL, hit.message)
            if match_url:
                payload_url = match_url.group()
                self.log.info(f"found hidden URL {payload_url}" f" in payload from attacker {scanner_ip}")
                payload_hostname = urlparse(payload_url).hostname
                self.log.info(f"extracted hostname {payload_hostname} from {payload_url}")
                ioc = IOC(
                    name=payload_hostname,
                    type=self._get_ioc_type(payload_hostname),
                    cowrie=True,
                    related_urls=[payload_url],
                )
                self._add_ioc(ioc, attack_type=PAYLOAD_REQUEST)
                self._add_fks(scanner_ip, payload_hostname)

    def _get_url_downloads(self):
        search = self._base_search(self.cowrie)
        search = search.filter("term", eventid="cowrie.session.file_download")
        search = search.filter("exists", field="url")
        search = search.source(["src_ip", "url"])
        hits = search[:1000].execute()
        for hit in hits:
            self.log.info(f"found IP {hit.src_ip} trying to execute download from {hit.url}")
            scanner_ip = str(hit.src_ip)
            ioc = IOC(name=scanner_ip, type=self._get_ioc_type(scanner_ip), cowrie=True)
            self._add_ioc(ioc, attack_type=SCANNER)
            self.added_ip_downloads += 1
            download_url = str(hit.url)
            if download_url:
                hostname = urlparse(download_url).hostname
                ioc = IOC(
                    name=hostname,
                    type=self._get_ioc_type(hostname),
                    cowrie=True,
                    related_urls=[download_url],
                )
                self._add_ioc(ioc, attack_type=PAYLOAD_REQUEST)
                self.added_url_downloads += 1
                self._add_fks(scanner_ip, hostname)

    def _get_sessions(self, scanner_ip: str):
        self.log.info(f"adding cowrie sessions from {scanner_ip}")
        search = self._base_search(self.cowrie)
        search = search.filter("term", src_ip=scanner_ip)
        search = search.source(["session", "eventid", "timestamp", "duration", "message", "username", "password"])
        hits_per_session = defaultdict(list)

        for hit in search.iterate():
            hits_per_session[int(hit.session, 16)].append(hit)

        for sid, hits in hits_per_session.items():
            try:
                session_record = CowrieSession.objects.get(session_id=sid)
            except CowrieSession.DoesNotExist:
                session_record = CowrieSession(session_id=sid)

            session_record.source = IOC.objects.filter(name=scanner_ip).first()
            for hit in hits:
                match hit.eventid:
                    case "cowrie.session.connect":
                        session_record.start_time = hit.timestamp
                    case "cowrie.login.failed" | "cowrie.login.success":
                        session_record.login_attempt = True
                        session_record.credentials.append(f"{hit.username} | {hit.password}")
                        session_record.source.login_attempts += 1
                    case "cowrie.command.input":
                        session_record.command_execution = True
                    case "cowrie.session.closed":
                        session_record.duration = hit.duration
                session_record.interaction_count += 1

            session_record.source.save()
            session_record.save()

        self.log.info(f"{len(hits_per_session)} sessions added")

    def _add_fks(self, scanner_ip, hostname):
        self.log.info(f"adding foreign keys for the following iocs: {scanner_ip}, {hostname}")
        scanner_ip_instance = IOC.objects.filter(name=scanner_ip).first()
        hostname_instance = IOC.objects.filter(name=hostname).first()

        if scanner_ip_instance:
            if hostname_instance and hostname_instance not in scanner_ip_instance.related_ioc.all():
                scanner_ip_instance.related_ioc.add(hostname_instance)
            scanner_ip_instance.save()

        if hostname_instance:
            if scanner_ip_instance and scanner_ip_instance not in hostname_instance.related_ioc.all():
                hostname_instance.related_ioc.add(scanner_ip_instance)
            hostname_instance.save()

    def run(self):
        self._healthcheck()
        self._check_first_time_run("cowrie")
        self._cowrie_lookup()
