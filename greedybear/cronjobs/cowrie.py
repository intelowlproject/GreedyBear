# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import re
from urllib.parse import urlparse

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.attacks import ExtractAttacks
from greedybear.cronjobs.honeypots import Honeypot
from greedybear.models import IOC
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
        search = self._base_search(self.cowrie)
        search = search.filter("terms", eventid=["cowrie.login.failed", "cowrie.session.file_upload"])
        # get no more than X IPs a day
        search.aggs.bucket(
            "attacker_ips",
            "terms",
            field="src_ip.keyword",
            size=1000,
        )
        agg_response = search[0:0].execute()
        for tag in agg_response.aggregations.attacker_ips.buckets:
            if not tag.key:
                self.log.warning(f"why tag.key is empty? tag: {tag}")
                continue
            self.log.info(f"found IP {tag.key} by honeypot cowrie")
            scanner_ip = str(tag.key)
            self._add_ioc(scanner_ip, SCANNER, cowrie=True)
            self.added_scanners += 1
            self._extract_possible_payload_in_messages(scanner_ip)

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
                self._add_ioc(
                    payload_hostname,
                    PAYLOAD_REQUEST,
                    related_urls=[payload_url],
                    cowrie=True,
                )
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
            self._add_ioc(scanner_ip, SCANNER, cowrie=True)
            self.added_ip_downloads += 1
            download_url = str(hit.url)
            if download_url:
                hostname = urlparse(download_url).hostname
                self._add_ioc(hostname, PAYLOAD_REQUEST, related_urls=[download_url], cowrie=True)
                self.added_url_downloads += 1
                self._add_fks(scanner_ip, hostname)

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
