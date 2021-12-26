import logging
from urllib.parse import urlparse

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.attacks import ExtractAttacks
from greedybear.cronjobs.honeypots import Honeypot
from greedybear.models import IOC

logger = logging.getLogger(__name__)


class ExtractCowrie(ExtractAttacks):
    def __init__(self):
        super().__init__()
        self.cowrie = Honeypot("Cowrie")
        self.added_scanners = 0
        self.added_ip_downloads = 0
        self.added_url_downloads = 0

    def _cowrie_lookup(self):
        self._get_scanners()
        self._get_url_downloads()
        logger.info(
            f"added {self.added_scanners} scanners, {self.added_ip_downloads} IP that tried to download,"
            f" {self.added_url_downloads} URL to download"
        )

    def _get_scanners(self):
        search = self._base_search(self.cowrie)
        search = search.filter(
            "terms", eventid=["cowrie.login.failed", "cowrie.session.file_upload"]
        )
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
                logger.warning(f"why tag.key is empty? tag: {tag}")
                continue
            logger.info(f"found IP {tag.key} by honeypot cowrie")
            self._add_ioc(str(tag.key), SCANNER, cowrie=True)
            self.added_scanners += 1

    def _get_url_downloads(self):
        search = self._base_search(self.cowrie)
        search = search.filter("term", eventid="cowrie.session.file_download")
        search = search.source(["src_ip", "url"])
        hits = search[:10].execute()
        for hit in hits:
            logger.info(
                f"found IP {hit.src_ip} trying to execute download from {hit.url}"
            )
            scanner_ip = str(hit.src_ip)
            self._add_ioc(scanner_ip, SCANNER, cowrie=True)
            self.added_ip_downloads += 1
            download_url = str(hit.url)
            if download_url:
                hostname = urlparse(download_url).hostname
                self._add_ioc(
                    hostname, PAYLOAD_REQUEST, related_urls=[download_url], cowrie=True
                )
                self.added_url_downloads += 1
                self._add_fks(scanner_ip, hostname)

    def _get_file_uploads(self):
        search = self._base_search(self.cowrie)
        search = search.filter("term", eventid="cowrie.session.file_download")
        search = search.source(["src_ip", "url"])
        hits = search[:10].execute()
        for hit in hits:
            logger.info(
                f"found IP {hit.src_ip} trying to execute download from {hit.url}"
            )
            scanner_ip = str(hit.src_ip)
            self._add_ioc(scanner_ip, SCANNER, cowrie=True)
            self.added_ip_downloads += 1
            download_url = str(hit.url)
            if download_url:
                hostname = urlparse(download_url).hostname
                self._add_ioc(
                    hostname, PAYLOAD_REQUEST, related_urls=[download_url], cowrie=True
                )
                self.added_url_downloads += 1
                self._add_fks(scanner_ip, hostname)

    def _add_fks(self, scanner_ip, hostname):
        logger.info(
            f"adding foreign keys for the following iocs: {scanner_ip}, {hostname}"
        )
        scanner_ip_instance = IOC.objects.filter(name=scanner_ip).first()
        hostname_instance = IOC.objects.filter(name=hostname).first()

        if scanner_ip_instance:
            if (
                hostname_instance
                and hostname_instance not in scanner_ip_instance.related_ioc.all()
            ):
                scanner_ip_instance.related_ioc.add(hostname_instance)
            scanner_ip_instance.save()

        if hostname_instance:
            if (
                scanner_ip_instance
                and scanner_ip_instance not in hostname_instance.related_ioc.all()
            ):
                hostname_instance.related_ioc.add(scanner_ip_instance)
            hostname_instance.save()

    def run(self):
        self._healthcheck()
        self._check_first_time_run("cowrie")
        self._cowrie_lookup()
