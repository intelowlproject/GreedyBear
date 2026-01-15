# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import base64
import re
from urllib.parse import urlparse

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.extraction.strategies import BaseExtractionStrategy
from greedybear.extraction.utils import get_ioc_type
from greedybear.cronjobs.repositories import IocRepository, SensorRepository
from greedybear.models import IOC
from greedybear.regex import REGEX_CVE_BASE64COMMAND, REGEX_CVE_URL, REGEX_URL


class Log4potExtractionStrategy(BaseExtractionStrategy):
    """
    Extraction strategy for Log4pot honeypot (CVE-2021-44228).
    Extracts scanner IPs, payload URLs from JNDI/LDAP exploit attempts,
    and hidden URLs from base64-encoded commands. Links related IOCs
    (scanners to payload hosts) via foreign key relationships.
    """

    def __init__(
        self,
        honeypot: str,
        ioc_repo: IocRepository,
        sensor_repo: SensorRepository,
    ):
        super().__init__(honeypot, ioc_repo, sensor_repo)

    def extract_from_hits(self, hits: list[dict]) -> None:
        # we want to get only probes that tried to exploit the specific log4j CVE
        exploit_hits = [hit for hit in hits if hit.get("reason", "") == "exploit"]



        added_scanners = 0
        added_payloads = 0
        added_hidden_payloads = 0

        for hit in exploit_hits:
            url = None
            hostname = None
            hidden_url = None
            hidden_hostname = None
            
            scanner_ip = self._get_scanner_ip(hit.get("correlation_id"), hits)



            match = re.search(REGEX_CVE_URL, hit.get("deobfuscated_payload", ""))
            if match:
                # we are losing the protocol but that's ok for now
                url = match.group()
                url_adjusted = "tcp:" + url
                # removing double slash
                url = url[2:]
                self.log.info(f"found URL {url} in payload for CVE-2021-44228")
                # protocol required or extraction won't work
                hostname = urlparse(url_adjusted).hostname
                self.log.info(f"extracted hostname {hostname} from {url}")

            # it is possible to extract another payload from base64 encoded string.
            # this is a behavior related to the attack that leverages LDAP
            match_command = re.search(REGEX_CVE_BASE64COMMAND, hit.get("deobfuscated_payload", ""))
            if match_command:
                # we are losing the protocol but that's ok for now
                base64_encoded = match_command.group(1)
                self.log.info(f"found base64 encoded command {base64_encoded} in payload from base64 code for CVE-2021-44228")
                try:
                    decoded_str = base64.b64decode(base64_encoded).decode()
                    self.log.info(f"decoded base64 command to {decoded_str} from payload from base64 code for CVE-2021-44228")
                except Exception as e:
                    self.log.warning(e, stack_info=True)
                else:
                    match_url = re.search(REGEX_URL, decoded_str)
                    if match_url:
                        hidden_url = match_url.group()
                        if "://" not in hidden_url:
                            hidden_url = "tcp://" + hidden_url
                        self.log.info(f"found hidden URL {hidden_url} in payload for CVE-2021-44228")

                        hidden_hostname = urlparse(hidden_url).hostname
                        self.log.info(f"extracted hostname {hidden_hostname} from {hidden_url}")

            # add scanner
            if scanner_ip:
                ioc = IOC(name=scanner_ip, type=get_ioc_type(scanner_ip), log4j=True)
                ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=SCANNER)
                if ioc_record:
                    self.ioc_records.append(ioc_record)
                    added_scanners += 1

            # add first URL
            if hostname:
                related_urls = [url] if url else []
                ioc = IOC(
                    name=hostname,
                    type=get_ioc_type(hostname),
                    log4j=True,
                    related_urls=related_urls,
                )
                ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST)
                if ioc_record:
                    self.ioc_records.append(ioc_record)
                    added_payloads += 1

            # add hidden URL
            if hidden_hostname:
                related_urls = [hidden_url] if hidden_url else []
                ioc = IOC(
                    name=hidden_hostname,
                    type=get_ioc_type(hidden_hostname),
                    log4j=True,
                    related_urls=related_urls,
                )
                ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST)
                if ioc_record:
                    self.ioc_records.append(ioc_record)
                    added_hidden_payloads += 1

            # once all have added, we can add the foreign keys
            self._add_fks(scanner_ip, hostname, hidden_hostname)

        self.log.info(f"added {added_scanners} scanners, {added_payloads} payloads and {added_hidden_payloads} hidden payloads")


    def _add_fks(self, scanner_ip: str, hostname: str, hidden_hostname: str) -> None:
        self.log.info(f"adding foreign keys for the following iocs: {scanner_ip}, {hostname}, {hidden_hostname}")
        scanner_ip_instance = self.ioc_repo.get_ioc_by_name(scanner_ip)
        hostname_instance = self.ioc_repo.get_ioc_by_name(hostname)
        hidden_hostname_instance = self.ioc_repo.get_ioc_by_name(hidden_hostname)

        if scanner_ip_instance is not None:
            if hostname_instance and hostname_instance not in scanner_ip_instance.related_ioc.all():
                scanner_ip_instance.related_ioc.add(hostname_instance)
            if hidden_hostname_instance and hidden_hostname_instance not in scanner_ip_instance.related_ioc.all():
                scanner_ip_instance.related_ioc.add(hidden_hostname_instance)
            self.ioc_repo.save(scanner_ip_instance)

        if hostname_instance is not None:
            if scanner_ip_instance and scanner_ip_instance not in hostname_instance.related_ioc.all():
                hostname_instance.related_ioc.add(scanner_ip_instance)
            if hidden_hostname_instance and hidden_hostname_instance not in hostname_instance.related_ioc.all():
                hostname_instance.related_ioc.add(hidden_hostname_instance)
            self.ioc_repo.save(hostname_instance)

        if hidden_hostname_instance is not None:
            if hostname_instance and hostname_instance not in hidden_hostname_instance.related_ioc.all():
                hidden_hostname_instance.related_ioc.add(hostname_instance)
            if scanner_ip_instance and scanner_ip_instance not in hidden_hostname_instance.related_ioc.all():
                hidden_hostname_instance.related_ioc.add(scanner_ip_instance)
            self.ioc_repo.save(hidden_hostname_instance)

    def _get_scanner_ip(self, correlation_id: str, hits: list[dict]) -> str | None:
        self.log.info(f"extracting scanner IP from correlation_id {correlation_id}")
        filtered_hits = [hit for hit in hits if str(hit.get("correlation_id", "")) == str(correlation_id) and hit.get("reason", "") == "request"]

        if not filtered_hits:
            self.log.warning(f"scanner IP was not extracted from correlation_id {correlation_id}")
            return None
        scanner_ip = filtered_hits[0]["src_ip"]
        self.log.info(f"extracted scanner IP {scanner_ip} from correlation_id {correlation_id}")
        return scanner_ip
