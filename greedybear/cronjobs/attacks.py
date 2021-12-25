import base64
import datetime
import re
from ipaddress import IPv4Address
from urllib.parse import urlparse

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.base import ExtractDataFromElastic, Honeypot
from greedybear.models import IOC, Sensors
from greedybear.regex import REGEX_CVE_BASE64COMMAND, REGEX_CVE_LOG4J, REGEX_URL


class ExtractAttacks(ExtractDataFromElastic):
    class IOCWhitelist(Exception):
        pass

    def __init__(self):
        super().__init__()
        self.honeypot = Honeypot("Log4pot")
        self.first_time_run = False

    @property
    def minutes_back_to_lookup(self):
        if self.first_time_run:
            minutes = 60 * 24 * 3  # 3 days
        else:
            minutes = 11
        return minutes

    def _log4pot_lookup(self):
        search = self._base_search(self.honeypot)
        # we want to get only probes that tried to exploit the specific log4j CVE
        search = search.filter("term", reason="exploit")
        search = search.source(["deobfuscated_payload", "correlation_id"])
        hits = search[:10000].execute()

        url = None
        hostname = None
        hidden_url = None
        hidden_hostname = None

        for hit in hits:
            scanner_ip = self._get_scanner_ip(hit.correlation_id)

            match = re.search(REGEX_CVE_LOG4J, hit.deobfuscated_payload)
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
            match_command = re.search(REGEX_CVE_BASE64COMMAND, hit.deobfuscated_payload)
            if match_command:
                # we are losing the protocol but that's ok for now
                base64_encoded = match_command.group(1)
                self.log.info(
                    f"found base64 encoded command {base64_encoded}"
                    f" in payload from base64 code for CVE-2021-44228"
                )
                try:
                    decoded_str = base64.b64decode(base64_encoded).decode()
                    self.log.info(
                        f"decoded base64 command to {decoded_str}"
                        f" from payload from base64 code for CVE-2021-44228"
                    )
                except Exception as e:
                    self.log.warning(e, stack_info=True)
                else:
                    match_url = re.search(REGEX_URL, decoded_str)
                    if match_url:
                        hidden_url = match_url.group()
                        if "://" not in hidden_url:
                            hidden_url = "tcp://" + hidden_url
                        self.log.info(
                            f"found hidden URL {hidden_url}"
                            f" in payload for CVE-2021-44228"
                        )

                        hidden_hostname = urlparse(hidden_url).hostname
                        self.log.info(
                            f"extracted hostname {hidden_hostname} from {hidden_url}"
                        )

            # add scanner
            if scanner_ip:
                self._add_ioc(scanner_ip, SCANNER)

            # add first URL
            if hostname:
                related_urls = [url] if url else None
                self._add_ioc(hostname, PAYLOAD_REQUEST, related_urls=related_urls)

            # add hidden URL
            if hidden_hostname:
                related_urls = [hidden_url] if hidden_url else None
                self._add_ioc(
                    hidden_hostname, PAYLOAD_REQUEST, related_urls=related_urls
                )

            # once all have added, we can add the foreign keys
            self._add_fks(scanner_ip, hostname, hidden_hostname)

    def _add_fks(self, scanner_ip, hostname, hidden_hostname):
        self.log.info(
            f"adding foreign keys for the following iocs: {scanner_ip}, {hostname}, {hidden_hostname}"
        )
        scanner_ip_instance = IOC.objects.filter(name=scanner_ip).first()
        hostname_instance = IOC.objects.filter(name=hostname).first()
        hidden_hostname_instance = IOC.objects.filter(name=hidden_hostname).first()

        if scanner_ip_instance:
            if (
                hostname_instance
                and hostname_instance not in scanner_ip_instance.related_ioc.all()
            ):
                scanner_ip_instance.related_ioc.add(hostname_instance)
            if (
                hidden_hostname_instance
                and hidden_hostname_instance
                not in scanner_ip_instance.related_ioc.all()
            ):
                scanner_ip_instance.related_ioc.add(hidden_hostname_instance)
            scanner_ip_instance.save()

        if hostname_instance:
            if (
                scanner_ip_instance
                and scanner_ip_instance not in hostname_instance.related_ioc.all()
            ):
                hostname_instance.related_ioc.add(scanner_ip_instance)
            if (
                hidden_hostname_instance
                and hidden_hostname_instance not in hostname_instance.related_ioc.all()
            ):
                hostname_instance.related_ioc.add(hidden_hostname_instance)
            hostname_instance.save()

        if hidden_hostname_instance:
            if (
                hostname_instance
                and hostname_instance not in hidden_hostname_instance.related_ioc.all()
            ):
                hidden_hostname_instance.related_ioc.add(hostname_instance)
            if (
                scanner_ip_instance
                and scanner_ip_instance
                not in hidden_hostname_instance.related_ioc.all()
            ):
                hidden_hostname_instance.related_ioc.add(scanner_ip_instance)
            hidden_hostname_instance.save()

    def _add_ioc(self, ioc, attack_type, related_urls=None):
        self.log.info(
            f"saving ioc {ioc} for attack_type {attack_type} and related_urls {related_urls}"
        )
        try:
            ioc_type = self._get_ioc_type(ioc)
            try:
                ioc_instance = IOC.objects.get(name=ioc)
            except IOC.DoesNotExist:
                self._check_if_allowed(ioc)
                ioc_instance = IOC(
                    name=ioc,
                    type=ioc_type,
                    honeypots=[self.honeypot.name],
                    attack_types=[attack_type],
                )
                if related_urls:
                    ioc_instance.related_urls = related_urls
            else:
                ioc_instance.last_seen = datetime.datetime.utcnow()
                ioc_instance.times_seen += 1
                if self.honeypot.name not in ioc_instance.honeypots:
                    ioc_instance.honeypots.append(self.honeypot.name)
                if attack_type not in ioc_instance.attack_types:
                    ioc_instance.attack_types.append(attack_type)
                if related_urls:
                    for related_url in related_urls:
                        if related_url not in ioc_instance.related_urls:
                            ioc_instance.related_urls.append(related_url)

            if ioc_instance:
                ioc_instance.save()
        except self.IOCWhitelist:
            self.log.info(f"not saved {ioc} because is whitelisted")

    def _check_if_allowed(self, ioc):
        try:
            Sensors.objects.get(address=ioc)
        except Sensors.DoesNotExist:
            pass
        else:
            raise self.IOCWhitelist()

    def _get_ioc_type(self, ioc):
        try:
            IPv4Address(ioc)
        except ValueError:
            ioc_type = "domain"
        else:
            ioc_type = "ip"
        return ioc_type

    def _get_scanner_ip(self, correlation_id):
        self.log.info(f"extracting scanner IP from correlation_id {correlation_id}")
        scanner_ip = None
        search = self._base_search(self.honeypot)
        search = search.filter("term", correlation_id=correlation_id)
        search = search.filter("term", reason="request")
        search = search.source(["src_ip"])
        hits = search[:10].execute()
        for hit in hits:
            scanner_ip = hit.src_ip

        if scanner_ip:
            self.log.info(
                f"extracted scanner IP {scanner_ip} from correlation_id {correlation_id}"
            )
        else:
            self.log.warning(
                f"scanner IP was not extracted from correlation_id {correlation_id}"
            )

        return scanner_ip

    def _check_first_time_run(self):
        all_ioc = IOC.objects.all()
        if not all_ioc:
            # first time we execute this project.
            # So we increment the time range to get the data from the last 3 days
            self.first_time_run = True

    def run(self):
        self._healthcheck()
        self._check_first_time_run()
        self._log4pot_lookup()
