# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from abc import ABCMeta
from collections import defaultdict
from datetime import datetime
from ipaddress import IPv4Address

from greedybear.consts import DOMAIN, IP, PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.sensors import ExtractSensors
from greedybear.models import IOC, GeneralHoneypot, Sensors
from greedybear.settings import EXTRACTION_INTERVAL, LEGACY_EXTRACTION


class ExtractAttacks(Cronjob, metaclass=ABCMeta):
    def __init__(self, minutes_back=None):
        super().__init__()
        self.first_time_run = False
        self.minutes_back = minutes_back
        self.whitelist = set(Sensors.objects.all())

    @property
    def minutes_back_to_lookup(self):
        # overwrite base
        if self.minutes_back:
            minutes = self.minutes_back
        elif self.first_time_run:
            minutes = 60 * 24 * 3  # 3 days
        else:
            minutes = 11 if LEGACY_EXTRACTION else EXTRACTION_INTERVAL
        return minutes

    def _add_ioc(self, ioc, attack_type: str, general=None) -> bool:
        self.log.info(f"saving ioc {ioc} for attack_type {attack_type}")
        if ioc.name in self.whitelist:
            self.log.info(f"not saved {ioc} because is whitelisted")
            return False

        try:
            ioc_record = IOC.objects.get(name=ioc.name)
        except IOC.DoesNotExist:
            # Create
            ioc_record = ioc
            ioc_record.save()
        else:
            # Update
            ioc_record.last_seen = ioc.last_seen
            ioc_record.attack_count += 1
            ioc_record.interaction_count += ioc.interaction_count
            ioc_record.related_urls = sorted(set(ioc_record.related_urls + ioc.related_urls))
            ioc_record.destination_ports = sorted(set(ioc_record.destination_ports + ioc.destination_ports))
            ioc_record.ip_reputation = ioc.ip_reputation
            ioc_record.asn = ioc.asn
            ioc_record.login_attempts += ioc.login_attempts

        if general is not None:
            if general not in ioc_record.general_honeypot.all():
                ioc_record.general_honeypot.add(GeneralHoneypot.objects.get(name=general))

        if len(ioc_record.days_seen) == 0 or ioc_record.days_seen[-1] != ioc_record.last_seen.date():
            ioc_record.days_seen.append(ioc_record.last_seen.date())
            ioc_record.number_of_days_seen = len(ioc_record.days_seen)
        ioc_record.scanner = attack_type == SCANNER
        ioc_record.payload_request = attack_type == PAYLOAD_REQUEST
        ioc_record.save()

    def _get_attacker_data(self, honeypot, fields: list) -> list:
        hits_by_ip = defaultdict(list)
        search = self._base_search(honeypot)
        search.source(fields)
        for hit in search.iterate():
            if "src_ip" not in hit:
                continue
            hits_by_ip[hit.src_ip].append(hit.to_dict())
        iocs = []
        for ip, hits in hits_by_ip.items():
            dest_ports = [hit["dest_port"] for hit in hits if "dest_port" in hit]
            ioc = IOC(
                name=ip,
                type=self._get_ioc_type(ip),
                interaction_count=len(hits),
                ip_reputation=hits[0].get("ip_rep", ""),
                asn=hits[0].get("geoip", {}).get("asn"),
                destination_ports=sorted(set(dest_ports)),
                login_attempts=len(hits) if honeypot.name == "Heralding" else 0,
            )
            timestamps = [hit["@timestamp"] for hit in hits if "@timestamp" in hit]
            if timestamps:
                ioc.first_seen = datetime.fromisoformat(min(timestamps))
                ioc.last_seen = datetime.fromisoformat(max(timestamps))
            iocs.append(ioc)
        return iocs

    def _get_ioc_type(self, ioc):
        try:
            IPv4Address(ioc)
        except ValueError:
            ioc_type = DOMAIN
        else:
            ioc_type = IP
        return ioc_type

    def _check_first_time_run(self, honeypot_flag, general=False):
        if not IOC.objects.exists():
            # plus, we extract the sensors addresses so we can whitelist them
            ExtractSensors().execute()
            self.first_time_run = True
        else:
            # if this is not the overall first time, it could that honeypot first time
            # FEEDS for a general honeypot it needs to be checked if it's in the list
            if not general:
                honeypot_ioc = IOC.objects.filter(**{f"{honeypot_flag}": True})
            else:
                honeypot_ioc = IOC.objects.filter(**{"general_honeypot__name__iexact": honeypot_flag})

            if not honeypot_ioc.exists():
                # first time we execute this project.
                # So we increment the time range to get the data from the last 3 days
                self.first_time_run = True
