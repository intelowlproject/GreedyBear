# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from abc import ABCMeta
from datetime import datetime
from ipaddress import IPv4Address

from greedybear.consts import DOMAIN, IP, PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.sensors import ExtractSensors
from greedybear.models import IOC, GeneralHoneypot, Sensors


class ExtractAttacks(Cronjob, metaclass=ABCMeta):
    class IOCWhitelist(Exception):
        pass

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
            minutes = 11
        return minutes

    def _add_ioc(self, ioc, attack_type: str, general=None) -> bool:
        self.log.info(f"saving ioc {ioc}")
        if ioc.name in self.whitelist:
            self.log.info(f"not saved {ioc} because is whitelisted")
            return False

        today = datetime.today().date()
        try:
            ioc_record = IOC.objects.get(name=ioc.name)
        except IOC.DoesNotExist:
            ioc_record = ioc
        else:
            ioc_record.related_urls = sorted(set(ioc_record.related_urls + ioc.related_urls))
            ioc_record.destination_ports = sorted(set(ioc_record.destination_ports + ioc.destination_ports))
            ioc_record.ip_reputation = ioc.ip_reputation
            ioc_record.asn = ioc.asn
            ioc_record.login_attempts += ioc.login_attempts

        if general is not None:
            if general not in ioc_record.general_honeypot.all():
                ioc_record.general_honeypot.add(GeneralHoneypot.objects.get(name=general))

        if len(ioc_record.days_seen) == 0 or ioc_record.days_seen[-1] != today:
            ioc_record.days_seen.append(today)
            ioc_record.number_of_days_seen += 1
        ioc_record.last_seen = datetime.utcnow()
        ioc_record.times_seen += 1
        ioc_record.scanner = attack_type == SCANNER
        ioc_record.payload_request = attack_type == PAYLOAD_REQUEST
        ioc_record.save()

    def _get_ioc_type(self, ioc):
        try:
            IPv4Address(ioc)
        except ValueError:
            ioc_type = DOMAIN
        else:
            ioc_type = IP
        return ioc_type

    def _check_first_time_run(self, honeypot_flag, general=False):
        all_ioc = IOC.objects.all()
        if not all_ioc:
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

            if not honeypot_ioc:
                # first time we execute this project.
                # So we increment the time range to get the data from the last 3 days
                self.first_time_run = True
