# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from abc import ABCMeta
from datetime import datetime
from ipaddress import IPv4Address

from greedybear.consts import DOMAIN, IP, PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.sensors import ExtractSensors
from greedybear.models import IOC, GeneralHoneypot, Sensors
from greedybear.settings import EXTRACTION_INTERVAL, LEGACY_EXTRACTION


class ExtractAttacks(Cronjob, metaclass=ABCMeta):
    class IOCWhitelist(Exception):
        pass

    def __init__(self, minutes_back=None):
        super().__init__()
        self.first_time_run = False
        self.minutes_back = minutes_back

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

    def _add_ioc(self, ioc, attack_type, related_urls=None, log4j=False, cowrie=False, general=""):  # FEEDS
        self.log.info(f"saving ioc {ioc} for attack_type {attack_type} and related_urls {related_urls}")
        try:
            today = datetime.today().date()
            ioc_type = self._get_ioc_type(ioc)
            try:
                ioc_instance = IOC.objects.get(name=ioc)
            except IOC.DoesNotExist:
                self._check_if_allowed(ioc)
                ioc_instance = IOC(
                    name=ioc,
                    type=ioc_type,
                    days_seen=[today],
                )
                if related_urls:
                    ioc_instance.related_urls = related_urls
            else:
                ioc_instance.last_seen = datetime.utcnow()
                ioc_instance.times_seen += 1
                if today not in ioc_instance.days_seen:
                    ioc_instance.days_seen.append(today)
                    ioc_instance.number_of_days_seen += 1
                if related_urls:
                    for related_url in related_urls:
                        if related_url and related_url not in ioc_instance.related_urls:
                            ioc_instance.related_urls.append(related_url)

            if attack_type == SCANNER:
                ioc_instance.scanner = True
            if attack_type == PAYLOAD_REQUEST:
                ioc_instance.payload_request = True

            if log4j:
                ioc_instance.log4j = True

            if cowrie:
                ioc_instance.cowrie = True

            if ioc_instance:
                ioc_instance.save()

            # FEEDS - add general honeypot to list, if it is no already in it
            if general and general not in ioc_instance.general_honeypot.all():
                ioc_instance.general_honeypot.add(GeneralHoneypot.objects.get(name=general))

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
