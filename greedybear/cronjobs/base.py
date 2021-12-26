import logging
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address

from django.conf import settings
from elasticsearch_dsl import Search

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.sensors import ExtractSensors
from greedybear.models import IOC, Sensors


@dataclass
class Honeypot:
    name: str
    description: str = ""


class ExtractDataFromElastic(metaclass=ABCMeta):
    class ElasticServerDownException(Exception):
        pass

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.elastic_client = settings.ELASTIC_CLIENT
        self.success = False

    def _healthcheck(self):
        if not self.elastic_client.ping():
            raise self.ElasticServerDownException(
                "elastic server is not reachable, could be down"
            )

    def _base_search(self, honeypot):
        """
        base method to create queries to Elastic
        :param honeypot: Honeypot instance
        :return: Search instance
        """
        search = Search(using=self.elastic_client, index="logstash-*")
        self.log.debug(f"minutes_back_to_lookup: {self.minutes_back_to_lookup}")
        gte_date = f"now-{self.minutes_back_to_lookup}m/m"
        search = search.filter(
            "range", **{"timestamp": {"gte": gte_date, "lte": "now/m"}}
        )
        search = search.filter("term", **{"type.keyword": honeypot.name})
        return search

    @property
    @abstractmethod
    def minutes_back_to_lookup(self):
        pass

    @abstractmethod
    def run(self):
        pass

    def execute(self):
        try:
            self.log.info("Starting execution")
            self.run()
        except Exception as e:
            self.log.exception(e)
        else:
            self.success = True
        finally:
            self.log.info("Finished execution")


class ExtractAttacks(ExtractDataFromElastic, metaclass=ABCMeta):
    class IOCWhitelist(Exception):
        pass

    def __init__(self):
        super().__init__()
        self.first_time_run = False

    @property
    def minutes_back_to_lookup(self):
        if self.first_time_run:
            minutes = 60 * 24 * 3  # 3 days
        else:
            minutes = 11
        return minutes

    def _add_ioc(self, ioc, attack_type, related_urls=None, log4j=False, cowrie=False):
        self.log.info(
            f"saving ioc {ioc} for attack_type {attack_type} and related_urls {related_urls}"
        )
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

    def _check_first_time_run(self, honeypot_flag):
        all_ioc = IOC.objects.all()
        if not all_ioc:
            # plus, we extract the sensors addresses so we can whitelist them
            ExtractSensors().execute()
            self.first_time_run = True
        else:
            # if this is not the overall first time, it could that honeypot first time
            honeypot_ioc = IOC.objects.filter(**{f"{honeypot_flag}": True})
            if not honeypot_ioc:
                # first time we execute this project.
                # So we increment the time range to get the data from the last 3 days
                self.first_time_run = True
