# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging
from abc import ABCMeta, abstractmethod

from django.conf import settings
from elasticsearch_dsl import Q, Search


class Cronjob(metaclass=ABCMeta):
    class ElasticServerDownException(Exception):
        pass

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.elastic_client = settings.ELASTIC_CLIENT
        self.success = False

    def _healthcheck(self):
        if not self.elastic_client.ping():
            raise self.ElasticServerDownException("elastic server is not reachable, could be down")

    def _base_search(self, honeypot):
        """
        base method to create queries to Elastic
        :param honeypot: Honeypot instance
        :return: Search instance
        """
        search = Search(using=self.elastic_client, index="logstash-*")
        self.log.debug(f"minutes_back_to_lookup: {self.minutes_back_to_lookup}")
        gte_date = f"now-{self.minutes_back_to_lookup}m/m"
        # Some honeypots have different column for the time
        # like 'timestamp' others 'start_time','end_time'
        # This chooses the one that exists
        q = Q(
            "bool",
            should=[
                Q("range", timestamp={"gte": gte_date, "lte": "now/m"}),
                Q("range", end_time={"gte": gte_date, "lte": "now/m"}),
                Q("range", **{"@timestamp": {"gte": gte_date, "lte": "now/m"}}),
            ],
            minimum_should_match=1,
        )
        search = search.query(q)
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
