# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging
from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta

from django.conf import settings
from elasticsearch_dsl import Q, Search
from greedybear.settings import EXTRACTION_INTERVAL, LEGACY_EXTRACTION


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
        if LEGACY_EXTRACTION:
            gte_date = f"now-{self.minutes_back_to_lookup}m/m"
            # Some honeypots had different column for the time
            # like 'timestamp' others 'start_time','end_time'
            # on older TPot versions.
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
        else:
            window_start, window_end = get_time_window(EXTRACTION_INTERVAL, self.minutes_back_to_lookup - EXTRACTION_INTERVAL)
            self.log.debug(f"time window: {window_start} - {window_end}")
            q = Q("range", **{"@timestamp": {"gte": window_start, "lt": window_end}})
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


def get_time_window(window_minutes: int, additonal_lookback: int = 0) -> tuple[int]:
    """
    Calculates the last completed time window of a specified length.

    Args:
        window_minutes (int): Length of the time window in minutes

    Returns:
        tuple: A tuple containing the start and end timestamps of the time window

    Raises:
        ValueError: If window_minutes is less than or equal to 0
    """
    if window_minutes < 1:
        raise ValueError("Window size must be at least 1 minute. ")

    now = datetime.now()
    rounded_minute = (now.minute // window_minutes) * window_minutes
    window_end = now.replace(minute=rounded_minute, second=0, microsecond=0)
    window_start = window_end - timedelta(minutes=window_minutes) - timedelta(minutes=additonal_lookback)
    return (window_start, window_end)
