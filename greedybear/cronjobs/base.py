# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging
from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta

from django.conf import settings
from elasticsearch8.dsl import Q, Search
from greedybear.settings import EXTRACTION_INTERVAL, LEGACY_EXTRACTION


class Cronjob(metaclass=ABCMeta):
    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.success = False

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


class ElasticJob(Cronjob):
    class ElasticServerDownException(Exception):
        pass

    def __init__(self):
        super().__init__()
        self.elastic_client = settings.ELASTIC_CLIENT

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
            window_start, window_end = get_time_window(datetime.now(), self.minutes_back_to_lookup)
            self.log.debug(f"time window: {window_start} - {window_end}")
            q = Q("range", **{"@timestamp": {"gte": window_start, "lt": window_end}})
        search = search.query(q)
        search = search.filter("term", **{"type.keyword": honeypot.name})
        return search

    @property
    @abstractmethod
    def minutes_back_to_lookup(self):
        pass


def get_time_window(reference_time: datetime, lookback_minutes: int = EXTRACTION_INTERVAL) -> tuple[datetime, datetime]:
    """
    Calculates a time window that ends at the last completed extraction interval and looks back a specified number of minutes.

    Args:
        reference_time (datetime): Reference point in time
        lookback_minutes (int): Minutes to look back (default: EXTRACTION_INTERVAL)

    Returns:
        tuple: A tuple containing the start and end time of the time window as datetime objects

    Raises:
        ValueError: If lookback_minutes is less than EXTRACTION_INTERVAL
    """
    if lookback_minutes < EXTRACTION_INTERVAL:
        raise ValueError(f"Argument lookback_minutes size must be at least {EXTRACTION_INTERVAL} minutes.")

    rounded_minute = (reference_time.minute // EXTRACTION_INTERVAL) * EXTRACTION_INTERVAL
    window_end = reference_time.replace(minute=rounded_minute, second=0, microsecond=0)
    window_start = window_end - timedelta(minutes=lookback_minutes)
    return (window_start, window_end)
