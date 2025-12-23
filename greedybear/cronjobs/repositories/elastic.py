import logging
from datetime import datetime, timedelta

from django.conf import settings
from elasticsearch8.dsl import Q, Search
from greedybear.consts import REQUIRED_FIELDS
from greedybear.settings import EXTRACTION_INTERVAL, LEGACY_EXTRACTION


class ElasticRepository:
    """
    Repository for querying honeypot log data from a T-Pot Elasticsearch instance.

    Provides a cached search interface for retrieving log entries within
    a specified time window from logstash indices.

    This class is intended for individual extraction runs, so the cache never clears.
    """

    class ElasticServerDownException(Exception):
        """Raised when the Elasticsearch server is unreachable."""

        pass

    def __init__(self):
        """Initialize the repository with an Elasticsearch client and empty cache."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.elastic_client = settings.ELASTIC_CLIENT
        self.search_cache = dict()

    def search(self, minutes_back_to_lookup: int):
        """
        Search for log entries within a specified time window.

        Returns cached results if available for the given lookback period.
        Uses legacy or modern query format based on LEGACY_EXTRACTION setting.

        Args:
            minutes_back_to_lookup: Number of minutes to look back from the current time.

        Returns:
            list: Log entries sorted by @timestamp, containing only REQUIRED_FIELDS.

        Raises:
            ElasticServerDownException: If Elasticsearch is unreachable.
        """
        if minutes_back_to_lookup in self.search_cache:
            self.log.debug("fetching elastic search result from cache")
            return self.search_cache[minutes_back_to_lookup]

        self._healthcheck()
        search = Search(using=self.elastic_client, index="logstash-*")
        self.log.debug(f"minutes_back_to_lookup: {minutes_back_to_lookup}")
        if LEGACY_EXTRACTION:
            self.log.debug("querying elastic using legacy method")
            gte_date = f"now-{minutes_back_to_lookup}m/m"
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
            q = self._standard_query(minutes_back_to_lookup)

        search = search.query(q)
        search.source(REQUIRED_FIELDS)
        result = list(search.scan())
        self.log.debug(f"found {len(result)} hits")

        result.sort(key=lambda hit: hit["@timestamp"])
        self.search_cache[minutes_back_to_lookup] = result
        return result

    def _standard_query(self, minutes_back_to_lookup: int) -> Q:
        """
        Builds an Elasticsearch query that filters documents based on their
        @timestamp field, searching backwards from the current time for the
        specified number of minutes.

        Args:
            minutes_back_to_lookup: Number of minutes to look back from the
                current time. Defines the size of the time window to search.

        Returns:
            Q: An elasticsearch-dsl Query object with a range filter on the
            @timestamp field. The range spans from (now - minutes_back_to_lookup)
            to now.
        """
        self.log.debug("querying elastic using standard method")
        window_start, window_end = get_time_window(datetime.now(), minutes_back_to_lookup)
        self.log.debug(f"time window: {window_start} - {window_end}")
        return Q("range", **{"@timestamp": {"gte": window_start, "lt": window_end}})

    def _healthcheck(self):
        """
        Verify Elasticsearch connectivity.

        Raises:
            ElasticServerDownException: If the server does not respond to ping.
        """
        self.log.debug("performing healthcheck")
        if not self.elastic_client.ping():
            raise self.ElasticServerDownException("elastic server is not reachable, could be down")
        self.log.debug("elastic server is reachable")


def get_time_window(reference_time: datetime, lookback_minutes: int, extraction_interval: int = EXTRACTION_INTERVAL) -> tuple[datetime, datetime]:
    """
    Calculates a time window that ends at the last completed extraction interval and looks back a specified number of minutes.

    Args:
        reference_time (datetime): Reference point in time
        lookback_minutes (int): Minutes to look back
        extraction_interval (int): Minutes between two subsequent extraction runs

    Returns:
        tuple: A tuple containing the start and end time of the time window as datetime objects

    Raises:
        ValueError: If lookback_minutes is less than extraction_interval
        ValueError: If extraction_interval is not a positive divisor of 60
    """
    if extraction_interval <= 0 or 60 % extraction_interval > 0:
        raise ValueError("Argument extraction_interval must be a positive divisor of 60.")

    if lookback_minutes < extraction_interval:
        raise ValueError(f"Argument lookback_minutes size must be at least {extraction_interval} minutes.")

    rounded_minute = (reference_time.minute // extraction_interval) * extraction_interval
    window_end = reference_time.replace(minute=rounded_minute, second=0, microsecond=0)
    window_start = window_end - timedelta(minutes=lookback_minutes)
    return (window_start, window_end)
