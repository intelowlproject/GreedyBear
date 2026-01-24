import logging
from datetime import datetime, timedelta

from django.conf import settings
from elasticsearch import exceptions as es_exceptions
from elasticsearch.dsl import Q, Search

from greedybear.consts import REQUIRED_FIELDS
from greedybear.settings import EXTRACTION_INTERVAL, LEGACY_EXTRACTION


class ElasticRepository:
    """
    Repository for querying honeypot log data from a T-Pot Elasticsearch instance.

    Provides a cached search interface for retrieving log entries within
    a specified time window from logstash indices.

    This class is intended for individual extraction runs, so the cache never clears.
    """

    class ElasticServerDownError(Exception):
        """Raised when the Elasticsearch server is unreachable."""

        pass

    def __init__(self):
        """Initialize the repository with an Elasticsearch client and empty cache."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.elastic_client = settings.ELASTIC_CLIENT
        self.search_cache = {}

    def has_honeypot_been_hit(self, minutes_back_to_lookup: int, honeypot_name: str) -> bool:
        """
        Check if a specific honeypot has been hit within a given time window.

        Args:
            minutes_back_to_lookup: Number of minutes to look back from the current
                time when searching for honeypot hits.
            honeypot_name: The name/type of the honeypot to check for hits.

        Returns:
            True if at least one hit was recorded for the specified honeypot within
            the time window, False otherwise.
        """
        search = Search(using=self.elastic_client, index="logstash-*")
        q = self._standard_query(minutes_back_to_lookup)
        search = search.query(q)
        search = search.filter("term", **{"type.keyword": honeypot_name})
        return search.count() > 0

    def search(self, minutes_back_to_lookup: int) -> list:
        """
        Search for log entries within a specified time window.

        Returns cached results if available for the given lookback period.
        Uses legacy or modern query format based on LEGACY_EXTRACTION setting.

        Args:
            minutes_back_to_lookup: Number of minutes to look back from the current time.

        Returns:
            list: Log entries sorted by @timestamp, containing only REQUIRED_FIELDS.

        Raises:
            ElasticServerDownError: If Elasticsearch is unreachable.
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

    def group_hits_by_honeypot(self, minutes_back_to_lookup: int):
        """
        Stream hits grouped by honeypot type without loading all data into memory.

        This generator yields (honeypot_type, hits_list) tuples one at a time,
        ensuring that only one honeypot's data is in memory at any given moment.

        Uses a two-phase approach:
        1. Get list of honeypot types using a lightweight terms aggregation
        2. For each type, stream hits using scan() API

        Args:
            minutes_back_to_lookup: Number of minutes to look back from current time.

        Yields:
            tuple: (honeypot_type: str, hits: list[dict]) for each honeypot type.

        Raises:
            ElasticServerDownError: If Elasticsearch is unreachable.
        """
        self._healthcheck()
        self.log.debug("streaming hits by honeypot using Elasticsearch scan API")
        window_start, window_end = get_time_window(datetime.now(), minutes_back_to_lookup)
        self.log.debug(f"time window: {window_start} - {window_end}")

        # Phase 1: Get list of honeypot types (lightweight aggregation)
        query = {
            "range": {
                "@timestamp": {
                    "gte": window_start.isoformat(),
                    "lt": window_end.isoformat(),
                }
            }
        }

        agg_body = {
            "query": query,
            "size": 0,
            "aggs": {
                "honeypot_types": {
                    "terms": {
                        "field": "type.keyword",
                        "size": 100,  # Max distinct honeypot types
                    }
                }
            },
        }

        try:
            response = self.elastic_client.search(
                index="logstash-*",
                body=agg_body,
            )
        except es_exceptions.ConnectionError as exc:
            raise self.ElasticServerDownError(f"elastic server is not reachable, could be down: {exc}") from exc

        buckets = response.get("aggregations", {}).get("honeypot_types", {}).get("buckets", [])
        honeypot_types = [bucket["key"] for bucket in buckets if "key" in bucket]

        self.log.debug(f"found {len(honeypot_types)} honeypot types")

        # Phase 2: For each honeypot type, stream hits using scan()
        for honeypot_type in honeypot_types:
            self.log.debug(f"streaming hits for honeypot type: {honeypot_type}")

            # Create search filtered by honeypot type
            search = Search(using=self.elastic_client, index="logstash-*")
            q = Q("range", **{"@timestamp": {"gte": window_start, "lt": window_end}})
            search = search.query(q)
            search = search.filter("term", **{"type.keyword": honeypot_type})
            search = search.source(REQUIRED_FIELDS)
            search = search.sort("@timestamp")

            # Stream hits and collect them for this honeypot type
            hits = []
            for hit in search.scan():
                source = hit.to_dict()

                # Skip hits with invalid src_ip
                src_ip = source.get("src_ip", "")
                if not isinstance(src_ip, str) or not src_ip.strip():
                    continue

                # Skip hits with invalid type
                hit_type = source.get("type", "")
                if not isinstance(hit_type, str) or not hit_type.strip():
                    continue

                hits.append(source)

            if hits:
                self.log.debug(f"yielding {len(hits)} hits for {honeypot_type}")
                yield (honeypot_type, hits)

    def _standard_query(self, minutes_back_to_lookup: int) -> Q:
        """
        Builds an Elasticsearch query that filters documents based on their
        @timestamp field, searching backwards from the current time for the
        specified number of minutes.

        Args:
            minutes_back_to_lookup: Number of minutes to look back from the current time.
                Defines the size of the time window to search.

        Returns:
            Q: An elasticsearch-dsl Query object with a range filter on the @timestamp field.
                The range spans from (now - minutes_back_to_lookup) to now.
        """
        self.log.debug("querying elastic using standard method")
        window_start, window_end = get_time_window(datetime.now(), minutes_back_to_lookup)
        self.log.debug(f"time window: {window_start} - {window_end}")
        return Q("range", **{"@timestamp": {"gte": window_start, "lt": window_end}})

    def _healthcheck(self):
        """
        Verify Elasticsearch connectivity.

        Raises:
            ElasticServerDownError: If the server does not respond to ping.
        """
        self.log.debug("performing healthcheck")
        if not self.elastic_client.ping():
            raise self.ElasticServerDownError("elastic server is not reachable, could be down")
        self.log.debug("elastic server is reachable")


def get_time_window(
    reference_time: datetime,
    lookback_minutes: int,
    extraction_interval: int = EXTRACTION_INTERVAL,
) -> tuple[datetime, datetime]:
    """
    Calculates a time window that ends at the last completed extraction interval
    and looks back a specified number of minutes.

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
