from collections import defaultdict

from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory
from greedybear.cronjobs.repositories import ElasticRepository, IocRepository, SensorRepository
from greedybear.cronjobs.scoring.scoring_jobs import UpdateScores
from greedybear.settings import EXTRACTION_INTERVAL, INITIAL_EXTRACTION_TIMESPAN, LEGACY_EXTRACTION


class ExtractionPipeline:
    """
    Pipeline for extracting IOCs from T-Pot's honeypot logs.
    Orchestrates the extraction workflow.
    """

    def __init__(self):
        """Initialize the pipeline with required repositories."""
        self.elastic_repo = ElasticRepository()
        self.ioc_repo = IocRepository()
        self.sensor_repo = SensorRepository()

    @property
    def _minutes_back_to_lookup(self) -> int:
        """
        Calculate the time window size for Elasticsearch queries.
        Returns a larger window on first run to backfill historical data,
        otherwise uses the configured extraction interval.

        Returns:
            Number of minutes to look back in the search query.
        """
        if self.ioc_repo.is_empty():
            return INITIAL_EXTRACTION_TIMESPAN
        return 11 if LEGACY_EXTRACTION else EXTRACTION_INTERVAL

    def execute(self) -> int:
        """
        Execute the extraction pipeline.

        Performs the following steps:
        1. Search Elasticsearch for honeypot log entries
        2. Group hits by honeypot type and extract sensors
        3. Apply honeypot-specific extraction strategies
        4. Update IOC scores

        Returns:
            Number of IOC records processed.
        """
        # 1. Search
        search_result = self.elastic_repo.search(self._minutes_back_to_lookup)
        hits_by_honeypot = defaultdict(list)

        # 2. Group by honeypot
        for hit in search_result:
            # skip hits with non-existing or empty sources
            if "src_ip" not in hit or not hit["src_ip"].strip():
                continue
            # skip hits with non-existing or empty types (=honeypots)
            if "type" not in hit or not hit["type"].strip():
                continue
            # extract sensor
            if "t-pot_ip_ext" in hit:
                self.sensor_repo.add_sensor(hit["t-pot_ip_ext"])
            hits_by_honeypot[hit["type"]].append(hit.to_dict())

        # 3. Extract using strategies
        ioc_records = []
        factory = ExtractionStrategyFactory(self.ioc_repo, self.sensor_repo)
        for honeypot, hits in sorted(hits_by_honeypot.items()):
            if not self.ioc_repo.is_ready_for_extraction(honeypot):
                continue
            strategy = factory.get_strategy(honeypot)
            strategy.extract_from_hits(hits)
            ioc_records += strategy.ioc_records

        # 4. Update scores
        if ioc_records:
            UpdateScores().score_only(ioc_records)
        return len(ioc_records)
