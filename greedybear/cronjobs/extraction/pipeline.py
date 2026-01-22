import logging
from collections import defaultdict

from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory
from greedybear.cronjobs.repositories import (
    ElasticRepository,
    IocRepository,
    SensorRepository,
)
from greedybear.cronjobs.scoring.scoring_jobs import UpdateScores
from greedybear.settings import (
    EXTRACTION_INTERVAL,
    INITIAL_EXTRACTION_TIMESPAN,
    LEGACY_EXTRACTION,
)


class ExtractionPipeline:
    """
    Pipeline for extracting IOCs from T-Pot's honeypot logs.
    Orchestrates the extraction workflow.
    """

    def __init__(self):
        """Initialize the pipeline with required repositories."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
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
        # 1. Search + group by honeypot (now done in ES)
        self.log.info("Getting honeypot hits from Elasticsearch (via aggregations)")
        hits_by_honeypot_dict = self.elastic_repo.group_hits_by_honeypot(self._minutes_back_to_lookup)

        # Convert to defaultdict(list) to keep type expectations in the rest of the code
        hits_by_honeypot = defaultdict(list)
        for honeypot, hits in hits_by_honeypot_dict.items():
            # Extract sensor information here to preserve previous behaviour
            for hit in hits:
                if "t-pot_ip_ext" in hit:
                    self.sensor_repo.add_sensor(hit["t-pot_ip_ext"])
                hits_by_honeypot[honeypot].append(hit)

        # 3. Extract using strategies
        ioc_records = []
        factory = ExtractionStrategyFactory(self.ioc_repo, self.sensor_repo)
        for honeypot, hits in sorted(hits_by_honeypot.items()):
            if not self.ioc_repo.is_ready_for_extraction(honeypot):
                self.log.info(f"Skipping honeypot {honeypot}")
                continue
            self.log.info(f"Extracting hits from honeypot {honeypot}")
            strategy = factory.get_strategy(honeypot)
            try:
                strategy.extract_from_hits(hits)
                ioc_records += strategy.ioc_records
            except Exception as exc:
                self.log.error(f"Extraction failed for honeypot {honeypot}: {exc}")

        # 4. Update scores
        self.log.info("Updating scores")
        if ioc_records:
            UpdateScores().score_only(ioc_records)
        return len(ioc_records)
