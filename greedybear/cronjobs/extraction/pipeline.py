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
        1. Stream hits grouped by honeypot type from Elasticsearch
        2. Extract IOCs immediately for each honeypot type (no intermediate storage)
        3. Update scores for all extracted IOCs

        Returns:
            Number of IOC records processed.
        """
        # 1. Stream hits grouped by honeypot type and process immediately
        self.log.info("Streaming honeypot hits from Elasticsearch")
        
        ioc_records = []
        
        # Process each honeypot type as it's yielded - no intermediate storage
        for honeypot, hits in self.elastic_repo.group_hits_by_honeypot(self._minutes_back_to_lookup):
            # Extract sensor information for this batch
            for hit in hits:
                if "t-pot_ip_ext" in hit:
                    self.sensor_repo.add_sensor(hit["t-pot_ip_ext"])
            
            # 2. Extract IOCs immediately for this honeypot type
            if not self.ioc_repo.is_ready_for_extraction(honeypot):
                self.log.info(f"Skipping honeypot {honeypot}")
                continue

            self.log.info(f"Extracting hits from honeypot {honeypot}")
            strategy = factory.get_strategy(honeypot)
            try:
                # Process these hits immediately and discard them
                extracted = strategy.extract_all(hits)
                ioc_records.extend(extracted)
                self.log.info(f"Extracted {len(extracted)} IOCs from {honeypot}")
            except Exception as e:
                self.log.error(f"Failed extracting from {honeypot}: {e}")

        # 3. Update scores
        self.log.info("Updating scores")
        if ioc_records:
            UpdateScores().score_only(ioc_records)

        return len(ioc_records)
