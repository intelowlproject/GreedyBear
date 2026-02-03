import logging
from abc import ABCMeta, abstractmethod

from greedybear.cronjobs.extraction.ioc_processor import IocProcessor
from greedybear.cronjobs.repositories import IocRepository, SensorRepository


class BaseExtractionStrategy(metaclass=ABCMeta):
    """
    Abstract base class for T-Pot extraction strategies.

    Subclasses implement `extract_from_hits` to define honeypot-specific
    logic for processing log entries into IOC records.

    Attributes:
        honeypot: Name of the honeypot this strategy handles.
        ioc_repo: Repository for IOC data access.
        sensor_repo: Repository for sensor data access.
        log: Logger instance for this class.
        ioc_processor: Processor for creating and updating IOC records.
        ioc_records: List of IOC records extracted during processing.
    """

    def __init__(
        self,
        honeypot: str,
        ioc_repo: IocRepository,
        sensor_repo: SensorRepository,
    ):
        self.honeypot = honeypot
        self.ioc_repo = ioc_repo
        self.sensor_repo = sensor_repo

        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.ioc_processor = IocProcessor(self.ioc_repo, self.sensor_repo)
        self.ioc_records = []

    @abstractmethod
    def extract_from_hits(self, hits: list[dict]) -> None:
        """
        Extract IOC records from honeypot log hits.
        Subclasses must implement this method to define honeypot-specific
        extraction logic. Extracted records should be stored in `ioc_records`.

        Args:
            hits: List of Elasticsearch hit dictionaries to process.
        """
        pass
