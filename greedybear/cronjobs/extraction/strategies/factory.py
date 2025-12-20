from greedybear.cronjobs.extraction.strategies import BaseExtractionStrategy, CowrieExtractionStrategy, GenericExtractionStrategy, Log4potExtractionStrategy
from greedybear.cronjobs.repositories import IocRepository, SensorRepository


class ExtractionStrategyFactory:
    """
    Factory for creating honeypot extraction strategies.
    Returns specialized strategies for special honeypots,
    and a generic strategy for all others.
    """

    def __init__(self, ioc_repo: IocRepository, sensor_repo: SensorRepository):
        """
        Initialize the factory with required repositories.

        Args:
            ioc_repo: Repository for IOC data access.
            sensor_repo: Repository for sensor data access.
        """
        self.ioc_repo = ioc_repo
        self.sensor_repo = sensor_repo
        self._strategies = {
            "Cowrie": lambda: CowrieExtractionStrategy("Cowrie", self.ioc_repo, self.sensor_repo),
            "Log4pot": lambda: Log4potExtractionStrategy("Log4pot", self.ioc_repo, self.sensor_repo),
        }

    def get_strategy(self, honeypot: str) -> BaseExtractionStrategy:
        """
        Get the appropriate extraction strategy for a honeypot.

        Args:
            honeypot: Name of the honeypot.

        Returns:
            A fitting strategy.
        """
        if honeypot in self._strategies:
            return self._strategies[honeypot]()
        return GenericExtractionStrategy(honeypot, self.ioc_repo, self.sensor_repo)
