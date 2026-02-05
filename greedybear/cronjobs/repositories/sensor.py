import logging

from greedybear.consts import IP
from greedybear.cronjobs.extraction.utils import get_ioc_type
from greedybear.models import Sensor


class SensorRepository:
    """
    Repository for data access to the set of T-Pot sensors with in-memory caching.

    The cache is populated once from the database at initialization and updated
    on successful additions. Stores Sensor objects for efficient retrieval.
    """

    def __init__(self):
        """Initialize the repository and populate the cache from the database."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.cache: dict[str, Sensor] = {}
        self._fill_cache()

    def get_or_create_sensor(self, ip: str) -> Sensor | None:
        """
        Get an existing sensor or create a new one.
        Validates that the IP is a valid IP address before writing it to the
        database and updating the cache.

        Args:
            ip: IP address string.

        Returns:
            Sensor object if valid, None if invalid IP format.
        """
        if ip in self.cache:
            return self.cache[ip]
        if get_ioc_type(ip) != IP:
            self.log.debug(f"{ip} is not an IP address - won't add as a sensor")
            return None
        sensor = Sensor(address=ip)
        sensor.save()
        self.cache[ip] = sensor
        self.log.info(f"added sensor {ip} to the database")
        return sensor

    def _fill_cache(self) -> None:
        """Load sensor objects from the database into the cache."""
        self.log.debug("populating sensor cache")
        self.cache = {s.address: s for s in Sensor.objects.all()}
