import logging

from greedybear.consts import IP
from greedybear.cronjobs.extraction.utils import get_ioc_type
from greedybear.models import Sensor


class SensorRepository:
    """
    Repository for data access to the set of T-Pot sensors with in-memory caching.

    The cache is populated once from the database at initialization and updated
    on successful additions.
    """

    def __init__(self):
        """Initialize the repository and populate the cache from the database."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.cache = set()
        self._fill_cache()

    @property
    def sensors(self) -> set:
        """
        Get the set of known sensor IP addresses.

        Returns:
            Set of IP address strings for all known sensors.
        """
        return self.cache

    def add_sensor(self, ip: str, country_name: str = None) -> bool:
        """
        Add a new sensor IP address with optional country information.
        Validates that the IP is not already known and is a valid IP address
        before writing it to the database and updating the cache.

        Args:
            ip: IP address string to add.
            country_name: Optional sensor country name.

        Returns:
            True if the sensor was added, False if already known or invalid.
        """
        if ip in self.cache:
            return False
        if get_ioc_type(ip) != IP:
            self.log.debug(f"{ip} is not an IP address - won't add as a sensor")
            return False
        sensor = Sensor(address=ip, sensor_country_name=country_name or "")
        sensor.save()
        self.cache.add(ip)
        self.log.info(f"added sensor {ip} to the database")
        return True

    def _fill_cache(self) -> None:
        """Load sensor addresses from the database into the cache."""
        self.log.debug("populating sensor cache")
        self.cache = {s.address for s in Sensor.objects.all()}
