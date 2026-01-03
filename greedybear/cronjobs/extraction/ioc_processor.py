import logging

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.extraction.utils import is_whatsmyip_domain
from greedybear.cronjobs.repositories import IocRepository, SensorRepository
from greedybear.models import IOC, iocType


class IocProcessor:
    """
    Processor for creating and updating IOC records.

    Handles filtering, merging, and persistence of IOC data extracted
    from T-Pot. Uses injected repositories for data access.
    """

    def __init__(self, ioc_repo: IocRepository, sensor_repo: SensorRepository):
        """
        Initialize the processor with required repositories.

        Args:
            ioc_repo: Repository for IOC data access.
            sensor_repo: Repository for sensor data access.
        """
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.ioc_repo = ioc_repo
        self.sensor_repo = sensor_repo

    def add_ioc(self, ioc: IOC, attack_type: str, general_honeypot_name: str = None) -> IOC | None:
        """
        Process an IOC record.
        Filters out sensor IPs and whats-my-ip domains, then creates a new
        IOC record or updates an existing one. Associates the IOC with a
        general honeypot if specified.

        Args:
            ioc: IOC instance to process.
            attack_type: Type of attack (SCANNER or PAYLOAD_REQUEST).
            general_honeypot_name: Optional honeypot name to associate with the IOC.

        Returns:
            The persisted IOC record, or None if filtered out.
        """
        self.log.info(f"processing ioc {ioc} for attack_type {attack_type}")

        if ioc.name in self.sensor_repo.sensors:
            self.log.debug(f"not saved {ioc} because it is a sensor")
            return None

        if ioc.type == iocType.DOMAIN and is_whatsmyip_domain(ioc.name):
            self.log.debug(f"not saved {ioc} because it is a whats-my-ip domain")
            return None

        ioc_record = self.ioc_repo.get_ioc_by_name(ioc.name)
        if ioc_record is None:  # Create
            self.log.debug(f"{ioc} was not seen before - creating a new record")
            ioc_record = self.ioc_repo.save(ioc)
        else:  # Update
            self.log.debug(f"{ioc} is already known - updating record")
            ioc_record = self._merge_iocs(ioc_record, ioc)

        if general_honeypot_name is not None:
            ioc_record = self.ioc_repo.add_honeypot_to_ioc(general_honeypot_name, ioc_record)

        ioc_record = self._update_days_seen(ioc_record)
        ioc_record.scanner = ioc_record.scanner or (attack_type == SCANNER)
        ioc_record.payload_request = ioc_record.payload_request or (attack_type == PAYLOAD_REQUEST)

        self.ioc_repo.save(ioc_record)
        return ioc_record

    def _merge_iocs(self, existing: IOC, new: IOC) -> IOC:
        """
        Merge a new IOC's data into an existing record.
        Updates timestamps, increments counters, and combines list fields.

        Args:
            existing: The existing IOC record from the database.
            new: The new IOC data to merge in.

        Returns:
            The updated existing IOC record.
        """
        existing.last_seen = new.last_seen
        existing.attack_count += 1
        existing.interaction_count += new.interaction_count
        existing.related_urls = sorted(set(existing.related_urls + new.related_urls))
        existing.destination_ports = sorted(set(existing.destination_ports + new.destination_ports))
        existing.ip_reputation = new.ip_reputation
        existing.asn = new.asn
        existing.login_attempts += new.login_attempts
        return existing

    def _update_days_seen(self, ioc: IOC) -> IOC:
        """
        Update the days_seen list if the IOC was seen on a new day.
        Appends the current date to days_seen if it differs from the last
        recorded date, and updates the count accordingly.

        Args:
            ioc: The IOC record to update.

        Returns:
            The updated IOC record.
        """
        if len(ioc.days_seen) == 0 or ioc.days_seen[-1] != ioc.last_seen.date():
            ioc.days_seen.append(ioc.last_seen.date())
            ioc.number_of_days_seen = len(ioc.days_seen)
        return ioc
