import logging

from greedybear.models import MassScanner


class MassScannerRepository:
    """
    Repository for data access to mass scanner entries.
    """

    def __init__(self):
        """Initialize the repository."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_by_ip(self, ip_address: str) -> MassScanner | None:
        """
        Retrieve a mass scanner entry by IP address.

        Args:
            ip_address: IP address to look up.

        Returns:
            The matching MassScanner entry, or None if not found.
        """
        try:
            return MassScanner.objects.get(ip_address=ip_address)
        except MassScanner.DoesNotExist:
            return None

    def create(self, ip_address: str, reason: str = "") -> MassScanner:
        """
        Create a new mass scanner entry.

        Args:
            ip_address: IP address of the mass scanner.
            reason: Optional reason/comment about the scanner.

        Returns:
            The newly created MassScanner instance.
        """
        scanner = MassScanner(ip_address=ip_address, reason=reason)
        scanner.save()
        return scanner

    def save(self, scanner: MassScanner) -> MassScanner:
        """
        Save a MassScanner entry to the database.

        Args:
            scanner: MassScanner instance to save.

        Returns:
            The saved MassScanner instance.
        """
        scanner.save()
        return scanner

    def exists(self, ip_address: str) -> bool:
        """
        Check if a mass scanner entry exists for the given IP.

        Args:
            ip_address: IP address to check.

        Returns:
            True if the entry exists, False otherwise.
        """
        return MassScanner.objects.filter(ip_address=ip_address).exists()
