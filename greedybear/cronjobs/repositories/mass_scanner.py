import logging

from greedybear.models import MassScanner


class MassScannerRepository:
    """
    Repository for data access to mass scanner entries.
    """

    def __init__(self):
        """Initialize the repository."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_or_create(self, ip_address: str, reason: str = "") -> tuple[MassScanner, bool]:
        """
        Get an existing mass scanner entry or create a new one.

        Args:
            ip_address: IP address of the scanner.
            reason: Optional reason/description for why it's flagged.

        Returns:
            Tuple of (MassScanner object, created_flag) where created_flag is True if new.
        """
        scanner, created = MassScanner.objects.get_or_create(ip_address=ip_address, defaults={"reason": reason})
        return scanner, created
