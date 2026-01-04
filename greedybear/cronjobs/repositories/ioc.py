import logging

from greedybear.models import IOC, GeneralHoneypot


class IocRepository:
    """
    Repository for IOC and honeypot data access with honeypot caching.

    Maintains a cache of existing honeypot names, populated at initialization
    and updated when new honeypots are created.
    """

    SPECIAL_HONEYPOTS = frozenset({"Cowrie", "Log4pot"})

    def __init__(self):
        """Initialize the repository and populate the honeypot cache from the database."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._honeypot_cache = {hp.name: hp.active for hp in GeneralHoneypot.objects.all()}
        self._honeypot_cache.update(dict.fromkeys(self.SPECIAL_HONEYPOTS, True))

    def add_honeypot_to_ioc(self, honeypot_name: str, ioc: IOC) -> IOC:
        """
        Associate a honeypot with an IOC.

        Args:
            honeypot_name: Name of the honeypot to associate.
            ioc: IOC instance to add the honeypot to.

        Returns:
            The updated IOC instance.
        """
        honeypot_set = {hp.name for hp in ioc.general_honeypot.all()}
        if honeypot_name not in honeypot_set:
            self.log.debug(f"adding honeypot {honeypot_name} to IoC {ioc}")
            honeypot = self.get_hp_by_name(honeypot_name)
            ioc.general_honeypot.add(honeypot)
        return ioc

    def create_honeypot(self, honeypot_name: str) -> GeneralHoneypot:
        """
        Create a new honeypot and save it to the database.

        Args:
            honeypot_name: Name for the new honeypot.

        Returns:
            The newly created GeneralHoneypot instance.
        """
        self.log.debug(f"creating honeypot {honeypot_name}")
        honeypot = GeneralHoneypot(name=honeypot_name, active=True)
        honeypot.save()
        self._honeypot_cache[honeypot_name] = True
        return honeypot

    def get_active_honeypots(self) -> list[GeneralHoneypot]:
        """
        Retrieve a list of all active honeypots.

        Returns:
            A list of all active honeypots in the database.
        """
        return list(GeneralHoneypot.objects.filter(active=True))

    def get_ioc_by_name(self, name: str) -> IOC | None:
        """
        Retrieve an IOC by its name.

        Args:
            name: The IOC name to look up.

        Returns:
            The matching IOC, or None if not found.
        """
        try:
            return IOC.objects.get(name=name)
        except IOC.DoesNotExist:
            return None

    def get_hp_by_name(self, name: str) -> GeneralHoneypot | None:
        """
        Retrieve a honeypot by its name.

        Args:
            name: The honeypot name to look up.

        Returns:
            The matching GeneralHoneypot, or None if not found.
        """
        try:
            return GeneralHoneypot.objects.get(name=name)
        except GeneralHoneypot.DoesNotExist:
            return None

    def is_empty(self) -> bool:
        """
        Check if the database holds any IOC records.

        Returns:
            True if no IOCs exist, False otherwise.
        """
        return not IOC.objects.exists()

    def is_enabled(self, honeypot_name: str) -> bool:
        """
        Check if a honeypot is enabled.
        Special honeypots (Cowrie, Log4pot) are always enabled.
        General honeypots are enabled based on their active flag.

        Args:
            honeypot_name: Name of the honeypot to check.

        Returns:
            True if the honeypot is enabled, False otherwise.
        """
        return self._honeypot_cache.get(honeypot_name, False)

    def is_ready_for_extraction(self, honeypot_name: str) -> bool:
        """
        Check if a honeypot is ready for data extraction.
        Creates the honeypot if it doesn't exist, then checks if it's enabled.

        Args:
            honeypot_name: Name of the honeypot to check.

        Returns:
            True if the honeypot exists and is enabled, False otherwise.
        """
        if honeypot_name not in self._honeypot_cache:
            self.create_honeypot(honeypot_name)
        return self.is_enabled(honeypot_name)

    def save(self, ioc: IOC) -> IOC:
        """
        Saves an IOC to the database.

        Args:
            ioc: The IOC instance to save.

        Returns:
            The saved IOC instance.
        """
        ioc.save()
        return ioc
