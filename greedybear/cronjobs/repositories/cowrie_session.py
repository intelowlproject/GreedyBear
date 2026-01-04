import logging

from greedybear.models import IOC, CommandSequence, CowrieSession


class CowrieSessionRepository:
    """
    Repository for data access to Cowrie sessions and command sequences.
    """

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_or_create_session(self, session_id: str, source: IOC) -> CowrieSession:
        """
        Retrieve an existing session or create a new one.

        Args:
            session_id: Cowrie session ID as a hexadecimal string.
            source: IOC instance to associate with a new session.

        Returns:
            The existing or newly created CowrieSession.

        Raises:
            ValueError: If session_id is not a valid hexadecimal string.
        """
        try:
            pk = int(session_id, 16)
        except ValueError:
            raise ValueError(f"session_id must be a valid hex string, got: {session_id!r}")
        record, created = CowrieSession.objects.get_or_create(session_id=pk, defaults={"source": source})
        self.log.debug(f"created new session {session_id}" if created else f"{session_id} already exists")
        return record

    def get_command_sequence_by_hash(self, commands_hash: str) -> CommandSequence | None:
        """
        Retrieve a command sequence by its hash.

        Args:
            commands_hash: SHA256 hash identifying the command sequence.

        Returns:
            The matching CommandSequence, or None if not found.
        """
        try:
            return CommandSequence.objects.get(commands_hash=commands_hash)
        except CommandSequence.DoesNotExist:
            return None

    def save_session(self, session: CowrieSession) -> CowrieSession:
        """
        Persist a CowrieSession to the database.

        Args:
            session: The CowrieSession instance to save.

        Returns:
            The saved CowrieSession instance.
        """
        session.save()
        return session

    def save_command_sequence(self, cmd: CommandSequence) -> CommandSequence:
        """
        Persist a CommandSequence to the database.

        Args:
            cmd: The CommandSequence instance to save.

        Returns:
            The saved CommandSequence instance.
        """
        cmd.save()
        return cmd
