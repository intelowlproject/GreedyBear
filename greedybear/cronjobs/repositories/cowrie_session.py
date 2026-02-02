import logging

from greedybear.models import IOC, CommandSequence, CowrieCredential, CowrieSession


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
        except ValueError as e:
            raise ValueError(f"session_id must be a valid hex string, got: {session_id!r}") from e
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

    def save_credential(self, session: CowrieSession, username: str, password: str) -> bool:
        """
        Save a single credential for a session using get_or_create to avoid duplicates.

        Args:
            session: The CowrieSession instance this credential belongs to.
            username: Username to save.
            password: Password to save.

        Returns:
            True if a new credential was created, False if it already existed.
        """
        _, created = CowrieCredential.objects.get_or_create(
            session=session,
            username=username,
            password=password,
        )
        return created

    def save_credentials(self, session: CowrieSession, credentials_list: list[tuple[str, str]]) -> int:
        """
        Save credentials for a session using get_or_create to avoid duplicates.

        Args:
            session: The CowrieSession instance these credentials belong to.
            credentials_list: List of (username, password) tuples to save.

        Returns:
            Number of new credential records created.
        """
        created_count = 0
        for username, password in credentials_list:
            _, created = CowrieCredential.objects.get_or_create(
                session=session,
                username=username,
                password=password,
            )
            if created:
                created_count += 1
        return created_count

    def delete_old_command_sequences(self, cutoff_date) -> int:
        """
        Delete command sequences older than the specified cutoff date.

        Args:
            cutoff_date: DateTime threshold - sequences with last_seen before this will be deleted.

        Returns:
            Number of CommandSequence objects deleted.
        """
        deleted_count, _ = CommandSequence.objects.filter(last_seen__lte=cutoff_date).delete()
        return deleted_count

    def delete_incomplete_sessions(self) -> int:
        """
        Delete Cowrie sessions without a start time (incomplete extractions).

        Returns:
            Number of sessions deleted.
        """
        deleted_count, _ = CowrieSession.objects.filter(start_time__isnull=True).delete()
        return deleted_count

    def delete_sessions_without_login(self, cutoff_date) -> int:
        """
        Delete Cowrie sessions without login attempts older than the cutoff date.

        Args:
            cutoff_date: DateTime threshold.

        Returns:
            Number of sessions deleted.
        """
        deleted_count, _ = CowrieSession.objects.filter(start_time__lte=cutoff_date, login_attempt=False).delete()
        return deleted_count

    def delete_sessions_without_commands(self, cutoff_date) -> int:
        """
        Delete Cowrie sessions without associated commands older than the cutoff date.

        Args:
            cutoff_date: DateTime threshold.

        Returns:
            Number of sessions deleted.
        """
        deleted_count, _ = CowrieSession.objects.filter(start_time__lte=cutoff_date, commands__isnull=True).delete()
        return deleted_count
