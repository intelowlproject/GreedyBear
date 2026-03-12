import logging

from greedybear.models import IOC, CommandSequence, CowrieSession, CowrieFileTransfer


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
    
    def get_or_create_file_transfer(self, session: CowrieSession, shasum: str, url: str, outfile: str, timestamp) -> CowrieFileTransfer:
        """
        Create or update a file transfer associated with a Cowrie session.

        If a transfer with the same session and shasum already exists,
        its timestamp will be updated to the latest event time.
        Otherwise, a new CowrieFileTransfer record will be created.

        Args:
            session: The CowrieSession instance the file transfer belongs to.
            shasum: SHA256 checksum of the transferred file.
            url: Source URL of the file if downloaded by the attacker.
            outfile: File path recorded by Cowrie when storing the transferred file on the honeypot.
            timestamp: Timestamp of the transfer event.

        Returns:
            The created or updated CowrieFileTransfer instance.
        """
        transfer, created = CowrieFileTransfer.objects.get_or_create(
            session=session,
            shasum=shasum,
            defaults={
                "url": url,
                "outfile": outfile,
                "timestamp": timestamp,
            },
        )
        if not created:
            transfer.timestamp = timestamp
            transfer.save()
        return transfer

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

    def add_credential(self, session: CowrieSession, username: str, password: str) -> None:
        """
        Get or create a Credential and associate it with the session.

        Args:
            session: The CowrieSession instance to associate the credential with.
            username: The credential username.
            password: The credential password.
        """
        from greedybear.models import Credential

        credential, _ = Credential.objects.get_or_create(username=username, password=password)
        session.credentials.add(credential)
