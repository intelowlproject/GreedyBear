from datetime import datetime, timedelta

from greedybear.cronjobs.base import Cronjob
from greedybear.models import IOC, CommandSequence, CowrieSession
from greedybear.settings import COMMAND_SEQUENCE_RETENTION, COWRIE_SESSION_RETENTION, IOC_RETENTION


class CleanUp(Cronjob):
    """
    A scheduled job that performs database cleanup operations by removing outdated records.

    This job handles deletion of old IOCs, CowrieSessions, and CommandSequences based on
    retention periods defined in the application settings. All deletion operations are logged
    with counts of removed objects.
    """

    def run(self) -> None:
        """
        Execute the database cleanup process.

        This method:
        1. Calculates expiration dates for different record types
        2. Deletes IOCs older than IOC_RETENTION days
        3. Deletes incomplete Cowrie sessions (those without start time)
        4. Deletes Cowrie sessions without login attempts older than 30 days
        5. Deletes all Cowrie sessions older than COWRIE_SESSION_RETENTION days
        6. Deletes all command sequences older than COMMAND_SEQUENCE_RETENTION days

        Each deletion operation is logged with the number of affected records.
        """
        ioc_expiration_date = datetime.utcnow() - timedelta(days=IOC_RETENTION)
        session_expiration_date = datetime.utcnow() - timedelta(days=30)
        session_with_login_expiration_date = datetime.utcnow() - timedelta(days=COWRIE_SESSION_RETENTION)
        command_expiration_date = datetime.utcnow() - timedelta(days=COMMAND_SEQUENCE_RETENTION)

        self.log.info(f"deleting all IOC older then {IOC_RETENTION} days")
        n = IOC.objects.filter(last_seen__lte=ioc_expiration_date).delete()[0]
        self.log.info(f"{n} objects deleted")

        self.log.info("deleting all Cowrie sessions without start time (incomplete extractions)")
        n = CowrieSession.objects.filter(start_time__isnull=True).delete()[0]
        self.log.info(f"{n} objects deleted")

        self.log.info("deleting all Cowrie sessions without login attempts older then 30 days")
        n = CowrieSession.objects.filter(start_time__lte=session_expiration_date, login_attempt=False).delete()[0]
        self.log.info(f"{n} objects deleted")

        self.log.info(f"deleting all Cowrie sessions older then {COWRIE_SESSION_RETENTION} days")
        n = CowrieSession.objects.filter(start_time__lte=session_with_login_expiration_date).delete()[0]
        self.log.info(f"{n} objects deleted")

        self.log.info(f"deleting all command sequences older then {COMMAND_SEQUENCE_RETENTION} days")
        n = CommandSequence.objects.filter(last_seen__lte=command_expiration_date).delete()[0]
        self.log.info(f"{n} objects deleted")
