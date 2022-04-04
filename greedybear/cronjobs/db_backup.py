import os
from datetime import datetime

from cStringIO import StringIO
from django.core import management

from greedybear import settings
from greedybear.apps import GreedyBearConfig
from greedybear.cronjobs.base import Cronjob


class DbBackup(Cronjob):
    def __init__(self):
        super().__init__()
        self.interval = settings.DB_BACKUP_FREQUENCY
        self.location = settings.DB_BACKUP_LOCATION
        self.max_backups = settings.DB_BACKUP_MAX_BACKUPS

    @property
    def minutes_back_to_lookup(self):
        return self.interval

    def _remove_oldest_backup(self):
        # removes files older than self.max_backups
        self.log.info("[db_backup] checking for older backups...")
        files = os.listdir(self.location)
        if len(files) >= self.max_backups:
            self.log.info("[db_backup] removing old backups...")
            oldest_file = min(files, key=os.path.getctime)
            os.remove(os.path.abspath(oldest_file))

    def run(self):
        self.log.info("[db_backup] starting cron job...")
        self._remove_oldest_backup()
        app_name = GreedyBearConfig.name
        backup_file = (
            f"{self.location}/db_backup_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        )
        # Init a new buffer
        buf = StringIO()
        # Call command with and pipe stdout to buffer
        management.call_command("dbbackup", app_name, stdout=buf)
        buf.seek(0)
        # Write buffer to file
        self.log.info(f"[db_backup] writing backup db to {backup_file}...")
        with open(backup_file, "w", "utf-8") as dump:
            dump.write(buf.read())
