# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from datetime import datetime, timedelta
from os.path import getmtime

from greedybear.cronjobs.base import Cronjob
from greedybear.slack import send_message


class MonitorLogs(Cronjob):
    def __init__(self):
        super(MonitorLogs, self).__init__()
        self.logs_to_monitor = ["greedybear", "api", "django", "celery"]
        self.log_directory = "/var/log/greedybear/django/"

    @property
    def minutes_back_to_lookup(self):
        return 61

    def run(self):
        for log_to_monitor in self.logs_to_monitor:
            log_file = log_to_monitor + "_errors.log"
            self.log.info(
                f"checking if the log {log_file} was populated in the last hour"
            )
            last_modification_time = getmtime(self.log_directory + log_file)
            last_modification_datetime = datetime.fromtimestamp(last_modification_time)
            one_hour_ago = datetime.today() - timedelta(
                minutes=self.minutes_back_to_lookup
            )
            self.log.info(
                f"modification time {last_modification_time}"
                f" ({last_modification_datetime}) for {log_file}."
                f" Checking if it is greater than {one_hour_ago}"
            )
            if last_modification_datetime > one_hour_ago:
                message = f"found errors in log file {log_file}"
                self.log.info(message)
                send_message(message)
