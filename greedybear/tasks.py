# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from __future__ import absolute_import, unicode_literals

from celery import shared_task


@shared_task()
def extract_log4pot():
    from greedybear.cronjobs.log4pot import ExtractLog4Pot

    ExtractLog4Pot().execute()


@shared_task()
def extract_cowrie():
    from greedybear.cronjobs.cowrie import ExtractCowrie

    ExtractCowrie().execute()


# FEEDS


@shared_task()
def extract_general():
    from greedybear.cronjobs.general import ExtractAllGenerals

    ExtractAllGenerals().execute()


@shared_task()
def extract_sensors():
    from greedybear.cronjobs.sensors import ExtractSensors

    ExtractSensors().execute()


@shared_task()
def monitor_honeypots():
    from greedybear.cronjobs.monitor_honeypots import MonitorHoneypots

    MonitorHoneypots().execute()


@shared_task()
def monitor_logs():
    from greedybear.cronjobs.monitor_logs import MonitorLogs

    MonitorLogs().execute()
