# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from __future__ import absolute_import, unicode_literals

import os
from datetime import timedelta

from celery import Celery
from celery.schedules import crontab
from celery.signals import setup_logging
from django.conf import settings
from kombu import Exchange, Queue

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "greedybear.settings")

app = Celery("greedybear")

app.autodiscover_tasks()

CELERY_QUEUES = ["default"]

app.conf.update(
    task_default_queue="default",
    task_queues=[
        Queue(
            key,
            Exchange(key),
            routing_key=key,
        )
        for key in CELERY_QUEUES
    ],
    task_time_limit=1800,
    broker_url=settings.BROKER_URL,
    accept_content=["application/json"],
    task_serializer="json",
    result_serializer="json",
    imports=("greedybear.tasks",),
    worker_redirect_stdouts=False,
    worker_hijack_root_logger=False,
    # these two are needed to enable priority and correct tasks execution
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    # this is to avoid RAM issues caused by long usage of this tool
    worker_max_tasks_per_child=200,
    # value is in kilobytes
    worker_max_memory_per_child=4000,
)


@setup_logging.connect
def setup_loggers(*args, **kwargs):
    from logging.config import dictConfig

    from django.conf import settings

    dictConfig(settings.LOGGING)


app.conf.beat_schedule = {
    # every 10 minutes
    "extract_log4pot": {
        "task": "greedybear.tasks.extract_log4pot",
        "schedule": crontab(minute="*/10"),
        "options": {"queue": "default"},
    },
    # every 10 minutes
    "extract_cowrie": {
        "task": "greedybear.tasks.extract_cowrie",
        "schedule": crontab(minute="*/10"),
        "options": {"queue": "default"},
    },
    # once a day
    "extract_sensors": {
        "task": "greedybear.tasks.extract_sensors",
        "schedule": crontab(hour=0),
        "options": {"queue": "default"},
    },
    # once an hour
    "monitor_honeypots": {
        "task": "greedybear.tasks.monitor_honeypots",
        "schedule": crontab(minute=18),
        "options": {"queue": "default"},
    },
    # once an hour
    "monitor_logs": {
        "task": "greedybear.tasks.monitor_logs",
        "schedule": crontab(minute=33),
        "options": {"queue": "default"},
    },
    # run once every settings.DB_BACKUP_FREQUENCY * 24 hour
    "db_backup": {
        "task": "greedybear.tasks.db_backup",
        "schedule": timedelta(days=settings.DB_BACKUP_FREQUENCY),
        "options": {"queue": "default"},
    },
}
