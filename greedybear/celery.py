# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from __future__ import absolute_import, unicode_literals

import os

from celery import Celery
from celery.schedules import crontab
from celery.signals import setup_logging
from django.conf import settings
from greedybear.settings import EXTRACTION_INTERVAL, LEGACY_EXTRACTION
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


hp_extraction_interval = 10 if LEGACY_EXTRACTION else EXTRACTION_INTERVAL
app.conf.beat_schedule = {
    # every 10 minutes or according to EXTRACTION_INTERVAL
    "extract_log4pot": {
        "task": "greedybear.tasks.extract_log4pot",
        "schedule": crontab(minute=f"*/{hp_extraction_interval}"),
        "options": {"queue": "default"},
    },
    # every 10 minutes or according to EXTRACTION_INTERVAL
    "extract_cowrie": {
        "task": "greedybear.tasks.extract_cowrie",
        "schedule": crontab(minute=f"*/{hp_extraction_interval}"),
        "options": {"queue": "default"},
    },
    # FEEDS
    # every 10 minutes or according to EXTRACTION_INTERVAL
    "extract_general": {
        "task": "greedybear.tasks.extract_general",
        "schedule": crontab(minute=f"*/{hp_extraction_interval}"),
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
    # SCORING
    # Important:
    # The training task must be run with a small offset after midnight (00:00)
    # to ensure training data aligns with complete calendar days.
    # The small offset is to make sure that the midnight extraction task is completed before training.
    # This way models learn from complete rather than partial day patterns, which is crucial for their performance.
    "train_and_update": {
        "task": "greedybear.tasks.chain_train_and_update",
        "schedule": crontab(hour=0, minute=hp_extraction_interval // 2),
        "options": {"queue": "default"},
    },
    # COMMANDS
    # once a day
    "command_clustering": {
        "task": "greedybear.tasks.cluster_commands",
        "schedule": crontab(hour=1, minute=3),
        "options": {"queue": "default"},
    },
}
