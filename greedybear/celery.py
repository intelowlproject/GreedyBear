# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

import os

from celery import Celery
from celery.schedules import crontab
from celery.signals import setup_logging
from django.conf import settings
from kombu import Exchange, Queue

from greedybear.settings import EXTRACTION_INTERVAL

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


hp_extraction_interval = EXTRACTION_INTERVAL
app.conf.beat_schedule = {
    # ===========================================
    # TIMING-CRITICAL: Extraction Task
    # Runs every 10 minutes (or EXTRACTION_INTERVAL)
    # Slots: :00, :10, :20, :30, :40, :50
    # ===========================================
    "extract_all": {
        "task": "greedybear.tasks.extract_all",
        "schedule": crontab(minute=f"*/{hp_extraction_interval}"),
        "options": {"queue": "default", "countdown": 10},
    },
    # ===========================================
    # TIMING-CRITICAL: Midnight Training
    # This wrapper ensures `chain_train_and_update` runs
    # only after the midnight extraction completes using Celery chain.
    # Scheduled at exactly 00:00.
    # ===========================================
    "train_and_update_after_midnight": {
        "task": "greedybear.tasks.train_and_update_after_midnight",
        "schedule": crontab(hour=0, minute=0),
        "options": {"queue": "default"},
    },
    # ===========================================
    # HOURLY: Monitoring Tasks
    # Run at :07 (avoiding extraction slots)
    # ===========================================
    "monitor_honeypots": {
        "task": "greedybear.tasks.monitor_honeypots",
        "schedule": crontab(minute=7),
        "options": {"queue": "default"},
    },
    "monitor_logs": {
        "task": "greedybear.tasks.monitor_logs",
        "schedule": crontab(minute=7),
        "options": {"queue": "default"},
    },
    # ===========================================
    # DAILY/WEEKLY: Maintenance Tasks
    # All bundled at 1:07 AM
    # Timing not critical - Celery queues sequentially
    # Avoids extraction slots at 1:00 and 1:10
    # ===========================================
    # once a day
    "command_clustering": {
        "task": "greedybear.tasks.cluster_commands",
        "schedule": crontab(hour=1, minute=7),
        "options": {"queue": "default"},
    },
    # once a day
    "clean_up": {
        "task": "greedybear.tasks.clean_up_db",
        "schedule": crontab(hour=1, minute=7),
        "options": {"queue": "default"},
    },
    "get_mass_scanners": {
        "task": "greedybear.tasks.get_mass_scanners",
        "schedule": crontab(hour=1, minute=7, day_of_week=0),
        "options": {"queue": "default"},
    },
    "get_whatsmyip": {
        "task": "greedybear.tasks.get_whatsmyip",
        "schedule": crontab(hour=1, minute=7, day_of_week=0),
        "options": {"queue": "default"},
    },
    "extract_firehol_lists": {
        "task": "greedybear.tasks.extract_firehol_lists",
        "schedule": crontab(hour=1, minute=7, day_of_week=0),
        "options": {"queue": "default"},
    },
    "get_tor_exit_nodes": {
        "task": "greedybear.tasks.get_tor_exit_nodes",
        "schedule": crontab(hour=1, minute=7, day_of_week=0),
        "options": {"queue": "default"},
    },
}
