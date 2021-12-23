from __future__ import absolute_import, unicode_literals

from celery import Celery
from celery.schedules import crontab
from django.conf import settings
from kombu import Exchange, Queue

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

app.conf.beat_schedule = {
    # once an hour
    "extract_data_from_elastic": {
        "task": "greedybear.tasks.extract_data_from_elastic",
        "schedule": crontab(minute=0),
        "options": {"queue": "default"},
    },
}
