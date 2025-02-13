# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from __future__ import absolute_import, unicode_literals

from celery import chain, shared_task


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


# SCORING


@shared_task()
def train_models():
    from greedybear.cronjobs.scoring.scoring_jobs import TrainModels

    trainer = TrainModels()
    trainer.execute()
    return trainer.current_data


@shared_task()
def update_scores(current_data=None):
    from greedybear.cronjobs.scoring.scoring_jobs import UpdateScores

    updater = UpdateScores()
    updater.data = current_data
    updater.execute()


@shared_task()
def chain_train_and_update():
    """Chain the training and scoring tasks"""
    return chain(
        train_models.s(),
        update_scores.s(),
    )()
