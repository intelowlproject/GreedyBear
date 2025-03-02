# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from __future__ import absolute_import, unicode_literals

from celery import chain, shared_task
from greedybear.settings import CLUSTER_COWRIE_COMMAND_SEQUENCES


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
def chain_train_and_update():
    from greedybear.cronjobs.scoring.scoring_jobs import TrainModels, UpdateScores

    trainer = TrainModels()
    trainer.execute()
    current_data = trainer.current_data

    updater = UpdateScores()
    updater.data = current_data
    updater.execute()

# COMMANDS


@shared_task()
def cluster_commands():
    from greedybear.cronjobs.commands.cluster import ClusterCommandSequences

    if CLUSTER_COWRIE_COMMAND_SEQUENCES:
        ClusterCommandSequences().execute()


# CLEAN UP


@shared_task()
def clean_up_db():
    from greedybear.cronjobs.cleanup import CleanUp

    CleanUp().execute()
