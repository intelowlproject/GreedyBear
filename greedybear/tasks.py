# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from celery import chain, shared_task

from greedybear.settings import CLUSTER_COWRIE_COMMAND_SEQUENCES


@shared_task()
def extract_all():
    from greedybear.cronjobs.extract import ExtractionJob

    ExtractionJob().execute()


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

    updater = UpdateScores()
    updater.data = trainer.current_data
    updater.execute()


# chain between extract all and train and update which ensures that training and updating is done only after extraction is done
@shared_task()
def train_and_update_after_midnight():
    chain(extract_all.s(), chain_train_and_update.s())()


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


@shared_task()
def get_mass_scanners():
    from greedybear.cronjobs.mass_scanners import MassScannersCron

    MassScannersCron().execute()


@shared_task()
def get_whatsmyip():
    from greedybear.cronjobs.whatsmyip import WhatsMyIPCron

    WhatsMyIPCron().execute()


@shared_task()
def extract_firehol_lists():
    from greedybear.cronjobs.firehol import FireHolCron

    FireHolCron().execute()


@shared_task()
def get_tor_exit_nodes():
    from greedybear.cronjobs.tor_exit_nodes import TorExitNodesCron

    TorExitNodesCron().execute()
