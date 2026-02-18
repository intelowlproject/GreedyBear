# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.


from greedybear.settings import CLUSTER_COWRIE_COMMAND_SEQUENCES


def extract_all():
    from greedybear.cronjobs.extract import ExtractionJob

    ExtractionJob().execute()


def monitor_honeypots():
    from greedybear.cronjobs.monitor_honeypots import MonitorHoneypots

    MonitorHoneypots().execute()


def monitor_logs():
    from greedybear.cronjobs.monitor_logs import MonitorLogs

    MonitorLogs().execute()


# SCORING
def chain_train_and_update():
    from greedybear.cronjobs.scoring.scoring_jobs import TrainModels, UpdateScores

    trainer = TrainModels()
    trainer.execute()

    updater = UpdateScores()
    updater.data = trainer.current_data
    updater.execute()


# COMMANDS
def cluster_commands():
    from greedybear.cronjobs.commands.cluster import ClusterCommandSequences

    if CLUSTER_COWRIE_COMMAND_SEQUENCES:
        ClusterCommandSequences().execute()


# CLEAN UP
def clean_up_db():
    from greedybear.cronjobs.cleanup import CleanUp

    CleanUp().execute()


def get_mass_scanners():
    from greedybear.cronjobs.mass_scanners import MassScannersCron

    MassScannersCron().execute()


def get_whatsmyip():
    from greedybear.cronjobs.whatsmyip import WhatsMyIPCron

    WhatsMyIPCron().execute()


def extract_firehol_lists():
    from greedybear.cronjobs.firehol import FireHolCron

    FireHolCron().execute()


def get_tor_exit_nodes():
    from greedybear.cronjobs.tor_exit_nodes import TorExitNodesCron

    TorExitNodesCron().execute()


def get_threatfox_feed():
    from greedybear.cronjobs.threatfox_feed import ThreatFoxCron

    ThreatFoxCron().execute()


def get_abuseipdb_feed():
    from greedybear.cronjobs.abuseipdb_feed import AbuseIPDBCron

    AbuseIPDBCron().execute()
