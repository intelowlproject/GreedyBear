from datetime import datetime
from unittest.mock import patch

from . import CustomTestCase


class TestExtractAllTrainingTrigger(CustomTestCase):
    """Test that extract_all triggers training only on the first run after midnight."""

    @patch("greedybear.tasks.train_and_update")
    @patch("greedybear.cronjobs.extract.ExtractionJob")
    @patch("greedybear.tasks.datetime")
    def test_triggers_training_at_midnight(self, mock_datetime, mock_job, mock_train):
        mock_datetime.now.return_value = datetime(2026, 1, 1, 0, 0)

        from greedybear.tasks import extract_all

        extract_all()

        mock_job().execute.assert_called_once()
        mock_train.assert_called_once()

    @patch("greedybear.tasks.train_and_update")
    @patch("greedybear.cronjobs.extract.ExtractionJob")
    @patch("greedybear.tasks.datetime")
    @patch("greedybear.tasks.EXTRACTION_INTERVAL", 2)
    def test_triggers_training_shortly_after_midnight(self, mock_datetime, mock_job, mock_train):
        mock_datetime.now.return_value = datetime(2026, 1, 1, 0, 1)

        from greedybear.tasks import extract_all

        extract_all()

        mock_job().execute.assert_called_once()
        mock_train.assert_called_once()

    @patch("greedybear.tasks.train_and_update")
    @patch("greedybear.cronjobs.extract.ExtractionJob")
    @patch("greedybear.tasks.datetime")
    @patch("greedybear.tasks.EXTRACTION_INTERVAL", 2)
    def test_does_not_trigger_training_on_next_extraction(self, mock_datetime, mock_job, mock_train):
        mock_datetime.now.return_value = datetime(2026, 1, 1, 0, 2)

        from greedybear.tasks import extract_all

        extract_all()

        mock_job().execute.assert_called_once()
        mock_train.assert_not_called()

    @patch("greedybear.tasks.train_and_update")
    @patch("greedybear.cronjobs.extract.ExtractionJob")
    @patch("greedybear.tasks.datetime")
    def test_does_not_trigger_training_outside_midnight(self, mock_datetime, mock_job, mock_train):
        mock_datetime.now.return_value = datetime(2026, 1, 1, 10, 55)

        from greedybear.tasks import extract_all

        extract_all()

        mock_job().execute.assert_called_once()
        mock_train.assert_not_called()


class TestOtherTasks(CustomTestCase):
    """Test the other tasks in greedybear/tasks.py."""

    @patch("greedybear.cronjobs.monitor_honeypots.MonitorHoneypots.execute")
    def test_monitor_honeypots(self, mock_execute):
        from greedybear.tasks import monitor_honeypots

        monitor_honeypots()
        mock_execute.assert_called_once()

    @patch("greedybear.cronjobs.monitor_logs.MonitorLogs.execute")
    def test_monitor_logs(self, mock_execute):
        from greedybear.tasks import monitor_logs

        monitor_logs()
        mock_execute.assert_called_once()

    @patch("greedybear.cronjobs.scoring.scoring_jobs.TrainModels.execute")
    @patch("greedybear.cronjobs.scoring.scoring_jobs.UpdateScores.execute")
    def test_train_and_update(self, mock_update_execute, mock_train_execute):
        from greedybear.tasks import train_and_update

        train_and_update()
        mock_train_execute.assert_called_once()
        mock_update_execute.assert_called_once()

    @patch("greedybear.tasks.CLUSTER_COWRIE_COMMAND_SEQUENCES", True)
    @patch("greedybear.cronjobs.commands.cluster.ClusterCommandSequences.execute")
    def test_cluster_commands_enabled(self, mock_execute):
        from greedybear.tasks import cluster_commands

        cluster_commands()
        mock_execute.assert_called_once()

    @patch("greedybear.tasks.CLUSTER_COWRIE_COMMAND_SEQUENCES", False)
    @patch("greedybear.cronjobs.commands.cluster.ClusterCommandSequences.execute")
    def test_cluster_commands_disabled(self, mock_execute):
        from greedybear.tasks import cluster_commands

        cluster_commands()
        mock_execute.assert_not_called()

    @patch("greedybear.cronjobs.cleanup.CleanUp.execute")
    def test_clean_up_db(self, mock_execute):
        from greedybear.tasks import clean_up_db

        clean_up_db()
        mock_execute.assert_called_once()

    @patch("greedybear.cronjobs.mass_scanners.MassScannersCron.execute")
    def test_get_mass_scanners(self, mock_execute):
        from greedybear.tasks import get_mass_scanners

        get_mass_scanners()
        mock_execute.assert_called_once()

    @patch("greedybear.cronjobs.whatsmyip.WhatsMyIPCron.execute")
    def test_get_whatsmyip(self, mock_execute):
        from greedybear.tasks import get_whatsmyip

        get_whatsmyip()
        mock_execute.assert_called_once()

    @patch("greedybear.cronjobs.firehol.FireHolCron.execute")
    def test_extract_firehol_lists(self, mock_execute):
        from greedybear.tasks import extract_firehol_lists

        extract_firehol_lists()
        mock_execute.assert_called_once()

    @patch("greedybear.cronjobs.tor_exit_nodes.TorExitNodesCron.execute")
    def test_get_tor_exit_nodes(self, mock_execute):
        from greedybear.tasks import get_tor_exit_nodes

        get_tor_exit_nodes()
        mock_execute.assert_called_once()

    @patch("greedybear.cronjobs.threatfox_feed.ThreatFoxCron.execute")
    def test_enrich_threatfox(self, mock_execute):
        from greedybear.tasks import enrich_threatfox

        enrich_threatfox()
        mock_execute.assert_called_once()

    @patch("greedybear.cronjobs.abuseipdb_feed.AbuseIPDBCron.execute")
    def test_enrich_abuseipdb(self, mock_execute):
        from greedybear.tasks import enrich_abuseipdb

        enrich_abuseipdb()
        mock_execute.assert_called_once()
