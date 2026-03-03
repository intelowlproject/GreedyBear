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
