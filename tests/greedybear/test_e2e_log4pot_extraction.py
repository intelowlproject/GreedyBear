import pytest

pytestmark = pytest.mark.xfail(
    reason="GreedyBear extraction E2E tests require IntelOwl Django environment",
    raises=ImportError,
)

def test_log4pot_extraction_pipeline_scaffold():
    import greedybear.cronjobs.log4pot  # noqa: F401

