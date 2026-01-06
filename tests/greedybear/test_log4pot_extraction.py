from django.test import TestCase
from greedybear.cronjobs.log4pot import ExtractLog4Pot


class TestLog4PotExtraction(TestCase):
    """
    End-to-end test scaffold for Log4Pot extraction pipeline.

    This verifies that the extraction job can be instantiated
    and its lookup method can be executed without raising errors.
    """

    def test_log4pot_extraction_runs(self):
        extractor = ExtractLog4Pot(minutes_back=5)

        try:
            extractor._log4pot_lookup()
        except Exception as exc:
            self.fail(f"Log4Pot extraction raised an exception: {exc}")

