from django.test import TestCase
from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline


class TestExtractionPipeline(TestCase):
    def test_pipeline_initialization(self):
        """
        Ensure ExtractionPipeline can be instantiated.
        Minimal scaffold for #636.
        """
        pipeline = ExtractionPipeline()
        self.assertIsNotNone(pipeline)

