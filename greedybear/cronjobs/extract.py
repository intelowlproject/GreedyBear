from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline


class ExtractionJob(Cronjob):
    def __init__(self):
        super().__init__()
        self.pipeline = ExtractionPipeline()

    def run(self):
        self.log.info("Beginning extraction.")
        result = self.pipeline.execute()
        self.log.info(f"Done. Extracted {result} IOCs.")
