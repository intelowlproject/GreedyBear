from greedybear.consts import SCANNER
from greedybear.cronjobs.extraction.strategies import BaseExtractionStrategy
from greedybear.cronjobs.extraction.utils import iocs_from_hits, threatfox_submission


class GenericExtractionStrategy(BaseExtractionStrategy):
    """
    Extraction strategy for generic honeypots.

    Processes log hits as scanner-type IOCs and submits qualifying
    records to ThreatFox. Used for honeypots without specialized
    extraction logic.
    """

    def extract_from_hits(self, hits: list[dict]) -> None:
        """
        Extract IOCs from honeypot log hits.
        Converts hits to IOC records, persists them via the IOC processor,
        and submits qualifying records to ThreatFox.

        Args:
            hits: List of Elasticsearch hits to process.
        """
        for ioc, sensors in iocs_from_hits(hits):
            self.log.info(f"IoC {ioc.name} found by honeypot {self.honeypot}")
            # Process IoC once with first sensor (or None)
            first_sensor = sensors[0] if sensors else None
            ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=SCANNER, general_honeypot_name=self.honeypot, sensor=first_sensor)
            # Add remaining sensors if any
            if ioc_record and len(sensors) > 1:
                for sensor in sensors[1:]:
                    self.ioc_repo.add_sensor_to_ioc(sensor, ioc_record)
            if ioc_record:
                self.ioc_records.append(ioc_record)
                threatfox_submission(ioc_record, ioc.related_urls, self.log)
        self.log.info(f"added {len(self.ioc_records)} IoCs from {self.honeypot}")
