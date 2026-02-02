from datetime import datetime

from django.test import TestCase

from greedybear.cronjobs.extraction.ioc_processor import IocProcessor
from greedybear.cronjobs.repositories import IocRepository, SensorRepository
from greedybear.models import IOC, AbuseIPDBEntry, IocType, Tag, ThreatFoxEntry


class TestIOCEnrichment(TestCase):
    """Test IOC enrichment with threat intelligence feeds."""

    def test_enrich_ioc_with_threatfox(self):
        """Test that IOC is enriched with ThreatFox tag when match found."""
        # Setup: Create ThreatFox entry
        ThreatFoxEntry.objects.create(ip_address="1.2.3.4", malware_family="emotet")

        # Create IOC
        processor = IocProcessor(IocRepository(), SensorRepository())
        ioc = IOC(name="1.2.3.4", type=IocType.IP, last_seen=datetime.now())
        result = processor.add_ioc(ioc, "scanner")

        # Verify tag created
        assert result is not None
        assert Tag.objects.filter(ioc=result, name="emotet", source="abuse_ch").exists()

    def test_enrich_ioc_with_abuseipdb_high_risk(self):
        """Test that IOC is enriched with AbuseIPDB tag when high-risk (score > 75)."""
        # Setup: Create AbuseIPDB entry with high score
        AbuseIPDBEntry.objects.create(ip_address="5.6.7.8", abuse_confidence_score=90)

        # Create IOC
        processor = IocProcessor(IocRepository(), SensorRepository())
        ioc = IOC(name="5.6.7.8", type=IocType.IP, last_seen=datetime.now())
        result = processor.add_ioc(ioc, "scanner")

        # Verify tag created
        assert result is not None
        assert Tag.objects.filter(ioc=result, name="high-risk", source="abuseipdb").exists()

    def test_no_enrichment_for_low_risk_abuseipdb(self):
        """Test that IOC with low AbuseIPDB score (<=75) gets no tag."""
        # Setup: Create AbuseIPDB entry with low score
        AbuseIPDBEntry.objects.create(ip_address="10.20.30.40", abuse_confidence_score=50)

        # Create IOC
        processor = IocProcessor(IocRepository(), SensorRepository())
        ioc = IOC(name="10.20.30.40", type=IocType.IP, last_seen=datetime.now())
        result = processor.add_ioc(ioc, "scanner")

        # Verify no tag created
        assert result is not None
        assert Tag.objects.filter(ioc=result, source="abuseipdb").count() == 0

    def test_enrich_ioc_with_both_feeds(self):
        """Test that IOC gets tags from both feeds when present in both."""
        # Setup: Create entries in both feeds
        ThreatFoxEntry.objects.create(ip_address="11.22.33.44", malware_family="mirai")
        AbuseIPDBEntry.objects.create(ip_address="11.22.33.44", abuse_confidence_score=95)

        # Create IOC
        processor = IocProcessor(IocRepository(), SensorRepository())
        ioc = IOC(name="11.22.33.44", type=IocType.IP, last_seen=datetime.now())
        result = processor.add_ioc(ioc, "scanner")

        # Verify both tags created
        assert result is not None
        assert Tag.objects.filter(ioc=result, name="mirai", source="abuse_ch").exists()
        assert Tag.objects.filter(ioc=result, name="high-risk", source="abuseipdb").exists()
        assert Tag.objects.filter(ioc=result).count() == 2

    def test_no_enrichment_for_domain(self):
        """Test that domains are not enriched (only IPs)."""
        processor = IocProcessor(IocRepository(), SensorRepository())
        ioc = IOC(name="evil.com", type=IocType.DOMAIN, last_seen=datetime.now())
        result = processor.add_ioc(ioc, "scanner")

        # Verify no tags created
        assert result is not None
        assert Tag.objects.filter(ioc=result).count() == 0

    def test_no_enrichment_when_no_feed_match(self):
        """Test that IOC without feed match gets no tags."""
        processor = IocProcessor(IocRepository(), SensorRepository())
        ioc = IOC(name="9.9.9.9", type=IocType.IP, last_seen=datetime.now())
        result = processor.add_ioc(ioc, "scanner")

        # Verify no tags created
        assert result is not None
        assert Tag.objects.filter(ioc=result).count() == 0

    def test_no_duplicate_tags_on_update(self):
        """Test that updating an IOC doesn't create duplicate tags."""
        # Setup: Create ThreatFox entry
        ThreatFoxEntry.objects.create(ip_address="12.34.56.78", malware_family="qakbot")

        # Create IOC first time
        processor = IocProcessor(IocRepository(), SensorRepository())
        ioc1 = IOC(name="12.34.56.78", type=IocType.IP, last_seen=datetime.now())
        processor.add_ioc(ioc1, "scanner")

        # Update IOC (simulate second attack)
        ioc2 = IOC(name="12.34.56.78", type=IocType.IP, last_seen=datetime.now())
        result2 = processor.add_ioc(ioc2, "scanner")

        # Verify only one tag exists (get_or_create prevents duplicates)
        assert result2 is not None
        assert Tag.objects.filter(ioc=result2, name="qakbot", source="abuse_ch").count() == 1

    def test_threatfox_empty_malware_family(self):
        """Test that ThreatFox entry with empty malware_family doesn't create tag."""
        # Setup: Create ThreatFox entry with empty malware_family
        ThreatFoxEntry.objects.create(ip_address="99.88.77.66", malware_family="")

        # Create IOC
        processor = IocProcessor(IocRepository(), SensorRepository())
        ioc = IOC(name="99.88.77.66", type=IocType.IP, last_seen=datetime.now())
        result = processor.add_ioc(ioc, "scanner")

        # Verify no tag created
        assert result is not None
        assert Tag.objects.filter(ioc=result, source="abuse_ch").count() == 0

    def test_tag_name_normalized_to_lowercase(self):
        """Test that tag names are normalized to lowercase."""
        # Setup: Create ThreatFox entry with mixed-case malware family
        ThreatFoxEntry.objects.create(ip_address="55.66.77.88", malware_family="Emotet")

        # Create IOC
        processor = IocProcessor(IocRepository(), SensorRepository())
        ioc = IOC(name="55.66.77.88", type=IocType.IP, last_seen=datetime.now())
        result = processor.add_ioc(ioc, "scanner")

        # Verify tag is lowercase
        assert result is not None
        tag = Tag.objects.get(ioc=result, source="abuse_ch")
        assert tag.name == "emotet"  # lowercase
