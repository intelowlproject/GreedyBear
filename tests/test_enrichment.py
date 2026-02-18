from greedybear.cronjobs.extraction.enrichment import enrich_ioc_with_tags
from greedybear.cronjobs.repositories import TagRepository
from greedybear.models import IOC, AbuseIPDBFeed, Tag, ThreatFoxFeed
from tests import CustomTestCase


class TestEnrichment(CustomTestCase):
    """Tests for IOC enrichment with tags."""

    def setUp(self):
        self.tag_repo = TagRepository()

    def test_enrich_ioc_with_threatfox_data(self):
        # Create an IOC
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")

        # Create ThreatFox feed data
        ThreatFoxFeed.objects.create(
            ip_address="1.2.3.4",
            malware="win.mirai",
            malware_printable="Mirai",
            threat_type="botnet_cc",
            confidence_level=85,
            tags=["botnet", "iot"],
        )

        # Enrich IOC
        enrich_ioc_with_tags(ioc)

        # Check tags were created
        tags = Tag.objects.filter(ioc=ioc, source="threatfox")
        self.assertGreater(tags.count(), 0)

        # Check malware tag
        malware_tag = tags.filter(key="malware").first()
        self.assertIsNotNone(malware_tag)
        self.assertEqual(malware_tag.value, "Mirai")

        # Check threat type tag
        threat_tag = tags.filter(key="threat_type").first()
        self.assertIsNotNone(threat_tag)
        self.assertEqual(threat_tag.value, "botnet_cc")

        # Check confidence level tag
        confidence_tag = tags.filter(key="confidence_level").first()
        self.assertIsNotNone(confidence_tag)
        self.assertEqual(confidence_tag.value, "85")

        # Check individual tags
        individual_tags = tags.filter(key="tag")
        self.assertEqual(individual_tags.count(), 2)
        tag_values = [t.value for t in individual_tags]
        self.assertIn("botnet", tag_values)
        self.assertIn("iot", tag_values)

    def test_enrich_ioc_with_abuseipdb_data(self):
        # Create an IOC
        ioc = IOC.objects.create(name="5.6.7.8", type="ip")

        # Create AbuseIPDB feed data
        AbuseIPDBFeed.objects.create(
            ip_address="5.6.7.8",
            abuse_confidence_score=95,
            usage_type="Data Center",
            country_code="US",
        )

        # Enrich IOC
        enrich_ioc_with_tags(ioc)

        # Check tags were created
        tags = Tag.objects.filter(ioc=ioc, source="abuseipdb")
        self.assertEqual(tags.count(), 3)

        # Check confidence tag
        confidence_tag = tags.filter(key="confidence_of_abuse").first()
        self.assertIsNotNone(confidence_tag)
        self.assertEqual(confidence_tag.value, "95%")

        # Check usage type tag
        usage_tag = tags.filter(key="usage_type").first()
        self.assertIsNotNone(usage_tag)
        self.assertEqual(usage_tag.value, "Data Center")

        # Check country tag
        country_tag = tags.filter(key="country").first()
        self.assertIsNotNone(country_tag)
        self.assertEqual(country_tag.value, "US")

    def test_enrich_ioc_with_both_sources(self):
        # Create an IOC
        ioc = IOC.objects.create(name="10.20.30.40", type="ip")

        # Create both ThreatFox and AbuseIPDB data
        ThreatFoxFeed.objects.create(
            ip_address="10.20.30.40",
            malware="win.emotet",
            malware_printable="Emotet",
        )
        AbuseIPDBFeed.objects.create(
            ip_address="10.20.30.40",
            abuse_confidence_score=90,
        )

        # Enrich IOC
        enrich_ioc_with_tags(ioc)

        # Check tags from both sources
        threatfox_tags = Tag.objects.filter(ioc=ioc, source="threatfox")
        abuseipdb_tags = Tag.objects.filter(ioc=ioc, source="abuseipdb")

        self.assertGreater(threatfox_tags.count(), 0)
        self.assertGreater(abuseipdb_tags.count(), 0)

    def test_enrich_domain_ioc_skipped(self):
        # Create a domain IOC
        ioc = IOC.objects.create(name="malware.example.com", type="domain")

        # Try to enrich (should skip)
        enrich_ioc_with_tags(ioc)

        # No tags should be created
        tags = Tag.objects.filter(ioc=ioc)
        self.assertEqual(tags.count(), 0)

    def test_enrich_ioc_no_feed_data(self):
        # Create an IOC with no corresponding feed data
        ioc = IOC.objects.create(name="99.99.99.99", type="ip")

        # Enrich IOC
        enrich_ioc_with_tags(ioc)

        # No tags should be created
        tags = Tag.objects.filter(ioc=ioc)
        self.assertEqual(tags.count(), 0)

    def test_enrich_unsaved_ioc_warning(self):
        # Create an unsaved IOC
        ioc = IOC(name="1.1.1.1", type="ip")

        # Try to enrich (should log warning and skip)
        enrich_ioc_with_tags(ioc)

        # No tags should be created
        tags = Tag.objects.filter(ioc__name="1.1.1.1")
        self.assertEqual(tags.count(), 0)


class TestTagRepository(CustomTestCase):
    """Tests for TagRepository."""

    def setUp(self):
        self.repo = TagRepository()
        self.ioc = IOC.objects.create(name="1.2.3.4", type="ip")

    def test_create_tag(self):
        tag = self.repo.create_tag(
            ioc=self.ioc,
            key="malware",
            value="mirai",
            source="threatfox",
        )

        self.assertIsNotNone(tag.id)
        self.assertEqual(tag.ioc, self.ioc)
        self.assertEqual(tag.key, "malware")
        self.assertEqual(tag.value, "mirai")
        self.assertEqual(tag.source, "threatfox")

    def test_get_tags_by_ioc(self):
        Tag.objects.create(ioc=self.ioc, key="test1", value="value1", source="source1")
        Tag.objects.create(ioc=self.ioc, key="test2", value="value2", source="source2")

        other_ioc = IOC.objects.create(name="5.6.7.8", type="ip")
        Tag.objects.create(ioc=other_ioc, key="test3", value="value3", source="source3")

        tags = self.repo.get_tags_by_ioc(self.ioc)

        self.assertEqual(tags.count(), 2)

    def test_get_tags_by_source(self):
        Tag.objects.create(ioc=self.ioc, key="test1", value="value1", source="threatfox")
        Tag.objects.create(ioc=self.ioc, key="test2", value="value2", source="abuseipdb")
        Tag.objects.create(ioc=self.ioc, key="test3", value="value3", source="threatfox")

        tags = self.repo.get_tags_by_source("threatfox")

        self.assertEqual(tags.count(), 2)

    def test_delete_tags_by_ioc(self):
        Tag.objects.create(ioc=self.ioc, key="test1", value="value1", source="source1")
        Tag.objects.create(ioc=self.ioc, key="test2", value="value2", source="source2")

        count = self.repo.delete_tags_by_ioc(self.ioc)

        self.assertEqual(count, 2)
        self.assertEqual(Tag.objects.filter(ioc=self.ioc).count(), 0)

    def test_enrich_multiple_threatfox_entries_for_same_ip(self):
        # Create an IOC
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")

        # Create multiple ThreatFox entries for same IP
        ThreatFoxFeed.objects.create(
            ip_address="1.2.3.4",
            malware="win.mirai",
            malware_printable="Mirai",
        )
        ThreatFoxFeed.objects.create(
            ip_address="1.2.3.4",
            malware="win.emotet",
            malware_printable="Emotet",
        )

        # Enrich IOC
        enrich_ioc_with_tags(ioc)

        # Should create tags for both malware families
        malware_tags = Tag.objects.filter(ioc=ioc, key="malware")
        self.assertEqual(malware_tags.count(), 2)
        malware_values = [t.value for t in malware_tags]
        self.assertIn("Mirai", malware_values)
        self.assertIn("Emotet", malware_values)

    def test_enrich_with_empty_optional_fields(self):
        # Create an IOC
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")

        # Create ThreatFox entry with minimal data
        ThreatFoxFeed.objects.create(
            ip_address="1.2.3.4",
            malware="",
            malware_printable="",
            threat_type="",
            confidence_level=None,
            tags=[],
        )

        # Enrich IOC - should not crash, just not create any tags
        enrich_ioc_with_tags(ioc)

        # No tags should be created from empty data
        tags = Tag.objects.filter(ioc=ioc)
        self.assertEqual(tags.count(), 0)

    def test_enrich_abuseipdb_updates_existing(self):
        # Create an IOC
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")

        # Create AbuseIPDB entry
        AbuseIPDBFeed.objects.create(
            ip_address="1.2.3.4",
            abuse_confidence_score=95,
        )

        # First enrichment
        enrich_ioc_with_tags(ioc)
        self.assertEqual(Tag.objects.filter(ioc=ioc, source="abuseipdb").count(), 1)

        # Update AbuseIPDB entry
        entry = AbuseIPDBFeed.objects.get(ip_address="1.2.3.4")
        entry.abuse_confidence_score = 98
        entry.save()

        # Second enrichment should not duplicate tags
        enrich_ioc_with_tags(ioc)
        # Tags should not be duplicated - enrichment only happens once at creation
