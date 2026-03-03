from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.models import Tag
from tests import CustomTestCase


class TestTagRepository(CustomTestCase):
    """Tests for TagRepository."""

    def setUp(self):
        self.repo = TagRepository()

    def test_replace_tags_for_source_creates_tags(self):
        """Should create new tags for a source."""
        tag_entries = [
            {"ioc_id": self.ioc.id, "key": "malware", "value": "Mirai"},
            {"ioc_id": self.ioc.id, "key": "threat_type", "value": "botnet_cc"},
        ]

        count = self.repo.replace_tags_for_source("threatfox", tag_entries)

        self.assertEqual(count, 2)
        self.assertEqual(Tag.objects.filter(source="threatfox").count(), 2)

    def test_replace_tags_for_source_replaces_existing(self):
        """Should delete existing tags and create new ones."""
        Tag.objects.create(ioc=self.ioc, key="malware", value="OldMalware", source="threatfox")

        tag_entries = [
            {"ioc_id": self.ioc.id, "key": "malware", "value": "NewMalware"},
        ]

        count = self.repo.replace_tags_for_source("threatfox", tag_entries)

        self.assertEqual(count, 1)
        tags = Tag.objects.filter(source="threatfox")
        self.assertEqual(tags.count(), 1)
        self.assertEqual(tags.first().value, "NewMalware")

    def test_replace_tags_preserves_other_sources(self):
        """Should not affect tags from other sources."""
        Tag.objects.create(ioc=self.ioc, key="confidence_of_abuse", value="84%", source="abuseipdb")

        self.repo.replace_tags_for_source("threatfox", [])

        self.assertEqual(Tag.objects.filter(source="abuseipdb").count(), 1)

    def test_replace_tags_with_empty_list_clears_source(self):
        """Should delete all tags for a source when given empty list."""
        Tag.objects.create(ioc=self.ioc, key="malware", value="Mirai", source="threatfox")
        Tag.objects.create(ioc=self.ioc, key="threat_type", value="botnet_cc", source="threatfox")

        count = self.repo.replace_tags_for_source("threatfox", [])

        self.assertEqual(count, 0)
        self.assertEqual(Tag.objects.filter(source="threatfox").count(), 0)

    def test_get_tags_by_ioc(self):
        """Should return all tags for a specific IOC."""
        Tag.objects.create(ioc=self.ioc, key="malware", value="Mirai", source="threatfox")
        Tag.objects.create(ioc=self.ioc, key="confidence_of_abuse", value="84%", source="abuseipdb")
        Tag.objects.create(ioc=self.ioc_2, key="malware", value="Emotet", source="threatfox")

        tags = self.repo.get_tags_by_ioc(self.ioc)

        self.assertEqual(tags.count(), 2)

    def test_get_tags_by_source(self):
        """Should return all tags from a specific source."""
        Tag.objects.create(ioc=self.ioc, key="malware", value="Mirai", source="threatfox")
        Tag.objects.create(ioc=self.ioc_2, key="malware", value="Emotet", source="threatfox")
        Tag.objects.create(ioc=self.ioc, key="confidence_of_abuse", value="84%", source="abuseipdb")

        tags = self.repo.get_tags_by_source("threatfox")

        self.assertEqual(tags.count(), 2)

    def test_delete_tags_by_source(self):
        """Should delete all tags from a specific source."""
        Tag.objects.create(ioc=self.ioc, key="malware", value="Mirai", source="threatfox")
        Tag.objects.create(ioc=self.ioc, key="confidence_of_abuse", value="84%", source="abuseipdb")

        deleted = self.repo.delete_tags_by_source("threatfox")

        self.assertEqual(deleted, 1)
        self.assertEqual(Tag.objects.filter(source="threatfox").count(), 0)
        self.assertEqual(Tag.objects.filter(source="abuseipdb").count(), 1)

    def test_tags_deleted_when_ioc_deleted(self):
        """Tags should be cascade deleted when their IOC is deleted."""
        Tag.objects.create(ioc=self.ioc, key="malware", value="Mirai", source="threatfox")
        Tag.objects.create(ioc=self.ioc, key="confidence_of_abuse", value="84%", source="abuseipdb")

        ioc_id = self.ioc.id
        self.ioc.delete()

        self.assertEqual(Tag.objects.filter(ioc_id=ioc_id).count(), 0)
