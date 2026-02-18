import logging

from greedybear.models import Tag


class TagRepository:
    """Repository for data access to Tag entries."""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def create_tag(self, ioc, key: str, value: str, source: str) -> Tag:
        """
        Create a new tag for an IOC.

        Args:
            ioc: IOC instance to tag.
            key: Tag key (e.g., "malware", "confidence_of_abuse").
            value: Tag value (e.g., "mirai", "84%").
            source: Source of the tag (e.g., "threatfox", "abuseipdb").

        Returns:
            The created Tag instance.
        """
        tag = Tag.objects.create(ioc=ioc, key=key, value=value, source=source)
        self.log.debug(f"Created tag for IOC {ioc.name}: {key}={value} from {source}")
        return tag

    def get_tags_by_ioc(self, ioc):
        """
        Get all tags for a specific IOC.

        Args:
            ioc: IOC instance to get tags for.

        Returns:
            QuerySet of Tag objects.
        """
        return Tag.objects.filter(ioc=ioc)

    def get_tags_by_source(self, source: str):
        """
        Get all tags from a specific source.

        Args:
            source: Source name (e.g., "threatfox", "abuseipdb").

        Returns:
            QuerySet of Tag objects.
        """
        return Tag.objects.filter(source=source)

    def delete_tags_by_ioc(self, ioc):
        """
        Delete all tags for a specific IOC.

        Args:
            ioc: IOC instance to delete tags for.

        Returns:
            Number of tags deleted.
        """
        count = Tag.objects.filter(ioc=ioc).count()
        Tag.objects.filter(ioc=ioc).delete()
        self.log.debug(f"Deleted {count} tags for IOC {ioc.name}")
        return count
