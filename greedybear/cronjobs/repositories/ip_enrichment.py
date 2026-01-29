from greedybear.models import IOC, Tag


class TagRepository:
    """Repository for Tag model."""

    def create_tags(self, ioc: IOC, tags: list, source: str) -> list:
        """Create Tag records for an IOC with normalized tag names."""
        created_tags = []
        for tag_name in tags:
            # Normalize tag name to lowercase
            normalized_name = tag_name.lower().strip()
            if normalized_name:  # Only create if tag is not empty
                tag, created = Tag.objects.get_or_create(
                    ioc=ioc,
                    name=normalized_name,
                    source=source,
                )
                created_tags.append(tag)
        return created_tags
