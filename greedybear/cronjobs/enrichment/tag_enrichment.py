from abc import abstractmethod
from collections import defaultdict, namedtuple

import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.models import IOC

ProtoTag = namedtuple("ProtoTag", ["ip", "key", "value"])

class TagEnrichment(Cronjob):
    SOURCE_NAME: str
    API_KEY: str

    def __init__(self, tag_repo=None):
        super().__init__()
        self.tag_repo = tag_repo if tag_repo is not None else TagRepository()


    @abstractmethod
    def _fetch_feed(self) -> list[dict]:
        pass

    @abstractmethod
    def _parse_tags(self, raw_data: list[dict]) -> list[ProtoTag]:
        pass

    def _get_tag_entries(self, tags: list[ProtoTag]) -> list[dict]:
        tags_by_ip = defaultdict(list)
        for tag in tags:
            tags_by_ip[tag.ip].append(tag)
        self.log.info(f"Parsed {len(tags_by_ip)} unique IPs from {self.SOURCE_NAME}")

        matching_iocs = IOC.objects.filter(name__in=tags_by_ip.keys()).values_list("id", "name")

        return [
            {"ioc_id": ioc_id, "key": tag.key, "value": tag.value}
            for ioc_id, ioc_name in matching_iocs
            for tag in tags_by_ip[ioc_name]
        ]

    def run(self) -> None:
        if not self.API_KEY:
            self.log.warning(f"{self.SOURCE_NAME} API key not configured. Skipping.")
            return

        self.log.info(f"Starting {self.SOURCE_NAME} feed download")
        try:
            raw_data = self._fetch_feed()
        except requests.RequestException as e:
            self.log.error(f"Failed to fetch from {self.SOURCE_NAME}: {e}")
            raise

        if raw_data is None:
            return

        tags = self._parse_tags(raw_data)
        tag_entries = self._get_tag_entries(tags)

        created_count = self.tag_repo.replace_tags_for_source(self.SOURCE_NAME, tag_entries)
        self.log.info(f"{self.SOURCE_NAME} enrichment completed, created {created_count} tags.")
