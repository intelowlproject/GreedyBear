# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class GreedyBearConfig(AppConfig):
    name = "greedybear"

    def ready(self):
        logger.debug("GreedyBear app ready")  # TODO: Remove before merging PR #701
