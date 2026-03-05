# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.apps import AppConfig


class GreedybearConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "greedybear"

    def ready(self):
        import greedybear.signals  # noqa: F401
